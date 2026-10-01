"""LifecycleAgent (Phase 0) - turns repeated pulls into a correct finding history.

Rules (per finding, using the source it came from):
  * present in this pull           -> keep; first_seen is sticky (earliest ever seen)
  * source failed / skipped / not run this time
                                   -> carry forward unchanged (never resolve because a tool was down)
  * snapshot source, absent        -> missed_runs + 1; resolved after `resolve_after_missed` consecutive
                                      complete pulls ("not seen in N full pulls")
  * incremental source, absent     -> carry forward (the source reports changes, not the full set);
                                      detections / alerts / advisories expire after N days without update
  * LODESTAR-generated findings (control health) that are no longer raised -> resolved ("condition cleared")
  * connector removed from config  -> resolved ("source no longer integrated")
The resolve/missed decisions are applied by Store.save_result.
"""
from __future__ import annotations

from datetime import timedelta, timezone

from ...models import Domain, Finding, FindingType, Status
from ..base import AgentContext, BaseAgent, PipelineState
from ..connectors.domains import SPECS

SHORT_LIVED = {FindingType.DETECTION, FindingType.INCIDENT, FindingType.POLICY_VIOLATION}


class LifecycleAgent(BaseAgent):
    name = "LifecycleAgent"
    phase = 0
    description = "Tracks findings across runs: sticky first-seen, carry-forward on source failure, resolution rules per sync mode."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        if ctx.store is None:
            return state
        cfg = (ctx.settings.raw.get("lifecycle") or {})
        n_missed = int(cfg.get("resolve_after_missed", 2))
        det_days = int(cfg.get("detection_expiry_days", 30))
        intel_days = int(cfg.get("intel_expiry_days", 30))
        org = ctx.settings.org_name
        now = ctx.now if ctx.now.tzinfo else ctx.now.replace(tzinfo=timezone.utc)
        current = {f.finding_id: f for f in state.findings}

        # sticky first_seen (also for findings that re-open)
        for fid, fs in ctx.store.first_seen_map(org, list(current)).items():
            f = current[fid]
            if fs and fs < (f.first_seen if f.first_seen.tzinfo else f.first_seen.replace(tzinfo=timezone.utc)):
                f.first_seen = fs

        sources = state.data_quality.get("sources", {})
        configured = {d.value for d, c in ctx.settings.connectors.items() if c.enabled}
        phase_ok = {d for d in configured if SPECS[Domain(d)].phase <= ctx.settings.deployment_phase}
        resolve, missed, carried = {}, {}, 0
        for fid, st in ctx.store.open_findings(org).items():
            if fid in current:
                continue
            f = Finding.model_validate_json(st["data"])
            src = f.evidence.get("_src")
            if f.source.startswith("lodestar.") and src is None:
                resolve[fid] = "condition cleared"
                continue
            if src == "hunt" and sources.get("hunt", {}).get("status") != "ok":
                status = None
            else:
                status = sources.get(src, {}).get("status") if src else None
            dom = f.domain.value
            if dom not in configured and src != "hunt":
                resolve[fid] = "source no longer integrated"
                continue
            if status in (None, "failed", "skipped", "no_data") or dom not in phase_ok:
                self._carry(state, f, st["missed_runs"], missed)
                carried += 1
                continue
            if f.evidence.get("_sync", "snapshot") == "snapshot":
                m = st["missed_runs"] + 1
                if m >= n_missed:
                    resolve[fid] = f"not seen in {m} consecutive full pulls"
                else:
                    self._carry(state, f, m, missed)
                    f.evidence.setdefault("tags", []).append("not_seen_last_pull")
                    carried += 1
                continue
            last = f.last_seen if f.last_seen.tzinfo else f.last_seen.replace(tzinfo=timezone.utc)
            limit = intel_days if dom == "threat_intel" else (det_days if f.finding_type in SHORT_LIVED else None)
            if limit and now - last > timedelta(days=limit):
                resolve[fid] = f"expired: no update for {limit} days"
            else:
                self._carry(state, f, 0, missed)
                carried += 1
        state.lifecycle = {"resolve": resolve, "missed": missed}
        state.data_quality["lifecycle"] = {"carried_forward": carried, "resolved_by_lifecycle": len(resolve),
                                          "rules": {"resolve_after_missed": n_missed, "detection_expiry_days": det_days}}
        return state

    @staticmethod
    def _carry(state: PipelineState, f: Finding, missed_runs: int, missed: dict) -> None:
        missed[f.finding_id] = missed_runs
        if f.status in (Status.RESOLVED, Status.FALSE_POSITIVE):
            return
        f.evidence["_carried"] = True
        f.correlation_ids, f.score, f.horizon, f.why = [], 0.0, None, []   # re-derived this run
        state.findings.append(f)
