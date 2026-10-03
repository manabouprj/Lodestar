"""IngestionMonitorAgent (Phase 0) - continuous validation of every ingestion source, every run.

For each configured source (connectors.<domain> or connectors.<domain>.sources[n]) it evaluates this
run's fetch against the source's expectations (lodestar/ingestion.py) and its own history:

  healthy        fetched (or not due yet) and every check passed
  retrying       the last fetch failed, fewer than `failing_after` times in a row (no alert yet)
  failing        `failing_after` (default 2) consecutive failed fetches               -> finding + alert
  stale          no successful fetch within max_age -> finding + alert; or the source's own data is
                 older than max_age -> alert (the finding is ControlAssurance's ctl-<domain>-health)
  volume_drop    snapshot pull far below its recent median (export truncated, scope lost) -> finding + alert
  volume_spike   snapshot pull far above its recent median (filter removed, duplication)
  degraded       fetched, but schema drift / unmapped rows / unknown severities / volume bounds
  awaiting_data  configured, nothing received yet (webhook not wired, empty drop folder)

Effects:
  * data_quality["ingestion"]  per-source state, detail, checks, cadence, last success, transitions
  * a COVERAGE_GAP finding per source in an alerting state (source "lodestar.ingestion_monitor"; HIGH when
    the domain is mandatory for the industry profile, otherwise MEDIUM). It resolves automatically on
    the first run in which the source is healthy again ("condition cleared").
  * a health issue on the domain's control, so ControlAssurance scores the broken pipe
  * the state is persisted (connector_state.monitor) for transitions, Slack/Teams alerts, /metrics, MCP
Read-only: it never retries, reconfigures or touches the source; humans fix pipes.
"""
from __future__ import annotations

from datetime import timezone
from typing import Any

from ...ingestion import ALERT_STATES, Check, classify, expectations, quality_checks
from ...models import Domain, Finding, FindingType, Severity
from ..base import AgentContext, BaseAgent, PipelineState
from ..connectors.domains import SPECS


def finding_id(key: str) -> str:
    return "ing-" + key.replace("/", "-").replace("#", "-")


class IngestionMonitorAgent(BaseAgent):
    name = "IngestionMonitorAgent"
    phase = 0
    description = "Continuously validates every ingestion source: failures, staleness, volume anomalies, schema drift."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        sources = state.data_quality.get("sources") or {}
        org = ctx.settings.org_name
        now = ctx.now if ctx.now.tzinfo else ctx.now.replace(tzinfo=timezone.utc)
        cfg = ctx.settings.raw.get("ingestion") or {}
        raise_on = set(cfg.get("finding_states") or ALERT_STATES)
        by_src: dict[str, list] = {}
        for f in state.findings:
            src = f.evidence.get("_src")
            if src and not f.evidence.get("_carried"):
                by_src.setdefault(src, []).append(f)
        out: dict[str, Any] = {}
        transitions: list[dict[str, Any]] = []
        controls = {c.domain.value: c for c in state.controls}
        for key, info in sources.items():
            if "adapter" not in info:          # threat hunt and other non-connector entries
                continue
            st = ctx.store.connector_state(org, key) if ctx.store is not None else {}
            if ctx.store is not None:
                st["last_items_at"] = ctx.store.last_items_at(org, key)
            prev = st.get("monitor") or {}
            exp = expectations(ctx.settings, info)
            checks: list[Check] = quality_checks(info, by_src.get(key, []), state.assets, exp, now)
            hist = ctx.store.source_history(org, key, int(exp.get("baseline_runs", 14)) + 1) if ctx.store is not None else []
            if info.get("status") in ("ok", "no_data") and hist and not ctx.dry_run:
                hist = hist[1:]                # drop this run's own record
            state_, detail = classify(info, st, checks, hist, exp, now, prev)
            since = prev.get("since") if prev.get("state") == state_ else now.isoformat()
            rec = {"state": state_, "detail": detail, "since": since, "domain": info.get("domain"),
                   "adapter": info.get("adapter"), "product": info.get("product"), "status": info.get("status"),
                   "mode": info.get("mode"), "items": info.get("items"),
                   "interval_minutes": info.get("interval_minutes"), "cadence_minutes": info.get("cadence_minutes"),
                   "consecutive_failures": int(st.get("failures") or 0),
                   "last_success": st["last_success"].isoformat() if st.get("last_success") else None,
                   "checks": [c.as_dict() for c in checks]}
            if prev.get("state") and prev.get("state") != state_:
                transitions.append({"source": key, "from": prev.get("state"), "to": state_, "detail": detail})
            out[key] = rec
            if ctx.store is not None and not ctx.dry_run:
                ctx.store.set_monitor_state(org, key, {**{k: prev.get(k) for k in ("alerted", "alerted_at") if k in prev},
                                                       "state": state_, "detail": detail, "since": since})
            # data the source itself reports as old is a control problem ControlAssurance already raises
            # (ctl-<domain>-health); the monitor raises findings for broken pipes only
            if state_ in raise_on and not (state_ == "stale" and detail.startswith("source data")):
                self._raise(ctx, state, key, rec, now)
            if state_ not in ("healthy", "awaiting_data", "retrying") and info.get("domain") in controls:
                controls[info["domain"]].health_issues.append(f"ingestion {key} {state_}: {detail}"[:200])
        counts: dict[str, int] = {}
        for r in out.values():
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        state.data_quality["ingestion"] = {"sources": out, "transitions": transitions, "states": counts,
                                           "healthy_pct": round(100 * counts.get("healthy", 0) / len(out), 1) if out else None}
        if transitions:
            ctx.record(self.name, "transitions", transitions=transitions[:20])
        return state

    @staticmethod
    def _raise(ctx: AgentContext, state: PipelineState, key: str, rec: dict[str, Any], now) -> None:
        dom = Domain(rec["domain"])
        mandatory = dom.value in ctx.vertical.mandatory_domains
        sev = Severity.HIGH if mandatory and rec["state"] in ("failing", "stale") else Severity.MEDIUM
        label = {"failing": "failing", "stale": "stale", "volume_drop": "volume drop",
                 "volume_spike": "volume spike", "degraded": "degraded"}.get(rec["state"], rec["state"])
        state.findings.append(Finding(
            finding_id=finding_id(key), domain=dom, source="lodestar.ingestion_monitor",
            finding_type=FindingType.COVERAGE_GAP, severity=sev,
            title=f"Ingestion {label}: {SPECS[dom].title} via {rec.get('product') or rec.get('adapter')} ({key})",
            description=f"{rec['detail']}. Until this is fixed LODESTAR shows the last good data for this source "
                        f"and never resolves its findings, so posture for {dom.value} may be out of date.",
            remediation="Run `lodestar check-ingestion --domain " + dom.value + "` to see which check fails; "
                        "fix credentials / endpoint / export job / field_map with the source owner.",
            first_seen=now, last_seen=now, evidence={"ingestion_state": rec["state"], "source_key": key}))
