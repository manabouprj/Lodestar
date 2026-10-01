"""ConnectorAgent - one instance per control domain (EDR, WAF, PAM, threat intel ...).

The agent is product-agnostic: it delegates collection to one or more adapters
(mock / file_drop / webhook / vendor API / SIEM query / feeds / mailbox) and then
enforces the contract:
  * per-source failure isolation (a failed source never resolves its findings)
  * per-source sync cursor and minimum interval, persisted in connector_state
  * every finding is stamped with its source key and sync mode for the LifecycleAgent
  * one merged health record per domain
"""
from __future__ import annotations

from datetime import timedelta

from ...models import ControlHealth
from ..base import AgentContext, BaseAgent, PipelineState
from .adapters import build_adapter
from .domains import SPECS, DomainSpec


class ConnectorAgent(BaseAgent):
    def __init__(self, spec: DomainSpec, sources: list[tuple]):
        self.spec = spec
        self.name = spec.agent_name
        self.phase = spec.phase
        self.description = spec.purpose
        self.adapters, self.intervals, self.keys = [], [], []
        seen: dict[str, int] = {}
        for src in sources:
            a, p, s = src[0], src[1], src[2]
            ad = build_adapter(a, spec.domain, p or spec.typical_products[0], s)
            key = f"{spec.domain.value}/{a}"
            seen[key] = seen.get(key, 0) + 1
            self.keys.append(key if seen[key] == 1 else f"{key}#{seen[key]}")
            self.adapters.append(ad)
            self.intervals.append(int(src[3]) if len(src) > 3 and src[3] else 0)
        self.adapter = self.adapters[0]   # backwards compatibility

    def _merge_health(self, results) -> ControlHealth | None:
        healths = [(ad, r.health) for ad, r, _ in results if r and r.health]
        failed = [(ad, err) for ad, _, err in results if err]
        if not healths and not failed:
            return None
        if len(results) == 1 and healths:
            return healths[0][1]
        if not healths:
            ad, err = failed[0]
            return ControlHealth(domain=self.spec.domain, product=ad.product, coverage_pct=0.0, data_freshness_hours=999.0,
                                 health_issues=[f"{ad.product}: source failed ({err[:120]})"])
        n = len(results)
        ok = [h for _, h in healths]
        kpis: dict = {}
        for h in ok:
            for k, v in h.kpis.items():
                kpis[k] = kpis.get(k, 0) + v if isinstance(v, (int, float)) and isinstance(kpis.get(k, 0), (int, float)) else v
        stale = [ad.product for ad, h in healths if h.data_freshness_hours > 48]
        kpis.update({"feeds_active": len(ok) - len(stale), "feeds_stale": len(stale) + len(failed)})
        issues = [f"{ad.product}: source failed ({err[:80]})" for ad, err in failed] + \
                 [f"{p}: no new data for > 48h" for p in stale] + [i for h in ok for i in h.health_issues]
        return ControlHealth(
            domain=self.spec.domain, product=" + ".join(ad.product for ad, *_ in results),
            coverage_pct=round(100 * (len(ok) - len(stale)) / n, 1),
            data_freshness_hours=min((h.data_freshness_hours for h in ok), default=999.0),
            policy_drift_items=sum(h.policy_drift_items for h in ok), health_issues=issues, kpis=kpis)

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        org = ctx.settings.org_name
        sources = state.data_quality.setdefault("sources", {})
        results = []
        for ad, key, interval in zip(self.adapters, self.keys, self.intervals, strict=True):
            st = ctx.store.connector_state(org, key) if ctx.store is not None else {}
            ad.cursor = st.get("cursor")
            if interval and not ctx.force and st.get("last_success") and \
                    ctx.now < st["last_success"] + timedelta(minutes=interval):
                sources[key] = {"status": "skipped", "mode": ad.sync_mode, "domain": self.spec.domain.value,
                                "reason": f"interval {interval} min not elapsed"}
                continue
            try:
                r = ad.fetch(ctx)
            except Exception as exc:      # one broken source must not hide the others, nor resolve its findings
                err = f"{type(exc).__name__}: {exc}"
                results.append((ad, None, err))
                sources[key] = {"status": "failed", "mode": ad.sync_mode, "domain": self.spec.domain.value, "error": err[:300]}
                state.data_quality.setdefault("agent_failures", []).append({"agent": self.name, "source": key, "error": err[:300]})
                ctx.record(self.name, "source_failed", source=key, error=err[:300])
                if ctx.store is not None and not ctx.dry_run:
                    ctx.store.set_connector_state(org, key, ok=False, error=err)
                continue
            no_data = r.health is None and not r.findings
            sources[key] = {"status": "no_data" if no_data else "ok", "mode": ad.sync_mode,
                            "domain": self.spec.domain.value, "items": len(r.findings)}
            for f in r.findings:
                f.evidence["_src"], f.evidence["_sync"] = key, ad.sync_mode
            results.append((ad, r, None))
            if ctx.store is not None and not ctx.dry_run and not no_data:
                ctx.store.set_connector_state(org, key, ok=True, cursor=r.cursor, items=len(r.findings))
        if not results:
            return state          # everything skipped by interval - LifecycleAgent carries findings forward
        findings = [f for _, r, _ in results if r for f in r.findings]
        warnings = [w for _, r, _ in results if r for w in r.warnings]
        health = self._merge_health(results)
        if health is None and not findings:
            state.data_quality.setdefault("not_integrated", []).append(self.spec.domain.value)
            ctx.record(self.name, "no_data", domain=self.spec.domain.value, warnings=warnings[:3])
            return state
        seen = {f.finding_id for f in state.findings}
        added = 0
        for f in findings:
            if f.domain != self.spec.domain:
                f.domain = self.spec.domain
            if f.finding_id in seen:
                continue
            seen.add(f.finding_id)
            state.findings.append(f)
            added += 1
        health = health or ControlHealth(domain=self.spec.domain, product=self.adapter.product, coverage_pct=0.0,
                                         data_freshness_hours=999.0, health_issues=["Adapter returned no health telemetry"])
        state.controls.append(health)
        dq = state.data_quality.setdefault("connectors", {})
        dq[self.spec.domain.value] = {"adapter": ",".join(a.name for a in self.adapters), "product": health.product,
                                      "findings": added, "warnings": warnings[:20],
                                      "source_failures": [e for *_, e in results if e]}
        ctx.record(self.name, "collected", domain=self.spec.domain.value, findings=added, warnings=len(warnings))
        return state


def build_connector_agents(settings, max_phase: int) -> list[ConnectorAgent]:
    agents = []
    for domain, cc in settings.connectors.items():
        sp = SPECS[domain]
        if not cc.enabled or sp.phase > max_phase:
            continue
        if settings.mode == "demo":
            sources = [("mock", cc.product, {}, 0)]
        elif cc.sources:
            sources = [(s["adapter"], s["product"], s["settings"], s.get("interval_minutes", 0)) for s in cc.sources]
        else:
            sources = [(cc.adapter, cc.product, cc.settings, cc.interval_minutes)]
        agents.append(ConnectorAgent(sp, sources))
    return sorted(agents, key=lambda a: (a.phase, a.spec.domain.value))
