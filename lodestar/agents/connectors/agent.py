"""ConnectorAgent - one instance per control domain (EDR, WAF, PAM, threat intel ...).

The agent is product-agnostic: it delegates collection to one or more adapters
(mock / file_drop / webhook / vendor API / feeds / mailbox) and then enforces the
contract: domain stamping, de-duplication, per-source failure isolation and a
single health record for the domain.
"""
from __future__ import annotations

from ...models import ControlHealth
from ..base import AgentContext, BaseAgent, PipelineState
from .adapters import AdapterResult, build_adapter
from .domains import SPECS, DomainSpec


class ConnectorAgent(BaseAgent):
    def __init__(self, spec: DomainSpec, sources: list[tuple[str, str, dict]]):
        self.spec = spec
        self.name = spec.agent_name
        self.phase = spec.phase
        self.description = spec.purpose
        self.adapters = [build_adapter(a, spec.domain, p or spec.typical_products[0], s) for a, p, s in sources]
        self.adapter = self.adapters[0]   # backwards compatibility

    def _merge_health(self, results: list[tuple[object, AdapterResult | None, str | None]]) -> ControlHealth | None:
        healths = [(ad, r.health) for ad, r, _ in results if r and r.health]
        failed = [(ad, err) for ad, _, err in results if err]
        if not healths and not failed:
            return None
        if len(results) == 1 and healths:
            return healths[0][1]
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
        results = []
        for ad in self.adapters:
            try:
                results.append((ad, ad.fetch(ctx), None))
            except Exception as exc:      # one broken feed must not hide the others
                if len(self.adapters) == 1:
                    raise
                results.append((ad, None, f"{type(exc).__name__}: {exc}"))
        findings = [f for _, r, _ in results if r for f in r.findings]
        warnings = [w for _, r, _ in results if r for w in r.warnings]
        health = self._merge_health(results)
        if health is None and not findings:
            # control not present in this environment - record, don't invent a failing control
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
            sources = [("mock", cc.product, {})]
        elif cc.sources:
            sources = [(s["adapter"], s["product"], s["settings"]) for s in cc.sources]
        else:
            sources = [(cc.adapter, cc.product, cc.settings)]
        agents.append(ConnectorAgent(sp, sources))
    return sorted(agents, key=lambda a: (a.phase, a.spec.domain.value))
