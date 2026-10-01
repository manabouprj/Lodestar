"""ConnectorAgent - one instance per control domain (EDR, WAF, PAM ...).

The agent is product-agnostic: it delegates collection to an adapter
(mock / file_drop / webhook / vendor API) and then enforces the contract:
domain stamping, de-duplication, basic validation and health reporting.
"""
from __future__ import annotations

from ...models import ControlHealth
from ..base import AgentContext, BaseAgent, PipelineState
from .adapters import build_adapter
from .domains import SPECS, DomainSpec


class ConnectorAgent(BaseAgent):
    def __init__(self, spec: DomainSpec, adapter_name: str, product: str, settings: dict):
        self.spec = spec
        self.name = spec.agent_name
        self.phase = spec.phase
        self.description = spec.purpose
        self.adapter = build_adapter(adapter_name, spec.domain, product or spec.typical_products[0], settings)

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        result = self.adapter.fetch(ctx)
        if result.health is None and not result.findings:
            # control not present in this environment - record, don't invent a failing control
            state.data_quality.setdefault("not_integrated", []).append(self.spec.domain.value)
            ctx.record(self.name, "no_data", domain=self.spec.domain.value, warnings=result.warnings[:3])
            return state
        seen = {f.finding_id for f in state.findings}
        added = 0
        for f in result.findings:
            if f.domain != self.spec.domain:
                f.domain = self.spec.domain
            if f.finding_id in seen:
                continue
            seen.add(f.finding_id)
            state.findings.append(f)
            added += 1
        health = result.health or ControlHealth(domain=self.spec.domain, product=self.adapter.product,
                                                coverage_pct=0.0, data_freshness_hours=999.0,
                                                health_issues=["Adapter returned no health telemetry"])
        state.controls.append(health)
        dq = state.data_quality.setdefault("connectors", {})
        dq[self.spec.domain.value] = {"adapter": self.adapter.name, "product": self.adapter.product,
                                      "findings": added, "warnings": result.warnings[:20]}
        ctx.record(self.name, "collected", domain=self.spec.domain.value, findings=added,
                   warnings=len(result.warnings))
        return state


def build_connector_agents(settings, max_phase: int) -> list[ConnectorAgent]:
    agents = []
    for domain, cc in settings.connectors.items():
        sp = SPECS[domain]
        if not cc.enabled or sp.phase > max_phase:
            continue
        adapter = "mock" if settings.mode == "demo" else cc.adapter
        agents.append(ConnectorAgent(sp, adapter, cc.product, cc.settings))
    return sorted(agents, key=lambda a: (a.phase, a.spec.domain.value))
