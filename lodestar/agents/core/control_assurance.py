"""ControlAssuranceAgent (Phase 1) - "are my controls actually working?"

Effectiveness (0-100) per control =
    55% coverage  + 20% data freshness + 15% policy drift + 10% health issues
Status: stale (>48h no data) | failing (<60) | degraded (<80) | healthy
A degraded control also generates a COVERAGE_GAP finding so it is
prioritised alongside threats - a broken control IS a risk.
"""
from __future__ import annotations

from ...models import Finding, FindingType, Severity
from ..base import AgentContext, BaseAgent, PipelineState
from ..connectors.domains import SPECS


def effectiveness(coverage: float, freshness_h: float, drift: int, issues: int) -> float:
    fresh = 100.0 if freshness_h <= 24 else max(0.0, 100 - (freshness_h - 24) * (100 / 144))
    drift_s = max(0.0, 100 - drift * 5)
    issue_s = max(0.0, 100 - issues * 25)
    return round(0.55 * coverage + 0.20 * fresh + 0.15 * drift_s + 0.10 * issue_s, 1)


class ControlAssuranceAgent(BaseAgent):
    name = "ControlAssuranceAgent"
    phase = 1
    description = "Measures coverage, freshness and drift of every integrated security control."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        for c in state.controls:
            c.effectiveness = effectiveness(c.coverage_pct, c.data_freshness_hours, c.policy_drift_items,
                                            len(c.health_issues))
            if c.data_freshness_hours > 48:
                c.status = "stale"
            elif c.effectiveness < 60:
                c.status = "failing"
            elif c.effectiveness < 80:
                c.status = "degraded"
            else:
                c.status = "healthy"
            if c.status in ("failing", "stale") or (c.status == "degraded" and c.domain.value in ctx.vertical.mandatory_domains):
                sev = Severity.HIGH if c.status in ("failing", "stale") else Severity.MEDIUM
                issues = "; ".join(c.health_issues[:3]) or "below effectiveness threshold"
                state.findings.append(Finding(
                    finding_id=f"ctl-{c.domain.value}-health", domain=c.domain, source="lodestar.control_assurance",
                    finding_type=FindingType.COVERAGE_GAP, severity=sev,
                    title=f"{SPECS[c.domain].title} control {c.status} ({c.effectiveness:.0f}/100)",
                    description=f"Coverage {c.coverage_pct:.1f}%, data age {c.data_freshness_hours:.0f}h, "
                                f"{c.policy_drift_items} drift items. {issues}",
                    remediation="Restore coverage/telemetry and resolve policy drift; confirm with control owner.",
                    first_seen=ctx.now, last_seen=ctx.now))
        return state
