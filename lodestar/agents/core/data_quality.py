"""DataQualityAgent (Phase 0) - trust but verify the data before scoring.

* drops exact duplicates and the same CVE reported twice for one asset
* tracks the CMDB match rate (findings whose asset is unknown get a default
  criticality of 3 - flagged so the CMDB owner can fix it)
* checks every *mandatory* control for the vertical is actually integrated
* flags stale connectors (no fresh data) so the dashboard never presents
  old data as current
"""
from __future__ import annotations

from ...models import Domain
from ..base import AgentContext, BaseAgent, PipelineState
from .asset_context import asset_match_rate


class DataQualityAgent(BaseAgent):
    name = "DataQualityAgent"
    phase = 0
    description = "Deduplicates, validates and scores the trustworthiness of incoming data."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        before = len(state.findings)
        seen_ids, seen_vuln, unique = set(), set(), []
        for f in state.findings:
            if f.finding_id in seen_ids:
                continue
            if f.cve and f.asset_id:
                key = (f.cve, f.asset_id)
                if key in seen_vuln:
                    continue
                seen_vuln.add(key)
            seen_ids.add(f.finding_id)
            unique.append(f)
        state.findings = unique

        integrated = {c.domain.value for c in state.controls}
        missing = [d for d in ctx.vertical.mandatory_domains if d not in integrated]
        stale = [c.domain.value for c in state.controls if c.data_freshness_hours > 48]
        unknown_assets = sorted({f.asset_id for f in state.findings if f.asset_id and f.asset_id not in state.assets})
        match = asset_match_rate(state)
        dq = state.data_quality
        dq.update({
            "duplicates_removed": before - len(unique),
            "asset_match_rate_pct": match,
            "unknown_assets_sample": unknown_assets[:25],
            "mandatory_controls_missing": missing,
            "stale_connectors": stale,
            "integrated_domains": sorted(integrated),
            "all_domains": [d.value for d in Domain],
        })
        score = 100.0
        score -= min(30, 5 * len(missing))
        score -= min(30, 10 * len(stale))
        score -= max(0.0, (95 - match)) * 0.8
        dq["trust_score"] = round(max(0.0, score), 1)
        # a posture score built on missing data must say so
        dq["confidence"] = "high" if score >= 85 else ("medium" if score >= 65 else "low")
        return state
