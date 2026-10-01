"""DataQualityAgent (Phase 0) - trust but verify the data before scoring.

* drops exact duplicates and the same CVE reported twice for one asset
* tracks the CMDB match rate (findings whose asset is unknown get a default
  criticality of 3 - flagged so the CMDB owner can fix it)
* checks every *mandatory* control for the vertical is actually integrated
* flags stale connectors (no fresh data) so the dashboard never presents
  old data as current
"""
from __future__ import annotations

from ...entities import EntityResolver, norm_host  # noqa: F401  (norm_host re-exported for compatibility)
from ...models import Domain
from ..base import AgentContext, BaseAgent, PipelineState
from .asset_context import asset_match_rate


class DataQualityAgent(BaseAgent):
    name = "DataQualityAgent"
    phase = 0
    description = "Deduplicates, validates and scores the trustworthiness of incoming data."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        icfg = ctx.settings.raw.get("identity") or {}
        res = EntityResolver(state.assets, state.identities, primary_domain=icfg.get("primary_domain"),
                             domains=icfg.get("domains") or [])
        state.resolver = res
        # 1. entity resolution: hosts / IPs / MACs / device ids / URLs -> CMDB asset; user spellings -> one identity
        resolved, how_counts, users_norm = 0, {}, 0
        for f in state.findings:
            ev = f.evidence
            if f.asset_id not in state.assets or (f.asset_id is None and (ev.get("ip") or ev.get("device_id"))):
                aid, how = res.asset(f.asset_id, ev.get("device_id"), ev.get("device_ids"), ev.get("ip"), ev.get("ips"),
                                     ev.get("mac"), f.app_id)
                if aid:
                    if f.asset_id and f.asset_id != aid:
                        ev.setdefault("reported_asset", f.asset_id)
                    f.asset_id, resolved = aid, resolved + 1
                    how_counts[how] = how_counts.get(how, 0) + 1
                elif f.domain == Domain.BUG_BOUNTY and f.asset_id:
                    ev.setdefault("tags", []).append("unknown_asset")
            if f.app_id and f.app_id not in state.assets:
                aid, _ = res.asset(f.app_id)
                if aid:
                    f.app_id = aid
            if f.user_id:
                uid, how = res.user(f.user_id)
                if uid and uid != f.user_id:
                    ev.setdefault("reported_user", f.user_id)
                    f.user_id, users_norm = uid, users_norm + 1
        # 2. de-duplicate (after resolution, so FQDN / short-name duplicates collapse)
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
        # 3. correlation keys shared across tools and intel sources
        for f in state.findings:
            if f.cve and f"cve:{f.cve.upper()}" not in f.entity_keys:
                f.entity_keys.append(f"cve:{f.cve.upper()}")
            for ioc in ([f.evidence["ioc"]] if f.evidence.get("ioc") else []) + \
                    (f.evidence.get("iocs", []) if f.domain != Domain.THREAT_INTEL else []):
                key = f"ioc:{str(ioc).lower()}"
                if key not in f.entity_keys:
                    f.entity_keys.append(key)
        dq_resolved = resolved
        state.data_quality["entity_resolution"] = {"assets_resolved": resolved, "by_method": how_counts,
                                                   "users_normalised": users_norm, "identities_loaded": len(state.identities),
                                                   "ambiguous_keys": sorted(res.ambiguous)[:25]}

        integrated = {c.domain.value for c in state.controls}
        missing = [d for d in ctx.vertical.mandatory_domains if d not in integrated]
        stale = [c.domain.value for c in state.controls if c.data_freshness_hours > 48]
        unknown_assets = sorted({f.asset_id for f in state.findings if f.asset_id and f.asset_id not in state.assets
                                 and f.domain != Domain.BUG_BOUNTY})
        match = asset_match_rate(state)
        dq = state.data_quality
        dq.update({
            "duplicates_removed": before - len(unique),
            "external_refs_resolved": dq_resolved,
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
