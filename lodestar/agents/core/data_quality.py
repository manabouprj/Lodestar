"""DataQualityAgent (Phase 0) - trust but verify the data before scoring.

* drops exact duplicates and the same CVE reported twice for one asset
* tracks the CMDB match rate (findings whose asset is unknown get a default
  criticality of 3 - flagged so the CMDB owner can fix it)
* checks every *mandatory* control for the vertical is actually integrated
* flags stale connectors (no fresh data) so the dashboard never presents
  old data as current
"""
from __future__ import annotations

import re

from ...models import Domain
from ..base import AgentContext, BaseAgent, PipelineState
from .asset_context import asset_match_rate


def norm_host(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)       # scheme
    v = v.split("/", 1)[0].split("@")[-1]              # path, credentials
    v = re.sub(r":\d+$", "", v)                         # port
    return v[4:] if v.startswith("www.") else v


def alias_index(assets: dict) -> tuple[dict[str, str], list[tuple[str, str]]]:
    exact, wild = {}, []
    for a in assets.values():
        for key in [a.asset_id, a.name, *a.aliases]:
            k = norm_host(key)
            if k.startswith("*."):
                wild.append((k[1:], a.asset_id))
            elif k:
                exact.setdefault(k, a.asset_id)
    return exact, wild


def resolve(value: str | None, exact: dict, wild: list) -> str | None:
    if not value:
        return None
    k = norm_host(value)
    if k in exact:
        return exact[k]
    return next((aid for suffix, aid in wild if k.endswith(suffix)), None)


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

        # map hostnames / URLs / FQDNs used by external reports (bug bounty, advisories, e-mail) to CMDB assets
        exact, wild = alias_index(state.assets)
        resolved = 0
        for f in state.findings:
            if f.asset_id and f.asset_id not in state.assets:
                hit = resolve(f.asset_id, exact, wild)
                if hit:
                    f.asset_id, resolved = hit, resolved + 1
                    if f.app_id and f.app_id not in state.assets:
                        f.app_id = hit
                elif f.domain == Domain.BUG_BOUNTY:
                    f.evidence.setdefault("tags", []).append("unknown_asset")
            # correlation keys shared across tools and intel sources
            if f.cve and f"cve:{f.cve.upper()}" not in f.entity_keys:
                f.entity_keys.append(f"cve:{f.cve.upper()}")
            for ioc in ([f.evidence["ioc"]] if f.evidence.get("ioc") else []) + \
                    (f.evidence.get("iocs", []) if f.domain != Domain.THREAT_INTEL else []):
                key = f"ioc:{str(ioc).lower()}"
                if key not in f.entity_keys:
                    f.entity_keys.append(key)
        dq_resolved = resolved

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
