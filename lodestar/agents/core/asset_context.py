"""AssetContextAgent (Phase 0) - business context for every finding.

Prioritisation is only as good as asset context. Loads the CMDB / crown-jewel
register (CSV export or demo dataset), then reports the asset match rate so
gaps in the CMDB are visible instead of silently skewing scores.
CSV columns: asset_id,name,asset_type,business_service,owner,criticality,exposure,data_classification,tags,aliases,ips,macs,external_ids
(list columns are ;-separated - aliases are the hostnames / FQDNs / URLs / *.wildcards tools and researchers use;
 external_ids are EDR device ids, cloud resource ids / ARNs etc.)
Optional identities export (identity.path, default config/identities.csv):
identity_id,display_name,upn,email,sam,entra_object_id,aliases,privileged,department
"""
from __future__ import annotations

import csv

from ...models import Asset, Exposure
from ..base import AgentContext, BaseAgent, PipelineState


class AssetContextAgent(BaseAgent):
    name = "AssetContextAgent"
    phase = 0
    description = "Loads CMDB / crown-jewel register and enriches findings with business context."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        assets: dict[str, Asset] = {}
        if ctx.dataset and ctx.dataset.get("assets"):
            for a in ctx.dataset["assets"]:
                asset = Asset.model_validate(a)
                assets[asset.asset_id] = asset
        path = ctx.settings.assets_path
        if path and path.exists():
            with path.open(newline="", encoding="utf-8-sig") as fh:
                for row in csv.DictReader(fh):
                    row = {k: v for k, v in row.items() if v not in (None, "")}
                    row["tags"] = [t.strip() for t in row.get("tags", "").split(";") if t.strip()]
                    for col in ("aliases", "ips", "macs", "external_ids"):
                        row[col] = [t.strip() for t in row.get(col, "").split(";") if t.strip()]
                    row["criticality"] = int(row.get("criticality", 3))
                    row["exposure"] = Exposure(row.get("exposure", "internal"))
                    asset = Asset.model_validate(row)
                    assets[asset.asset_id] = asset
        state.assets = assets
        from ...entities import load_identities
        icfg = ctx.settings.raw.get("identity") or {}
        ipath = icfg.get("path", "config/identities.csv")
        state.identities = load_identities(ctx.settings.path(ipath)) if ipath else []
        return state


def asset_match_rate(state: PipelineState) -> float:
    with_asset = [f for f in state.findings if f.asset_id]
    if not with_asset:
        return 100.0
    return round(100 * sum(1 for f in with_asset if f.asset_id in state.assets) / len(with_asset), 1)
