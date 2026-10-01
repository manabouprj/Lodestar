"""ComplianceMappingAgent (Phase 3) - translate findings into framework language.

Control status: at_risk = 3+ Today findings, attention = any Today finding or
5+ this-week findings. Readiness = on-track 100%, attention 60%, at-risk 20%.
Maps each control domain to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A and
PCI DSS v4.0.1 (config/frameworks.yaml). For each mapped control it reports
open Today/Week findings so audit and regulators see the same picture as the
SOC. Vertical-specific frameworks are listed from the vertical profile;
mapping packs for them are added as YAML (see docs/CONNECTOR_GUIDE.md).
"""
from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import yaml

from ...models import Horizon, Status
from ..base import AgentContext, BaseAgent, PipelineState

FRAMEWORKS_FILE = Path(__file__).resolve().parents[3] / "config" / "frameworks.yaml"


@lru_cache(maxsize=4)
def load_mappings(path: str = str(FRAMEWORKS_FILE)) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


class ComplianceMappingAgent(BaseAgent):
    name = "ComplianceMappingAgent"
    phase = 3
    description = "Maps findings to NIST CSF 2.0, ISO 27001 and PCI DSS controls; flags at-risk controls."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        maps = load_mappings()
        result = {}
        applicable = [fw for fw in maps["frameworks"] if fw["applies_to"] == "all"
                      or fw["name"] in ctx.vertical.frameworks]
        for fw in applicable:
            controls = defaultdict(lambda: {"today": 0, "week": 0, "open": 0, "domains": set()})
            for f in state.findings:
                if f.status not in (Status.OPEN, Status.IN_PROGRESS):
                    continue
                for cid in fw["mapping"].get(f.domain.value, []):
                    tag = f"{fw['short']}:{cid}"
                    if tag not in f.frameworks:
                        f.frameworks.append(tag)
                    c = controls[cid]
                    c["open"] += 1
                    c["domains"].add(f.domain.value)
                    if f.horizon == Horizon.TODAY:
                        c["today"] += 1
                    elif f.horizon == Horizon.THIS_WEEK:
                        c["week"] += 1
            rows = []
            for cid, c in sorted(controls.items()):
                status = "at_risk" if c["today"] >= 3 else ("attention" if c["today"] or c["week"] >= 5 else "on_track")
                rows.append({"control": cid, "name": fw["names"].get(cid, cid), "status": status,
                             "today": c["today"], "week": c["week"], "open": c["open"],
                             "domains": sorted(c["domains"])})
            mapped = {cid for v in fw["mapping"].values() for cid in v}
            at_risk = sum(1 for r in rows if r["status"] == "at_risk")
            attention = sum(1 for r in rows if r["status"] == "attention")
            # readiness: on-track controls count fully, attention 60%, at-risk 20%
            readiness = (len(mapped) - at_risk - attention + 0.6 * attention + 0.2 * at_risk) / len(mapped) if mapped else 1.0
            result[fw["short"]] = {"name": fw["name"], "controls_mapped": len(mapped), "at_risk": at_risk,
                                   "attention": attention, "readiness_pct": round(100 * readiness, 1),
                                   "controls": rows}
        result["_vertical_frameworks"] = ctx.vertical.frameworks
        state.compliance = result
        return state
