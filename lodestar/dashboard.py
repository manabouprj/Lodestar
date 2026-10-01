"""Builds the JSON payload behind the CISO prioritisation dashboard."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .agents.connectors.domains import SPECS
from .chatops.engine import precomputed
from .metrics import kri_table
from .models import Domain, Horizon, PipelineResult, Status
from .verticals import load_vertical

ACTIVE = (Status.OPEN, Status.IN_PROGRESS)


def _finding_row(f, assets_lookup: dict[str, str]) -> dict[str, Any]:
    return {
        "id": f.finding_id, "score": f.score, "horizon": f.horizon.value if f.horizon else None,
        "title": f.title, "domain": f.domain.value, "domain_title": SPECS[f.domain].title,
        "severity": f.severity.value, "type": f.finding_type.value, "source": f.source,
        "asset": assets_lookup.get(f.asset_id or "", f.asset_id), "user": f.user_id, "cve": f.cve, "kev": f.kev,
        "owner": f.owner_team, "why": f.why, "remediation": f.remediation,
        "due": f.due_date.date().isoformat() if f.due_date else None,
        "first_seen": f.first_seen.date().isoformat(), "attack_path": bool(f.correlation_ids),
        "frameworks": f.frameworks[:6],
    }


def _delta(history, key: str, days: int):
    if len(history) <= days:
        return None
    prev = history[-1 - days]
    cur = history[-1]
    a = getattr(prev, key) if hasattr(prev, key) else prev.kris.get(key)
    b = getattr(cur, key) if hasattr(cur, key) else cur.kris.get(key)
    if a is None or b is None:
        return None
    return round(b - a, 1)


def _fraud(result: PipelineResult, assets: dict[str, str]) -> dict[str, Any] | None:
    ctl = next((c for c in result.controls if c.domain == Domain.FRAUD), None)
    if not ctl:
        return None
    items = [f for f in result.findings if f.domain == Domain.FRAUD and f.status in ACTIVE
             and f.horizon in (Horizon.TODAY, Horizon.THIS_WEEK)]
    return {
        "product": ctl.product, "kpis": ctl.kpis, "status": ctl.status, "issues": ctl.health_issues,
        "paths": [{"title": c.title, "entity": c.entity, "score": c.score, "rule": c.rule_id,
                   "domains": [d.value for d in c.domains], "action": c.recommended_action}
                  for c in result.correlations if Domain.FRAUD in c.domains],
        "items": [_finding_row(f, assets) for f in sorted(items, key=lambda x: -x.score)[:30]],
        "decisions": [d["decision_id"] for d in result.decisions if d["type"] in ("fraud_response", "str_filing")],
    }


def build_payload(result: PipelineResult, assets: dict[str, str] | None = None) -> dict[str, Any]:
    v = load_vertical(result.vertical)
    assets = assets or result.asset_names
    act = [f for f in result.findings if f.status in ACTIVE]
    by_h: dict[str, list] = {h.value: [] for h in Horizon}
    for f in act:
        if f.horizon:
            by_h[f.horizon.value].append(f)
    limits = {"today": 60, "week": 60, "month": 50, "backlog": 0}
    lists = {h: [_finding_row(f, assets) for f in sorted(items, key=lambda x: -x.score)[:limits[h]]]
             for h, items in by_h.items()}
    hist = result.history
    snap = result.snapshot
    team_load = Counter(f.owner_team for f in by_h["today"] + by_h["week"])
    controls = []
    for c in sorted(result.controls, key=lambda c: c.effectiveness):
        sp = SPECS[c.domain]
        controls.append({"domain": c.domain.value, "title": sp.title, "product": c.product, "phase": sp.phase,
                         "effectiveness": c.effectiveness, "coverage": c.coverage_pct, "status": c.status,
                         "freshness_h": c.data_freshness_hours, "drift": c.policy_drift_items,
                         "issues": c.health_issues, "open": snap.open_by_domain.get(c.domain.value, 0)})
    integrated = {c.domain for c in result.controls}
    not_integrated = [{"domain": d.value, "title": SPECS[d].title, "mandatory": d.value in v.mandatory_domains}
                      for d in Domain if d not in integrated]
    trend = [{"date": h.date, "posture": h.posture_score, "today": h.open_by_horizon.get("today", 0),
              "week": h.open_by_horizon.get("week", 0), "sla": h.sla_breaches} for h in hist[-180:]]
    compliance = [{"key": k, "name": c["name"], "readiness": c["readiness_pct"], "at_risk": c["at_risk"],
                   "attention": c["attention"], "mapped": c["controls_mapped"],
                   "controls": [r for r in c["controls"] if r["status"] != "on_track"][:12]}
                  for k, c in result.compliance.items() if not k.startswith("_")]
    kris = kri_table(snap.kris, v)
    for k in kris:
        k["delta30"] = _delta(hist, k["metric"], 30)
        k["spark"] = [h.kris.get(k["metric"]) for h in hist[-90:]]
    return {
        "org": result.org_name, "vertical": v.name, "vertical_id": v.id,
        "generated_at": result.generated_at.isoformat() if isinstance(result.generated_at, datetime) else str(result.generated_at),
        "frameworks": v.frameworks, "crown_jewels": v.crown_jewel_services, "threats": v.threat_landscape,
        "posture": snap.posture_score, "posture_d7": _delta(hist, "posture_score", 7),
        "posture_d30": _delta(hist, "posture_score", 30), "appetite": next((k["appetite"] for k in v.kris if k["metric"] == "posture_score"), 75),
        "funnel": {"signals": len(result.findings), "open": len(act), "week": len(by_h["week"]),
                   "today": len(by_h["today"]), "attack_paths": len(result.correlations)},
        "counts": {h: len(items) for h, items in by_h.items()},
        "sla_breaches": snap.sla_breaches, "incidents": snap.incidents,
        "lists": lists,
        "attack_paths": [{**c.model_dump(mode="json"), "domains": [d.value for d in c.domains]} for c in result.correlations],
        "controls": controls, "not_integrated": not_integrated,
        "kris": kris, "trend": trend, "compliance": compliance,
        "team_load": dict(team_load.most_common()),
        "actions": result.actions[:40],
        "decisions": result.decisions[:30],
        "chat": precomputed(result),
        "fraud": _fraud(result, assets),
        "data_quality": {k: result.data_quality.get(k) for k in ("trust_score", "confidence", "asset_match_rate_pct", "stale_connectors",
                         "mandatory_controls_missing", "duplicates_removed", "today_deferred", "phase", "agent_failures")},
    }
