"""ReportingAgent - weekly (technical leads), monthly (CISO/CIO) and quarterly
(board / ExCo) reports in HTML (print-ready), Markdown and JSON.

Business-language rules applied to every report:
  * lead with the answer (posture, trend, what we need from you)
  * risk in terms of business services and money, not CVEs
  * every number traceable to the pipeline result (narrative guardrails)
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .agents.connectors.domains import SPECS
from .agents.core.narrative import summarise
from .metrics import kri_table
from .models import Horizon, PipelineResult, Status
from .verticals import load_vertical

TEMPLATES = Path(__file__).resolve().parent / "web" / "templates"
PERIODS = {"weekly": 7, "monthly": 30, "quarterly": 90}
AUDIENCE = {"weekly": "Security & IT technical leads", "monthly": "CISO, CIO and risk committee",
            "quarterly": "Board of Directors / Executive Committee"}

# indicative impact profile per attack-path rule (FAIR-lite, ranges not point estimates)
IMPACT = {
    "LDS-001": ("downtime", 8, 36), "LDS-002": ("downtime", 2, 8), "LDS-003": ("downtime", 6, 24),
    "LDS-004": ("downtime", 1, 6), "LDS-005": ("fraud", 0.5, 2.0), "LDS-006": ("records", 0.5, 1.0),
    "LDS-007": ("records", 0.05, 0.2), "LDS-008": ("records", 0.1, 0.4), "LDS-009": ("downtime", 8, 48),
    "LDS-010": ("downtime", 12, 72), "LDS-011": ("loss", 0.3, 1.0), "LDS-012": ("loss", 0.5, 1.0),
    "LDS-013": ("loss", 0.2, 0.6),
}

DECISIONS = {
    "priv_accounts_vaulted_pct": "Approve a 30-day PAM onboarding sprint for all remaining privileged accounts",
    "edr_coverage_pct": "Mandate EDR on all servers; fund replacement of legacy OS that cannot run it",
    "mfa_coverage_pct": "Enforce phishing-resistant MFA for 100% of the workforce and remove legacy authentication",
    "kev_open_count": "Endorse an emergency-change policy: known-exploited vulnerabilities fixed within 72 hours",
    "toxic_combinations_open": "Authorise a 24-hour emergency change window for attack-path remediation",
    "critical_vuln_sla_pct": "Add patching capacity or automate patch deployment for critical systems",
    "mttr_critical_days": "Set remediation SLAs as an IT performance objective with monthly review",
    "mttd_hours": "Invest in detection engineering / 24x7 MDR coverage to cut time-to-detect",
    "phishing_click_rate_pct": "Run targeted awareness for high-risk departments; report quarterly",
    "brand_takedown_hours": "Contract an accelerated takedown service level with the brand-protection provider",
    "internet_facing_critical_count": "Require security sign-off before any internet exposure of critical systems",
    "ot_unmanaged_remote_access_count": "Ban direct vendor remote access to OT; route through ZTNA/PAM jump hosts",
    "backup_immutability_pct": "Fund immutable / isolated backup for all crown-jewel systems",
    "waf_block_mode_pct": "Move all internet applications to WAF blocking mode within one release cycle",
    "cloud_critical_misconfig_count": "Enforce cloud guardrails (policy-as-code) to block critical misconfigurations",
    "fraud_channel_coverage_pct": "Make real-time fraud scoring a go-live condition for every payment channel",
    "fraud_alert_backlog_hours": "Fund fraud-operations capacity or automation to clear alerts within 24 hours",
    "fraud_detection_rate_pct": "Approve the joint cyber-fraud fusion process and model re-training plan",
}


def _money(x: float, cur: str) -> str:
    if x >= 1_000_000:
        return f"{cur} {x / 1_000_000:.1f}M"
    if x >= 1_000:
        return f"{cur} {x / 1_000:.0f}K"
    return f"{cur} {x:.0f}"


def exposure_estimate(result: PipelineResult) -> dict[str, Any]:
    v = load_vertical(result.vertical)
    fe = v.financial_exposure
    cur = fe.get("currency", "USD")
    by_id = {f.finding_id: f for f in result.findings}
    rows, lo_t, hi_t = [], 0.0, 0.0
    for c in result.correlations:
        kind, a, b = IMPACT.get(c.rule_id, ("downtime", 4, 12))
        if kind == "downtime":
            lo, hi = a * fe["downtime_cost_per_hour"], b * fe["downtime_cost_per_hour"]
        elif kind == "records":
            records = max((by_id[i].evidence.get("records_estimate", 0) for i in c.finding_ids if i in by_id), default=0) or 20000
            lo, hi = a * records * fe["cost_per_record"], b * records * fe["cost_per_record"]
            lo += 0.02 * fe["regulatory_fine_ceiling"] * a
            hi += 0.10 * fe["regulatory_fine_ceiling"] * b
        elif kind == "loss":
            value = max((by_id[i].evidence.get("exposed_value", 0) for i in c.finding_ids if i in by_id), default=0) or 500_000
            lo, hi = a * value, b * value
        else:
            lo, hi = a * fe["downtime_cost_per_hour"], b * fe["downtime_cost_per_hour"]   # fraud/response cost proxy
        # annualised probability of the path being exploited; fraud paths are already in progress
        likelihood = min(0.8, c.score / 100 * 0.5) if kind == "loss" else min(0.5, c.score / 100 * 0.25)
        lo, hi = lo * likelihood, hi * likelihood
        lo_t += lo
        hi_t += hi
        rows.append({"title": c.title, "entity": c.entity, "low": _money(lo, cur), "high": _money(hi, cur),
                     "likelihood_pct": round(likelihood * 100), "action": c.recommended_action})
    return {"rows": rows, "total_low": _money(lo_t, cur), "total_high": _money(hi_t, cur),
            "range": f"{_money(lo_t, cur)} - {_money(hi_t, cur)}",
            "method": "Indicative FAIR-style range: likelihood (from LODESTAR score) x impact (vertical downtime "
                      "cost, record cost and regulatory exposure). For prioritisation, not actuarial use."}


def build_context(result: PipelineResult, period: str, llm_cfg: dict | None = None) -> dict[str, Any]:
    if period not in PERIODS:
        raise ValueError(f"period must be one of {list(PERIODS)}")
    v = load_vertical(result.vertical)
    days = PERIODS[period]
    hist = result.history
    snap = result.snapshot
    prev = hist[-1 - days] if len(hist) > days else (hist[0] if hist else snap)
    act = [f for f in result.findings if f.status in (Status.OPEN, Status.IN_PROGRESS)]
    today = [f for f in act if f.horizon == Horizon.TODAY]
    week = [f for f in act if f.horizon == Horizon.THIS_WEEK]
    kris = kri_table(snap.kris, v)
    for k in kris:
        pv = prev.kris.get(k["metric"])
        k["previous"] = pv
        k["delta"] = round(k["value"] - pv, 1) if k["value"] is not None and pv is not None else None
        if k["delta"] is None or k["delta"] == 0:
            k["trend"] = "flat"
        else:
            better = (k["delta"] > 0) == (k["direction"] == "higher_better")
            k["trend"] = "improving" if better else "worsening"
    breaches = [k for k in kris if k["status"] == "breach" and k["metric"] != "posture_score"]
    decisions = [DECISIONS[k["metric"]] for k in breaches if k["metric"] in DECISIONS]
    if period == "quarterly":
        decisions = decisions[:5]          # a board can act on a handful of asks, not a backlog
    exposure = exposure_estimate(result)
    window = hist[-days:] if hist else [snap]
    new_total = sum(h.new_findings for h in window)
    closed_total = sum(h.closed_findings for h in window)
    controls = sorted(result.controls, key=lambda c: c.effectiveness)
    facts = {
        "period": period, "org": result.org_name, "vertical": v.name,
        "posture_score": snap.posture_score, "posture_prev": prev.posture_score,
        "today": len(today), "week": len(week), "total_open": len(act), "controls": len(result.controls),
        "attack_paths": len(result.correlations),
        "top_attack_path": result.correlations[0].title if result.correlations else None,
        "kris": [{"label": k["label"], "value": k["value"], "appetite": k["appetite"], "status": k["status"]} for k in kris],
        "exposure_estimate": exposure["range"] if result.correlations else None,
        "decisions": decisions,
    }
    summary, engine = summarise(facts, period, llm_cfg)
    trend = [{"date": h.date, "posture": h.posture_score} for h in hist[-max(days, 30):]]
    return {
        "period": period, "title": f"{period.capitalize()} Security {'Operations' if period == 'weekly' else 'Risk'} Report",
        "audience": AUDIENCE[period], "org": result.org_name, "vertical": v, "generated": result.generated_at,
        "from_date": prev.date, "to_date": snap.date, "summary": summary, "summary_engine": engine,
        "posture": snap.posture_score, "posture_prev": prev.posture_score,
        "posture_delta": round(snap.posture_score - prev.posture_score, 1),
        "appetite": next((k["appetite"] for k in kris if k["metric"] == "posture_score"), 75),
        "kris": kris, "breaches": breaches, "decisions": decisions,
        "today": today[:15], "week": week[:15], "counts": {"today": len(today), "week": len(week), "open": len(act),
                                                          "signals": len(result.findings)},
        "attack_paths": result.correlations[:10], "exposure": exposure,
        "controls": controls, "specs": SPECS, "weakest_controls": controls[:5],
        "sla_breaches": snap.sla_breaches, "sla_breaches_prev": prev.sla_breaches,
        "incidents": snap.incidents, "new_total": new_total, "closed_total": closed_total,
        "compliance": {k: c for k, c in result.compliance.items() if not k.startswith("_")},
        "actions": result.actions[:15], "data_quality": result.data_quality, "trend": trend,
        "decisions_pending": [d for d in result.decisions if d.get("status", "pending") == "pending"],
        "fraud": next((c for c in result.controls if c.domain.value == "fraud"), None),
        "threats": v.threat_landscape, "crown_jewels": v.crown_jewel_services,
    }


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html.j2", "html"], default_for_string=False),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["fmt"] = lambda v, u="": "n/a" if v is None else (f"{v:,.1f}".rstrip("0").rstrip(".") + (u or ""))
    env.filters["signed"] = lambda v: "n/a" if v is None else (f"+{v:g}" if v > 0 else f"{v:g}")
    return env


def _spark_points(trend: list[dict], w: int = 640, h: int = 140, pad: int = 28) -> dict[str, Any]:
    vals = [t["posture"] for t in trend] or [0]
    lo, hi = max(0, min(vals) - 5), min(100, max(vals) + 5)
    span = max(hi - lo, 1)
    n = max(len(vals) - 1, 1)
    pts = [(pad + i * (w - 2 * pad) / n, h - pad - (v - lo) / span * (h - 2 * pad)) for i, v in enumerate(vals)]
    ticks = [round(lo + span * f) for f in (0, 0.5, 1)]
    return {"w": w, "h": h, "pad": pad, "points": " ".join(f"{x:.1f},{y:.1f}" for x, y in pts),
            "last": pts[-1], "ticks": [(t, h - pad - (t - lo) / span * (h - 2 * pad)) for t in ticks],
            "first_date": trend[0]["date"] if trend else "", "last_date": trend[-1]["date"] if trend else ""}


def render(result: PipelineResult, period: str, fmt: str = "html", llm_cfg: dict | None = None) -> str:
    ctx = build_context(result, period, llm_cfg)
    if fmt == "json":
        safe = {k: v for k, v in ctx.items() if k not in ("vertical", "specs", "controls", "weakest_controls",
                                                         "today", "week", "attack_paths")}
        safe["vertical"] = ctx["vertical"].name
        safe["today"] = [f.model_dump(mode="json", include={"finding_id", "title", "score", "domain", "owner_team"}) for f in ctx["today"]]
        safe["attack_paths"] = [c.model_dump(mode="json") for c in ctx["attack_paths"]]
        safe["controls"] = [c.model_dump(mode="json") for c in ctx["controls"]]
        return json.dumps(safe, indent=2, default=str)
    ctx["chart"] = _spark_points(ctx["trend"])
    tpl = "report.html.j2" if fmt == "html" else "report.md.j2"
    return _env().get_template(tpl).render(**ctx)


def write_reports(result: PipelineResult, out_dir: Path, periods=("weekly", "monthly", "quarterly"),
                  formats=("html", "md", "json"), llm_cfg: dict | None = None) -> list[Path]:
    slug = "".join(ch if ch.isalnum() else "-" for ch in result.org_name.lower()).strip("-").replace("--", "-")
    stamp = result.snapshot.date if isinstance(result.snapshot.date, str) else date.today().isoformat()
    out_dir = out_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for p in periods:
        for fmt in formats:
            path = out_dir / f"{stamp}_{p}.{fmt}"
            path.write_text(render(result, p, fmt, llm_cfg), encoding="utf-8")
            paths.append(path)
    return paths
