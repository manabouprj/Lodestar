"""KRIs, posture score and daily snapshot calculation (shared by agents & reports)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import (
    ControlHealth,
    Correlation,
    DailySnapshot,
    Domain,
    Exposure,
    Finding,
    FindingType,
    Horizon,
    Severity,
    Status,
)
from .verticals import VerticalProfile

ACTIVE = {Status.OPEN, Status.IN_PROGRESS}


def active(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.status in ACTIVE]


def _kpi(controls: dict[str, ControlHealth], domain: str, key: str, default: float | None = None):
    c = controls.get(domain)
    if not c:
        return default
    if key == "coverage_pct":
        return c.coverage_pct
    return c.kpis.get(key, default)


def compute_kris(findings: list[Finding], controls: list[ControlHealth], correlations: list[Correlation],
                 assets: dict, now: datetime) -> dict[str, float]:
    ctl = {c.domain.value: c for c in controls}
    act = active(findings)
    crit_vulns = [f for f in act if f.domain == Domain.VMDR and f.severity == Severity.CRITICAL]
    in_sla = [f for f in crit_vulns if not f.due_date or f.due_date.replace(tzinfo=f.due_date.tzinfo or timezone.utc) >= now]
    internet_crit = [f for f in act if f.severity in (Severity.CRITICAL,)
                     and f.asset_id in assets and assets[f.asset_id].exposure == Exposure.INTERNET]
    k: dict[str, Any] = {
        "edr_coverage_pct": _kpi(ctl, "edr", "coverage_pct"),
        "mfa_coverage_pct": _kpi(ctl, "identity", "mfa_coverage_pct", _kpi(ctl, "identity", "coverage_pct")),
        "priv_accounts_vaulted_pct": _kpi(ctl, "pam", "vaulted_pct", _kpi(ctl, "pam", "coverage_pct")),
        # prefer the scanner's own closed+open SLA statistic; fall back to open-only calculation
        "critical_vuln_sla_pct": _kpi(ctl, "vmdr", "critical_sla_pct",
                                      round(100 * len(in_sla) / len(crit_vulns), 1) if crit_vulns else 100.0),
        "kev_open_count": float(sum(1 for f in act if f.kev)),
        "phishing_click_rate_pct": _kpi(ctl, "email", "phishing_click_rate_pct"),
        "mttr_critical_days": _kpi(ctl, "vmdr", "mttr_critical_days"),
        "mttd_hours": _kpi(ctl, "soc", "mttd_hours"),
        "toxic_combinations_open": float(len(correlations)),
        "brand_takedown_hours": _kpi(ctl, "brand", "brand_takedown_hours"),
        "internet_facing_critical_count": float(len(internet_crit)),
        "cloud_critical_misconfig_count": float(sum(1 for f in act if f.domain == Domain.CLOUD
                                                   and f.severity == Severity.CRITICAL
                                                   and f.finding_type == FindingType.MISCONFIGURATION)),
        "waf_block_mode_pct": _kpi(ctl, "waf", "block_mode_pct"),
        "ot_unmanaged_remote_access_count": _kpi(ctl, "ot", "unmanaged_remote_access"),
        "backup_immutability_pct": _kpi(ctl, "backup", "immutable_pct"),
        "fraud_detection_rate_pct": _kpi(ctl, "fraud", "detection_rate_pct"),
        "fraud_alert_backlog_hours": _kpi(ctl, "fraud", "alert_backlog_hours"),
        "fraud_channel_coverage_pct": _kpi(ctl, "fraud", "channel_coverage_pct"),
        "fraud_confirmed_loss_30d": _kpi(ctl, "fraud", "confirmed_loss_30d"),
        "bounty_high_open_past_sla": float(sum(1 for f in act if f.domain == Domain.BUG_BOUNTY
                                               and f.severity in (Severity.CRITICAL, Severity.HIGH)
                                               and (f.evidence.get("sla_breaches") or (f.due_date and f.due_date.replace(tzinfo=f.due_date.tzinfo or timezone.utc) < now)))),
        "sector_targeted_vulns_open": float(sum(1 for f in act if f.domain == Domain.THREAT_INTEL
                                                and "sector_targeted" in f.evidence.get("tags", []) and f.evidence.get("matched_cves"))),
        "intel_ioc_sightings_open": float(sum(1 for f in act if f.domain == Domain.THREAT_INTEL and "sighted" in f.evidence.get("tags", []))),
        "shadow_ai_users": _kpi(ctl, "web_proxy", "shadow_ai_users", _kpi(ctl, "ai_security", "unsanctioned_ai_apps")),
    }
    return {key: round(float(v), 2) for key, v in k.items() if v is not None}


def kri_status(value: float | None, appetite: float, direction: str) -> str:
    """within | near | breach - 'near' is within 10% of appetite on the wrong side."""
    if value is None:
        return "no_data"
    if direction == "higher_better":
        if value >= appetite:
            return "within"
        return "near" if value >= appetite * 0.95 else "breach"
    if value <= appetite:
        return "within"
    tolerance = max(appetite * 0.25, 1)
    return "near" if value <= appetite + tolerance else "breach"


def kri_table(kris: dict[str, float], vertical: VerticalProfile) -> list[dict[str, Any]]:
    rows = []
    for k in vertical.kris:
        v = kris.get(k["metric"])
        rows.append({**k, "value": v, "status": kri_status(v, float(k["appetite"]), k["direction"])})
    return rows


def posture_score(kris: dict[str, float], controls: list[ControlHealth], findings: list[Finding],
                  correlations: list[Correlation], vertical: VerticalProfile) -> float:
    """0-100. 45% control effectiveness, 40% KRI attainment vs appetite, 15% acute exposure."""
    eff = [c.effectiveness for c in controls if c.effectiveness]
    ctl_part = sum(eff) / len(eff) if eff else 50.0
    rows = [r for r in kri_table(kris, vertical) if r["metric"] != "posture_score" and r["status"] != "no_data"]
    pts = {"within": 1.0, "near": 0.6, "breach": 0.15}
    kri_part = 100 * sum(pts[r["status"]] for r in rows) / len(rows) if rows else 50.0
    p1 = sum(1 for f in active(findings) if f.horizon == Horizon.TODAY)
    acute = max(0.0, 100 - min(60.0, p1 * 1.5) - min(40.0, len(correlations) * 3.0))
    return round(0.45 * ctl_part + 0.40 * kri_part + 0.15 * acute, 1)


def build_snapshot(date: str, findings: list[Finding], controls: list[ControlHealth],
                   correlations: list[Correlation], kris: dict[str, float], posture: float,
                   now: datetime, new_since: datetime | None = None) -> DailySnapshot:
    act = active(findings)
    by_h = Counter(f.horizon.value for f in act if f.horizon)
    by_s = Counter(f.severity.value for f in act)
    by_d = Counter(f.domain.value for f in act)
    breaches = sum(1 for f in act if f.due_date and f.due_date.replace(tzinfo=f.due_date.tzinfo or timezone.utc) < now)
    new = sum(1 for f in act if new_since and f.first_seen.replace(tzinfo=f.first_seen.tzinfo or timezone.utc) >= new_since)
    closed = sum(1 for f in findings if f.status not in ACTIVE)
    soc = next((c for c in controls if c.domain == Domain.SOC), None)
    return DailySnapshot(
        date=date, posture_score=posture,
        open_by_horizon={h.value: by_h.get(h.value, 0) for h in Horizon},
        open_by_severity={s.value: by_s.get(s.value, 0) for s in Severity},
        open_by_domain=dict(sorted(by_d.items())),
        sla_breaches=breaches, new_findings=new, closed_findings=closed,
        mttr_days={"critical": kris.get("mttr_critical_days", 0.0)},
        mttd_hours=kris.get("mttd_hours", 0.0),
        control_effectiveness={c.domain.value: c.effectiveness for c in controls},
        kris=kris, incidents=int(soc.kpis.get("incidents_open", 0)) if soc else 0,
    )
