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


# Which connector domain a findings-derived KRI depends on. A count of zero from a tool that is not
# integrated is "not measured", never "within appetite".
# Any one of the listed domains must be integrated for the KRI to count as measured.
KRI_REQUIRES: dict[str, tuple[str, ...]] = {
    "kev_open_count": ("vmdr",), "cloud_critical_misconfig_count": ("cloud",), "bounty_high_open_past_sla": ("bug_bounty",),
    "sector_targeted_vulns_open": ("threat_intel",), "intel_ioc_sightings_open": ("threat_intel",),
    "internet_facing_critical_count": ("vmdr", "cloud", "dast", "waf"),
    "toxic_combinations_open": (),          # any integrated domain, but only once correlation runs (phase >= 2)
    # measured by LODESTAR from finding history - meaningful only while the scanner is integrated
    "mttr_critical_days": ("vmdr",), "mttr_high_days": ("vmdr",), "critical_vuln_sla_pct": ("vmdr",),
}
CORRELATION_PHASE = 2

# KRI -> (connector domain, KPI keys in its health record / SIEM health_query columns, first match wins)
KRI_CONNECTOR: dict[str, tuple[str, tuple[str, ...]]] = {
    "edr_coverage_pct": ("edr", ("coverage_pct",)),
    "mfa_coverage_pct": ("identity", ("mfa_coverage_pct", "coverage_pct")),
    "priv_accounts_vaulted_pct": ("pam", ("vaulted_pct", "coverage_pct")),
    "critical_vuln_sla_pct": ("vmdr", ("critical_sla_pct",)),
    "phishing_click_rate_pct": ("email", ("phishing_click_rate_pct",)),
    "mttr_critical_days": ("vmdr", ("mttr_critical_days",)),
    "mttd_hours": ("soc", ("mttd_hours",)),
    "brand_takedown_hours": ("brand", ("brand_takedown_hours",)),
    "waf_block_mode_pct": ("waf", ("block_mode_pct",)),
    "ot_unmanaged_remote_access_count": ("ot", ("unmanaged_remote_access",)),
    "backup_immutability_pct": ("backup", ("immutable_pct",)),
    "fraud_detection_rate_pct": ("fraud", ("detection_rate_pct",)),
    "fraud_alert_backlog_hours": ("fraud", ("alert_backlog_hours",)),
    "fraud_channel_coverage_pct": ("fraud", ("channel_coverage_pct",)),
    "fraud_confirmed_loss_30d": ("fraud", ("confirmed_loss_30d",)),
    "shadow_ai_users": ("web_proxy", ("shadow_ai_users",)),
}


def lifecycle_kpis(stats: list[dict[str, Any]], findings: list[Finding], now: datetime,
                   min_samples: int = 3) -> dict[str, float]:
    """KPIs LODESTAR measures itself from finding history (needs a few weeks of runs to be meaningful).
    mttr_critical_days     mean days first-seen -> resolved, critical vulnerabilities closed in the window
    critical_vuln_sla_pct  closed-within-SLA + open-not-yet-overdue, over all critical vulnerabilities in the window
    mttr_high_days         same for high"""
    out: dict[str, float] = {}

    def _utc(d):
        return d.replace(tzinfo=d.tzinfo or timezone.utc) if d else None
    for sev, key in (("critical", "mttr_critical_days"), ("high", "mttr_high_days")):
        closed = [r for r in stats if r["severity"] == sev and r["domain"] == "vmdr" and r["first_seen"] and r["resolved_at"]]
        if len(closed) >= min_samples:
            out[key] = round(sum((_utc(r["resolved_at"]) - _utc(r["first_seen"])).total_seconds() for r in closed)
                             / len(closed) / 86400, 1)
    closed_c = [r for r in stats if r["severity"] == "critical" and r["domain"] == "vmdr"]
    open_c = [f for f in active(findings) if f.domain == Domain.VMDR and f.severity == Severity.CRITICAL]
    if len(closed_c) + len(open_c) >= min_samples and closed_c:
        ok = sum(1 for r in closed_c if not r["due_date"] or _utc(r["resolved_at"]) <= _utc(r["due_date"]))
        ok += sum(1 for f in open_c if not f.due_date or _utc(f.due_date) >= now)
        out["critical_vuln_sla_pct"] = round(100 * ok / (len(closed_c) + len(open_c)), 1)
    return out


def manual_kpis(cfg: dict[str, Any] | None, now: datetime) -> tuple[dict[str, float], dict[str, str], list[str]]:
    """Manually supplied KPIs (e.g. phishing click rate from the awareness platform's quarterly report).
    kpis_manual:
      phishing_click_rate_pct: {value: 4.2, as_of: 2026-09-01, max_age_days: 100, source: "Awareness Q3 report"}
    Returns (values, provenance, stale_metric_names). Stale values are NOT used."""
    vals, prov, stale = {}, {}, []
    for metric, spec in (cfg or {}).items():
        if not isinstance(spec, dict) or spec.get("value") is None:
            continue
        as_of = spec.get("as_of")
        try:
            d = datetime.fromisoformat(str(as_of)) if as_of else None
        except ValueError:
            d = None
        if d is None:
            stale.append(metric)
            continue
        d = d.replace(tzinfo=d.tzinfo or timezone.utc)
        if (now - d).days > int(spec.get("max_age_days", 100)):
            stale.append(metric)
            continue
        vals[metric] = float(spec["value"])
        prov[metric] = f"manual: {spec.get('source', 'config')} ({d.date().isoformat()})"
    return vals, prov, stale


def compute_kris(findings: list[Finding], controls: list[ControlHealth], correlations: list[Correlation],
                 assets: dict, now: datetime, computed: dict[str, float] | None = None,
                 manual: dict[str, float] | None = None, manual_sources: dict[str, str] | None = None,
                 provenance: dict[str, str] | None = None, phase: int = 4) -> dict[str, float]:
    """KRI values with honest provenance. Precedence per metric:
    1. the control's own KPI (connector / SIEM health query)  -> "connector:<domain>"
    2. LODESTAR lifecycle measurement (history of runs)        -> "lodestar:lifecycle"
    3. a findings-derived count, only if its source domain is integrated -> "lodestar:findings"
    4. a fresh manual value from config                        -> "manual: ..."
    otherwise the KRI is NOT MEASURED (absent) - it never defaults to a value that looks good."""
    ctl = {c.domain.value: c for c in controls}
    integrated = set(ctl)
    act = active(findings)
    computed, manual, manual_sources = computed or {}, manual or {}, manual_sources or {}
    prov: dict[str, str] = {}

    def from_ctl(domain: str, *keys: str):
        c = ctl.get(domain)
        if not c:
            return None
        for key in keys:
            if key == "coverage_pct":
                if "Coverage not reported" not in " ".join(c.health_issues):
                    return c.coverage_pct
                continue
            if c.kpis.get(key) is not None:
                return c.kpis[key]
        return None

    k: dict[str, Any] = {}
    for metric, (domain, keys) in KRI_CONNECTOR.items():
        v = from_ctl(domain, *keys)
        if v is None and metric == "shadow_ai_users":
            v, domain = from_ctl("ai_security", "unsanctioned_ai_apps"), "ai_security"
        if v is not None:
            k[metric], prov[metric] = v, f"connector:{domain}"
    for metric, v in computed.items():
        need = KRI_REQUIRES.get(metric, ())
        if metric not in k and (not need or integrated & set(need)):
            k[metric], prov[metric] = v, "lodestar:lifecycle"

    derived = {
        "kev_open_count": lambda: sum(1 for f in act if f.kev),
        "toxic_combinations_open": lambda: len(correlations),
        "internet_facing_critical_count": lambda: sum(
            1 for f in act if f.severity == Severity.CRITICAL and f.asset_id in assets
            and assets[f.asset_id].exposure == Exposure.INTERNET),
        "cloud_critical_misconfig_count": lambda: sum(
            1 for f in act if f.domain == Domain.CLOUD and f.severity == Severity.CRITICAL
            and f.finding_type == FindingType.MISCONFIGURATION),
        "bounty_high_open_past_sla": lambda: sum(
            1 for f in act if f.domain == Domain.BUG_BOUNTY and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and (f.evidence.get("sla_breaches") or (f.due_date and f.due_date.replace(tzinfo=f.due_date.tzinfo or timezone.utc) < now))),
        "sector_targeted_vulns_open": lambda: sum(
            1 for f in act if f.domain == Domain.THREAT_INTEL and "sector_targeted" in f.evidence.get("tags", [])
            and f.evidence.get("matched_cves")),
        "intel_ioc_sightings_open": lambda: sum(
            1 for f in act if f.domain == Domain.THREAT_INTEL and "sighted" in f.evidence.get("tags", [])),
    }
    for metric, fn in derived.items():
        need = KRI_REQUIRES.get(metric, ())
        if metric in k or not integrated or (need and not integrated & set(need)):
            continue
        if metric == "toxic_combinations_open" and phase < CORRELATION_PHASE:
            continue
        k[metric], prov[metric] = fn(), "lodestar:findings"
    for metric, v in manual.items():
        if metric not in k:
            k[metric], prov[metric] = v, manual_sources.get(metric, "manual")
    if provenance is not None:
        provenance.update({m: p for m, p in prov.items() if k.get(m) is not None})
    return {key: round(float(v), 2) for key, v in k.items() if v is not None}


def kri_coverage(kris: dict[str, float], vertical: VerticalProfile) -> tuple[float, list[str]]:
    """% of the industry profile's KRIs that are actually measured, and the list that is not."""
    wanted = [k["metric"] for k in vertical.kris if k["metric"] != "posture_score"]
    missing = [m for m in wanted if m not in kris]
    return (round(100 * (len(wanted) - len(missing)) / len(wanted), 1) if wanted else 100.0), missing


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


def kri_table(kris: dict[str, float], vertical: VerticalProfile,
              sources: dict[str, str] | None = None) -> list[dict[str, Any]]:
    rows = []
    for k in vertical.kris:
        v = kris.get(k["metric"])
        rows.append({**k, "value": v, "status": kri_status(v, float(k["appetite"]), k["direction"]),
                     "source": (sources or {}).get(k["metric"]) or ("not measured" if v is None else None)})
    return rows


def posture_score(kris: dict[str, float], controls: list[ControlHealth], findings: list[Finding],
                  correlations: list[Correlation], vertical: VerticalProfile) -> float:
    """0-100. 45% control effectiveness, 40% KRI attainment vs appetite, 15% acute exposure."""
    eff = [c.effectiveness for c in controls if c.effectiveness]
    ctl_part = sum(eff) / len(eff) if eff else 50.0
    rows = [r for r in kri_table(kris, vertical) if r["metric"] != "posture_score" and r["status"] != "no_data"]
    pts = {"within": 1.0, "near": 0.6, "breach": 0.15}
    # unmeasured KRIs count as "near" (0.6), not as "within": missing data must never raise the score
    total = [r for r in kri_table(kris, vertical) if r["metric"] != "posture_score"]
    unmeasured = len(total) - len(rows)
    kri_part = 100 * (sum(pts[r["status"]] for r in rows) + 0.6 * unmeasured) / len(total) if total else 50.0
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
