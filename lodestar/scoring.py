"""LODESTAR Risk Score (LRS) - explainable, deterministic prioritisation.

    raw   = 0.30*Severity + 0.25*Exploitability + 0.20*AssetCriticality
          + 0.15*Exposure + 0.10*TimePressure                (each 0..1)
    LRS   = min(100, 100 * raw * VerticalWeight * Compensating * AttackPath)

Horizon (what to work on when):
    TODAY  : LRS >= 75 AND (severity high/critical OR KEV OR attack path OR active
             exploitation), or active exploitation on a criticality>=4 asset.
             Capped at `today_capacity` - lower-ranked non-urgent items roll to WEEK.
    WEEK   : LRS >= 55
    MONTH  : LRS >= 35
    BACKLOG: everything else (tracked, reported, not pushed to humans)

Every factor is stored on the finding (`score_factors`) together with plain
English reasons (`why`) so that analysts and auditors can see exactly why
something is on today's list. No ML black box - see docs/SCORING_MODEL.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .models import (
    EXPOSURE_WEIGHT,
    SEVERITY_WEIGHT,
    Asset,
    Exposure,
    Finding,
    FindingType,
    Horizon,
    Severity,
)
from .verticals import VerticalProfile

TYPE_BASE_EXPLOITABILITY = {
    FindingType.INCIDENT: 1.0,
    FindingType.DETECTION: 0.8,
    FindingType.EXPOSURE: 0.7,
    FindingType.POLICY_VIOLATION: 0.55,
    FindingType.COVERAGE_GAP: 0.5,
    FindingType.MISCONFIGURATION: 0.45,
    FindingType.VULNERABILITY: 0.2,
}

DOMAIN_OWNER = {
    "edr": "Endpoint Security", "firewall": "Network Security", "vmdr": "Infrastructure / Patching",
    "identity": "Identity & Access", "pam": "Identity & Access", "cloud": "Cloud Platform",
    "ztna": "Network Security", "web_proxy": "Network Security", "soc": "SOC",
    "sast": "Application Security", "dast": "Application Security", "waf": "Application Security",
    "brand": "Threat Intelligence", "email": "Messaging Security", "ai_security": "AI Governance",
    "dlp": "Data Protection", "ot": "OT Security", "backup": "Infrastructure / Resilience",
    "fraud": "Fraud Operations",
}


@dataclass
class ScoringConfig:
    w_severity: float = 0.30
    w_exploit: float = 0.25
    w_asset: float = 0.20
    w_exposure: float = 0.15
    w_time: float = 0.10
    today: float = 75.0
    week: float = 55.0
    month: float = 35.0
    compensating_dampener: float = 0.85
    attack_path_boost: float = 1.20
    vertical_weight_strength: float = 0.6   # 1.0 = full vertical multiplier, 0 = ignore vertical weights
    today_capacity: int = 25                # max non-urgent items on Today list (0 = unlimited)
    weights_sum_tolerance: float = 1e-6
    extra: dict = field(default_factory=dict)

    def validate(self) -> None:
        s = self.w_severity + self.w_exploit + self.w_asset + self.w_exposure + self.w_time
        if abs(s - 1.0) > self.weights_sum_tolerance:
            raise ValueError(f"Scoring weights must sum to 1.0 (got {s:.3f})")
        if not (self.today > self.week > self.month > 0):
            raise ValueError("Horizon thresholds must satisfy today > week > month > 0")


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def score_finding(
    f: Finding,
    asset: Optional[Asset],
    vertical: VerticalProfile,
    now: datetime,
    cfg: ScoringConfig | None = None,
) -> Finding:
    cfg = cfg or ScoringConfig()
    why: list[str] = []
    now = _as_utc(now)

    # Severity
    s = SEVERITY_WEIGHT[f.severity]

    # Exploitability
    e = max(f.epss, TYPE_BASE_EXPLOITABILITY.get(f.finding_type, 0.3))
    if f.kev:
        e = max(e, 0.95)
        why.append(f"{f.cve or 'Vulnerability'} is on the CISA Known Exploited Vulnerabilities list")
    elif f.epss >= 0.3:
        why.append(f"High exploit probability (EPSS {f.epss:.0%})")
    if f.actively_exploited_in_env:
        e = 1.0
        why.append("Active exploitation / threat activity observed in our environment")

    # Asset criticality & exposure
    crit = asset.criticality if asset else 3
    a = 0.2 + 0.8 * (crit - 1) / 4
    exposure = asset.exposure if asset else Exposure.INTERNAL
    x = EXPOSURE_WEIGHT[exposure]
    if asset and crit >= 5:
        why.append(f"Crown-jewel asset ({asset.business_service or asset.name})")
    elif asset and crit == 4:
        why.append(f"Business-critical asset ({asset.business_service or asset.name})")
    if exposure == Exposure.INTERNET:
        why.append("Internet-facing")

    # Time pressure vs vertical SLA
    sla = vertical.sla(f.severity.value)
    age_days = max(0.0, (now - _as_utc(f.first_seen)).total_seconds() / 86400)
    due = _as_utc(f.due_date) if f.due_date else None
    if due and now > due:
        t = 1.0
        why.append(f"SLA breached by {(now - due).days} day(s) ({vertical.name} SLA {sla}d for {f.severity.value})")
    else:
        t = min(1.0, age_days / sla) if sla else 0.0
        if t >= 0.75:
            why.append(f"{t:.0%} of {sla}-day SLA consumed")

    raw = cfg.w_severity * s + cfg.w_exploit * e + cfg.w_asset * a + cfg.w_exposure * x + cfg.w_time * t

    # Multipliers
    vw_raw = vertical.weight(f.domain)
    vw = round(1 + (vw_raw - 1) * cfg.vertical_weight_strength, 3)
    if vw_raw > 1.0:
        why.append(f"{f.domain.value.upper()} carries extra weight for {vertical.name} (x{vw:g})")
    comp = cfg.compensating_dampener if f.compensating_controls else 1.0
    if f.compensating_controls:
        why.append("Risk reduced by compensating control: " + ", ".join(f.compensating_controls))
    path = cfg.attack_path_boost if f.correlation_ids else 1.0
    if f.correlation_ids:
        why.append("Part of a correlated attack path (toxic combination)")

    score = round(min(100.0, 100.0 * raw * vw * comp * path), 1)

    urgent = bool(f.actively_exploited_in_env or f.kev or f.correlation_ids)
    severe = f.severity in (Severity.CRITICAL, Severity.HIGH)
    if (f.actively_exploited_in_env and crit >= 4) or (score >= cfg.today and (severe or urgent)):
        horizon = Horizon.TODAY
    elif score >= cfg.week:
        horizon = Horizon.THIS_WEEK
    elif score >= cfg.month:
        horizon = Horizon.THIS_MONTH
    else:
        horizon = Horizon.BACKLOG

    f.score = score
    f.horizon = horizon
    f.score_factors = {
        "severity": round(s, 3), "exploitability": round(e, 3), "asset_criticality": round(a, 3),
        "exposure": round(x, 3), "time_pressure": round(t, 3), "vertical_weight": vw,
        "compensating": comp, "attack_path": path,
    }
    f.why = why or ["Baseline risk from severity and asset context"]
    f.owner_team = f.owner_team or DOMAIN_OWNER.get(f.domain.value, "Security Operations")
    return f
