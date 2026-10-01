"""LODESTAR common data model.

Every connector agent, whatever the vendor, emits objects from this module.
This is the contract that lets the core agents (correlation, prioritisation,
reporting) stay vendor- and vertical-agnostic.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Domain(str, Enum):
    """Security control domains LODESTAR integrates with."""

    EDR = "edr"
    FIREWALL = "firewall"
    VMDR = "vmdr"
    IDENTITY = "identity"
    PAM = "pam"
    CLOUD = "cloud"
    ZTNA = "ztna"
    WEB_PROXY = "web_proxy"
    SOC = "soc"
    SAST = "sast"
    DAST = "dast"
    WAF = "waf"
    BRAND = "brand"
    EMAIL = "email"
    AI_SECURITY = "ai_security"
    DLP = "dlp"
    OT = "ot"
    BACKUP = "backup"
    FRAUD = "fraud"
    BUG_BOUNTY = "bug_bounty"
    THREAT_INTEL = "threat_intel"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.2,
    Severity.INFO: 0.05,
}


class Exposure(str, Enum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"


EXPOSURE_WEIGHT = {
    Exposure.INTERNET: 1.0,
    Exposure.PARTNER: 0.65,
    Exposure.INTERNAL: 0.35,
    Exposure.ISOLATED: 0.1,
}


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    DETECTION = "detection"          # alert / threat activity
    MISCONFIGURATION = "misconfiguration"
    COVERAGE_GAP = "coverage_gap"    # control not deployed / agent missing
    POLICY_VIOLATION = "policy_violation"
    EXPOSURE = "exposure"            # brand / leaked credential / public asset
    INCIDENT = "incident"


class Status(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RISK_ACCEPTED = "risk_accepted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Horizon(str, Enum):
    """When the CISO / tech lead should act."""

    TODAY = "today"        # P1
    THIS_WEEK = "week"     # P2
    THIS_MONTH = "month"   # P3
    BACKLOG = "backlog"    # P4 - track only


class Asset(BaseModel):
    asset_id: str
    name: str
    asset_type: str = "server"            # server, workstation, app, cloud_account, domain, user, ot_device, model
    business_service: Optional[str] = None
    owner: Optional[str] = None
    criticality: int = Field(3, ge=1, le=5)  # 5 = crown jewel
    exposure: Exposure = Exposure.INTERNAL
    tags: list[str] = Field(default_factory=list)          # e.g. vendor:siemens, product:s7-1500, sector:energy
    aliases: list[str] = Field(default_factory=list)       # hostnames, FQDNs, URLs, *.wildcards used by tools and reports
    ips: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    external_ids: list[str] = Field(default_factory=list)  # e.g. EDR device ids, cloud resource ids / ARNs
    data_classification: str = "internal"   # public, internal, confidential, restricted


class Finding(BaseModel):
    """A normalised security signal from any control."""

    finding_id: str
    domain: Domain
    source: str                         # vendor/product e.g. "crowdstrike_falcon"
    finding_type: FindingType
    title: str
    description: str = ""
    severity: Severity
    status: Status = Status.OPEN
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    app_id: Optional[str] = None
    entity_keys: list[str] = Field(default_factory=list)  # extra correlation keys
    cve: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    due_date: Optional[datetime] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    # enrichment (filled by core agents)
    kev: bool = False
    epss: float = 0.0
    actively_exploited_in_env: bool = False
    compensating_controls: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    # prioritisation output
    score: float = 0.0
    horizon: Optional[Horizon] = None
    score_factors: dict[str, float] = Field(default_factory=dict)
    why: list[str] = Field(default_factory=list)
    owner_team: Optional[str] = None
    tlp: Optional[str] = None           # clear | green | amber | amber+strict | red (from intel sources)


def safe_title(f: "Finding") -> str:
    """Title safe to send outside the dashboard (chat, e-mail, reports): TLP:RED content never leaves."""
    return "[TLP:RED item - open the dashboard]" if (f.tlp or "").lower() == "red" else f.title


class ControlHealth(BaseModel):
    """Is the control itself deployed, fresh and effective?"""

    domain: Domain
    product: str
    coverage_pct: float = Field(ge=0, le=100)          # assets/users protected vs in scope
    data_freshness_hours: float = 0.0
    policy_drift_items: int = 0
    health_issues: list[str] = Field(default_factory=list)
    kpis: dict[str, Any] = Field(default_factory=dict)
    effectiveness: float = 0.0                         # 0-100, computed
    status: str = "unknown"                            # healthy, degraded, failing, stale


class Correlation(BaseModel):
    """A 'toxic combination' - multiple signals that together form an attack path."""

    correlation_id: str
    rule_id: str
    title: str
    narrative: str
    severity: Severity
    finding_ids: list[str]
    domains: list[Domain]
    entity: str
    recommended_action: str
    score: float = 0.0
    mitre: list[str] = Field(default_factory=list)


class DailySnapshot(BaseModel):
    """Aggregated metrics captured each pipeline run - feeds trends and reports."""

    date: str
    posture_score: float
    open_by_horizon: dict[str, int]
    open_by_severity: dict[str, int]
    open_by_domain: dict[str, int]
    sla_breaches: int
    new_findings: int
    closed_findings: int
    mttr_days: dict[str, float] = Field(default_factory=dict)
    mttd_hours: float = 0.0
    control_effectiveness: dict[str, float] = Field(default_factory=dict)
    kris: dict[str, float] = Field(default_factory=dict)
    incidents: int = 0
    kri_sources: dict[str, str] = Field(default_factory=dict)   # metric -> connector:<domain> | lodestar:* | manual: ...
    kri_coverage_pct: Optional[float] = None                    # share of the profile's KRIs actually measured
    kri_missing: list[str] = Field(default_factory=list)
    posture_provisional: bool = False                           # too little measured data to trust the score


class PipelineResult(BaseModel):
    org_name: str
    vertical: str
    generated_at: datetime = Field(default_factory=utcnow)
    findings: list[Finding]
    controls: list[ControlHealth]
    correlations: list[Correlation]
    snapshot: DailySnapshot
    history: list[DailySnapshot] = Field(default_factory=list)
    data_quality: dict[str, Any] = Field(default_factory=dict)
    compliance: dict[str, Any] = Field(default_factory=dict)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    asset_names: dict[str, str] = Field(default_factory=dict)
