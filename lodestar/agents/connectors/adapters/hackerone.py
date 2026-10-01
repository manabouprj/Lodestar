"""HackerOne bug bounty / VDP.

Pull: HackerOne API v1 (read-only token; basic auth identifier:token)
  GET https://api.hackerone.com/v1/reports?filter[program][]=<handle>
Push: HackerOne webhooks -> POST /api/ingest/hackerone, verified with X-H1-Signature (HMAC-SHA256).
Docs: https://api.hackerone.com/  ·  https://docs.hackerone.com/en/articles/8517658-webhooks

The vulnerability write-up (proof of concept) is deliberately NOT stored - only title,
severity, weakness, scope asset, state and the report link. Exploit detail stays in HackerOne.
settings: api_identifier, api_token (env refs), program_handle, response_targets
          {first_response_hours: 24, triage_hours: 48, bounty_days: 14}
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ....models import ControlHealth, Domain, Finding, FindingType, Severity, Status
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .intel_common import parse_dt

API = "https://api.hackerone.com/v1"
SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
       "none": Severity.INFO}
OPEN = {"new", "pending-program-review", "triaged", "needs-more-info", "retesting"}
CLOSED_FP = {"not-applicable", "informative", "duplicate", "spam"}
DEFAULT_TARGETS = {"first_response_hours": 24, "triage_hours": 48, "bounty_days": 14}


def _rel(report: dict, name: str) -> dict:
    data = ((report.get("relationships") or {}).get(name) or {}).get("data") or {}
    return data.get("attributes") or {}


def map_report(report: dict, targets: dict | None = None, now: datetime | None = None) -> Finding:
    t = {**DEFAULT_TARGETS, **(targets or {})}
    now = now or datetime.now(timezone.utc)
    a = report.get("attributes", {})
    state = a.get("state", "new")
    sev = _rel(report, "severity")
    weak = _rel(report, "weakness")
    scope = _rel(report, "structured_scope")
    created = parse_dt(a.get("created_at")) or now
    age_h = (now - created).total_seconds() / 3600
    tags = ["researcher_report"]
    breaches = []
    if state in ("new", "pending-program-review") and not a.get("first_program_activity_at") and age_h > t["first_response_hours"]:
        breaches.append("first response")
    if state in ("new", "pending-program-review") and age_h > t["triage_hours"]:
        breaches.append("triage")
    if state == "triaged":
        tags.append("triaged")
        triaged = parse_dt(a.get("triaged_at")) or created
        if not a.get("bounty_awarded_at") and (now - triaged).days > t["bounty_days"]:
            breaches.append("bounty decision")
        if not a.get("bounty_awarded_at") and sev.get("rating") in ("medium", "high", "critical"):
            tags.append("bounty_pending")
    if breaches:
        tags.append("sla_breach")
    status = Status.OPEN if state in OPEN else (Status.FALSE_POSITIVE if state in CLOSED_FP else Status.RESOLVED)
    asset = scope.get("asset_identifier")
    return Finding(
        finding_id=f"bug_bounty-h1-{report.get('id')}", domain=Domain.BUG_BOUNTY, source="HackerOne",
        finding_type=FindingType.VULNERABILITY, title=a.get("title", "Researcher report"),
        severity=SEV.get(sev.get("rating", "medium"), Severity.MEDIUM), status=status,
        asset_id=asset, app_id=asset, first_seen=created, last_seen=parse_dt(a.get("last_activity_at")) or created,
        evidence={"tags": tags, "state": state, "cvss": sev.get("score"), "weakness": weak.get("name"),
                  "cwe": weak.get("external_id"), "asset_type": scope.get("asset_type"),
                  "researcher": _rel(report, "reporter").get("username"), "sla_breaches": breaches,
                  "url": f"https://hackerone.com/reports/{report.get('id')}"},
        remediation="Validate the fix with the researcher (retest) before closing; agree bounty with the programme owner.",
    )


class HackerOneAdapter(Adapter):
    name = "hackerone"
    supported_domains = (Domain.BUG_BOUNTY,)

    def fetch(self, ctx) -> AdapterResult:
        self.require("api_identifier", "api_token", "program_handle")
        reports: list[dict[str, Any]] = []
        url = f"{API}/reports"
        params = {"filter[program][]": self.settings["program_handle"], "page[size]": 100}
        with http_client(60) as c:
            for _ in range(100):
                data = request_with_retry(c, "GET", url, params=params, headers={"Accept": "application/json"},
                                          auth=(self.settings["api_identifier"], self.settings["api_token"])).json()
                reports += data.get("data", [])
                url, params = (data.get("links") or {}).get("next"), None
                if not url:
                    break
        findings = [map_report(r, self.settings.get("response_targets")) for r in reports]
        open_ = [f for f in findings if f.status == Status.OPEN]
        return AdapterResult(findings=findings, health=ControlHealth(
            domain=Domain.BUG_BOUNTY, product="HackerOne", coverage_pct=float(self.settings.get("in_scope_internet_assets_pct", 100)),
            data_freshness_hours=0.0, kpis={
                "reports_open": len(open_), "critical_open": sum(1 for f in open_ if f.severity == Severity.CRITICAL),
                "triaged_awaiting_fix": sum(1 for f in open_ if "triaged" in f.evidence["tags"]),
                "sla_breaches": sum(1 for f in open_ if f.evidence["sla_breaches"]),
                "bounties_pending_decision": sum(1 for f in open_ if "bounty_pending" in f.evidence["tags"])}))
