"""Microsoft Entra ID Protection + MFA registration coverage.

Required (application, read-only): IdentityRiskyUser.Read.All, AuditLog.Read.All
Docs: https://learn.microsoft.com/graph/api/riskyuser-list
      https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
"""
from __future__ import annotations

from datetime import datetime, timezone

from ....models import ControlHealth, Domain, Finding, FindingType, Severity
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .ms_graph_security import GRAPH, get_token

RISK = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


class EntraIdentityProtectionAdapter(Adapter):
    name = "entra_identity_protection"
    supported_domains = (Domain.IDENTITY,)

    def _paged(self, c, url, token, params=None):
        while url:
            data = request_with_retry(c, "GET", url, params=params, headers={"Authorization": f"Bearer {token}"}).json()
            yield from data.get("value", [])
            url, params = data.get("@odata.nextLink"), None

    def fetch(self, ctx) -> AdapterResult:
        self.require("tenant_id", "client_id", "client_secret")
        findings = []
        with http_client() as c:
            token = get_token(c, self.settings["tenant_id"], self.settings["client_id"], self.settings["client_secret"])
            for u in self._paged(c, f"{GRAPH}/identityProtection/riskyUsers", token,
                                 {"$filter": "riskState eq 'atRisk'"}):
                sev = RISK.get(u.get("riskLevel", ""), Severity.MEDIUM)
                ts = u.get("riskLastUpdatedDateTime")
                when = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.now(timezone.utc)
                findings.append(Finding(
                    finding_id=f"identity-risky-{u['id']}", domain=Domain.IDENTITY, source="Microsoft Entra ID Protection",
                    finding_type=FindingType.DETECTION, title=f"Risky user: {u.get('riskDetail', 'atRisk')}",
                    severity=sev, user_id=u.get("userPrincipalName"), first_seen=when, last_seen=when,
                    remediation="Confirm compromise, reset credentials, revoke sessions, enforce MFA re-registration."))
            total = mfa = 0
            for r in self._paged(c, f"{GRAPH}/reports/authenticationMethods/userRegistrationDetails", token,
                                 {"$filter": "userType eq 'member'"}):
                total += 1
                mfa += 1 if r.get("isMfaRegistered") else 0
        cov = round(100 * mfa / total, 1) if total else 0.0
        health = ControlHealth(domain=Domain.IDENTITY, product="Microsoft Entra ID", coverage_pct=cov,
                               data_freshness_hours=0.0, kpis={"mfa_coverage_pct": cov, "risky_users": len(findings)})
        return AdapterResult(findings=findings, health=health)
