"""Microsoft Graph Security API (alerts_v2) - one integration covering
Defender for Endpoint, Identity, Office 365, Cloud Apps, Cloud and Sentinel.

Required (application, read-only): SecurityAlert.Read.All
settings: tenant_id, client_id, client_secret (env refs), lookback_days (default 14)
Docs: https://learn.microsoft.com/graph/api/security-list-alerts_v2
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ....models import ControlHealth, Domain, Finding, FindingType, Severity, Status
from .base import Adapter, AdapterResult, http_client, request_with_retry

GRAPH = "https://graph.microsoft.com/v1.0"
SOURCES = {
    Domain.EDR: ["microsoftDefenderForEndpoint"],
    Domain.IDENTITY: ["microsoftDefenderForIdentity", "azureAdIdentityProtection"],
    Domain.EMAIL: ["microsoftDefenderForOffice365"],
    Domain.CLOUD: ["microsoftDefenderForCloud"],
    Domain.SOC: ["microsoftSentinel", "microsoft365Defender"],
    Domain.WEB_PROXY: ["microsoftDefenderForCloudApps"],
}
SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
       "informational": Severity.INFO, "unknown": Severity.MEDIUM}
STATUS = {"new": Status.OPEN, "inProgress": Status.IN_PROGRESS, "resolved": Status.RESOLVED}


def get_token(client, tenant_id: str, client_id: str, client_secret: str,
              scope: str = "https://graph.microsoft.com/.default") -> str:
    r = request_with_retry(client, "POST", f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                           data={"grant_type": "client_credentials", "client_id": client_id,
                                 "client_secret": client_secret, "scope": scope})
    return r.json()["access_token"]


def _dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else datetime.now(timezone.utc)


class MsGraphSecurityAdapter(Adapter):
    name = "ms_graph_security"
    supported_domains = tuple(SOURCES)

    def fetch(self, ctx) -> AdapterResult:
        self.require("tenant_id", "client_id", "client_secret")
        since = (datetime.now(timezone.utc) - timedelta(days=int(self.settings.get("lookback_days", 14))))
        src_filter = " or ".join(f"serviceSource eq '{s}'" for s in SOURCES[self.domain])
        flt = f"({src_filter}) and createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        findings: list[Finding] = []
        with http_client() as c:
            token = get_token(c, self.settings["tenant_id"], self.settings["client_id"], self.settings["client_secret"])
            url, params = f"{GRAPH}/security/alerts_v2", {"$filter": flt, "$top": 500}
            newest = None
            while url:
                data = request_with_retry(c, "GET", url, params=params,
                                          headers={"Authorization": f"Bearer {token}"}).json()
                for a in data.get("value", []):
                    host = user = None
                    for ev in a.get("evidence", []):
                        t = ev.get("@odata.type", "")
                        if t.endswith("deviceEvidence") and not host:
                            host = ev.get("deviceDnsName") or ev.get("mdeDeviceId")
                        if t.endswith("userEvidence") and not user:
                            user = (ev.get("userAccount") or {}).get("userPrincipalName")
                    last = _dt(a.get("lastUpdateDateTime"))
                    newest = max(newest, last) if newest else last
                    findings.append(Finding(
                        finding_id=f"{self.domain.value}-msg-{a['id']}", domain=self.domain,
                        source=a.get("serviceSource", self.product), finding_type=FindingType.DETECTION,
                        title=a.get("title", "Alert"), description=a.get("description", "") or "",
                        severity=SEV.get(a.get("severity", "unknown"), Severity.MEDIUM),
                        status=STATUS.get(a.get("status", "new"), Status.OPEN),
                        asset_id=host, user_id=user, first_seen=_dt(a.get("createdDateTime")), last_seen=last,
                        evidence={"category": a.get("category"), "mitre": a.get("mitreTechniques", []),
                                  "incident_id": a.get("incidentId"), "url": a.get("alertWebUrl")},
                        remediation=a.get("recommendedActions", "") or "",
                    ))
                url, params = data.get("@odata.nextLink"), None
        fresh = (datetime.now(timezone.utc) - newest).total_seconds() / 3600 if newest else 0.0
        health = ControlHealth(domain=self.domain, product=self.product or "Microsoft Defender XDR",
                               coverage_pct=float(self.settings.get("coverage_pct", 0)),
                               data_freshness_hours=round(fresh, 1))
        return AdapterResult(findings=findings, health=health)
