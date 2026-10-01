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
    sync_mode = "incremental"
    supported_domains = tuple(SOURCES)

    def fetch(self, ctx) -> AdapterResult:
        self.require("tenant_id", "client_id", "client_secret")
        # incremental: first run = alerts created in the lookback window; afterwards = anything UPDATED since
        # the cursor, so status changes (resolved / in progress) flow back and nothing silently "disappears"
        src_filter = " or ".join(f"serviceSource eq '{s}'" for s in SOURCES[self.domain])
        if self.cursor:
            flt = f"({src_filter}) and lastUpdateDateTime ge {self.cursor}"
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=int(self.settings.get("lookback_days", 14))))
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
                    device_ids, ips, iocs = [], [], []
                    for ev in a.get("evidence", []):
                        t = ev.get("@odata.type", "")
                        if t.endswith("deviceEvidence"):
                            host = host or ev.get("deviceDnsName") or ev.get("hostName")
                            if ev.get("mdeDeviceId"):
                                device_ids.append(f"mde:{ev['mdeDeviceId']}")
                            if ev.get("azureAdDeviceId"):
                                device_ids.append(f"entra:{ev['azureAdDeviceId']}")
                        elif t.endswith("userEvidence") and not user:
                            acct = ev.get("userAccount") or {}
                            user = acct.get("userPrincipalName") or acct.get("accountName")
                        elif t.endswith("ipEvidence") and ev.get("ipAddress"):
                            ips.append(ev["ipAddress"])
                        elif t.endswith("urlEvidence") and ev.get("url"):
                            iocs.append(ev["url"])
                    last = _dt(a.get("lastUpdateDateTime"))
                    newest = max(newest, last) if newest else last
                    findings.append(Finding(
                        finding_id=f"{self.domain.value}-msg-{a['id']}", domain=self.domain,
                        source=a.get("serviceSource", self.product), finding_type=FindingType.DETECTION,
                        title=a.get("title", "Alert"), description=a.get("description", "") or "",
                        severity=SEV.get(a.get("severity", "unknown"), Severity.MEDIUM),
                        status=Status.FALSE_POSITIVE if a.get("classification") == "falsePositive"
                        else STATUS.get(a.get("status", "new"), Status.OPEN),
                        asset_id=host, user_id=user, first_seen=_dt(a.get("createdDateTime")), last_seen=last,
                        evidence={"category": a.get("category"), "mitre": a.get("mitreTechniques", []),
                                  "incident_id": a.get("incidentId"), "url": a.get("alertWebUrl"),
                                  "device_ids": device_ids, "ips": ips, "iocs": iocs[:20]},
                        remediation=a.get("recommendedActions", "") or "",
                    ))
                url, params = data.get("@odata.nextLink"), None
        # a successful incremental query IS fresh data, even when nothing changed
        health = ControlHealth(domain=self.domain, product=self.product or "Microsoft Defender XDR",
                               coverage_pct=float(self.settings.get("coverage_pct") or 100.0),
                               data_freshness_hours=0.0,
                               health_issues=[] if self.settings.get("coverage_pct") else ["Coverage not reported - set settings.coverage_pct from the console"])
        cursor = newest.strftime("%Y-%m-%dT%H:%M:%SZ") if newest else self.cursor
        return AdapterResult(findings=findings, health=health, cursor=cursor)
