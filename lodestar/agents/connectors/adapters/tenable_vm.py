"""Tenable Vulnerability Management (tenable.io) export API.

Required: API keys of a user with 'Basic' + Can View on the relevant assets.
settings: access_key, secret_key (env refs), severities (default [critical, high]),
          base_url (default https://cloud.tenable.com), max_wait_seconds (600)
Incremental: the first run exports every OPEN/REOPENED vulnerability. Later runs export only
what changed since the previous export (filters.since) INCLUDING state FIXED, so remediated
vulnerabilities are closed in LODESTAR on the next run. The cursor is the export start time.
Docs: https://developer.tenable.com/reference/exports-vulns-request-export
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from ....models import ControlHealth, Domain, Finding, FindingType, Severity, Status
from .base import Adapter, AdapterResult, http_client, request_with_retry

SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
       "low": Severity.LOW, "info": Severity.INFO}


class TenableVmAdapter(Adapter):
    name = "tenable_vm"
    sync_mode = "incremental"
    supported_domains = (Domain.VMDR,)

    def fetch(self, ctx) -> AdapterResult:
        self.require("access_key", "secret_key")
        base = self.settings.get("base_url", "https://cloud.tenable.com").rstrip("/")
        headers = {"X-ApiKeys": f"accessKey={self.settings['access_key']};secretKey={self.settings['secret_key']}"}
        started = int(time.time())
        filters = {"severity": self.settings.get("severities", ["critical", "high"]), "state": ["OPEN", "REOPENED"]}
        if self.cursor:
            filters.update({"since": int(float(self.cursor)), "state": ["OPEN", "REOPENED", "FIXED"]})
        body = {"num_assets": 500, "filters": filters}
        findings, warnings = [], []
        with http_client(timeout=60) as c:
            uuid = request_with_retry(c, "POST", f"{base}/vulns/export", json=body, headers=headers).json()["export_uuid"]
            deadline = time.time() + int(self.settings.get("max_wait_seconds", 600))
            done, status = set(), {}
            while time.time() < deadline:
                status = request_with_retry(c, "GET", f"{base}/vulns/export/{uuid}/status", headers=headers).json()
                for chunk in status.get("chunks_available", []):
                    if chunk in done:
                        continue
                    for v in request_with_retry(c, "GET", f"{base}/vulns/export/{uuid}/chunks/{chunk}",
                                                headers=headers).json():
                        findings.append(self._map(v))
                    done.add(chunk)
                if status.get("status") in ("FINISHED", "CANCELLED", "ERROR"):
                    break
                time.sleep(10)
            else:
                warnings.append("Tenable export did not finish within max_wait_seconds; partial data used")
        health = ControlHealth(domain=Domain.VMDR, product="Tenable Vulnerability Management",
                               coverage_pct=float(self.settings.get("coverage_pct") or 100.0), data_freshness_hours=0.0,
                               health_issues=[] if self.settings.get("coverage_pct") else ["Coverage not reported - set settings.coverage_pct from the console"])
        complete = status.get("status") == "FINISHED"
        return AdapterResult(findings=findings, health=health, warnings=warnings,
                             cursor=str(started) if complete else self.cursor)

    def _map(self, v: dict) -> Finding:
        asset, plugin = v.get("asset", {}), v.get("plugin", {})
        cves = plugin.get("cve") or []
        first = v.get("first_found")
        when = datetime.fromisoformat(first.replace("Z", "+00:00")) if first else datetime.now(timezone.utc)
        epss = plugin.get("epss_score")
        return Finding(
            finding_id=f"vmdr-ten-{asset.get('uuid', '')[:12]}-{plugin.get('id')}", domain=Domain.VMDR,
            source="tenable_vm", finding_type=FindingType.VULNERABILITY, title=plugin.get("name", "Vulnerability"),
            severity=SEV.get(v.get("severity", "medium"), Severity.MEDIUM),
            asset_id=asset.get("fqdn") or asset.get("hostname") or asset.get("ipv4") or asset.get("uuid"),
            cve=cves[0] if cves else None, first_seen=when,
            epss=float(epss) / 100 if epss and float(epss) > 1 else float(epss or 0),
            evidence={"vpr": plugin.get("vpr", {}).get("score"), "cvss3": plugin.get("cvss3_base_score"),
                      "port": (v.get("port") or {}).get("port"), "ips": [asset["ipv4"]] if asset.get("ipv4") else [],
                      "device_ids": [f"tenable:{asset['uuid']}"] if asset.get("uuid") else [],
                      "mac": asset.get("mac_address")},
            remediation=plugin.get("solution", "") or "",
            status=Status.RESOLVED if str(v.get("state", "")).upper() == "FIXED" else Status.OPEN,
            last_seen=_dt(v.get("last_fixed") or v.get("last_found")) or when,
        )


def _dt(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None
