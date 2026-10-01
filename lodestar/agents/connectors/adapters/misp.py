"""MISP communities (sector ISACs, national CERT MISP instances).

settings: base_url, api_key (env ref), lookback ("7d"), verify_tls (true), tags_filter (optional, e.g. ["tlp:amber", "sector:energy"])
Docs: https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents
"""
from __future__ import annotations

from datetime import datetime, timezone

from ....models import ControlHealth, Domain, Severity
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .intel_common import advisory_finding

THREAT_LEVEL = {"1": Severity.HIGH, "2": Severity.MEDIUM, "3": Severity.LOW, "4": Severity.INFO}
IOC_TYPES = {"ip-dst", "ip-src", "domain", "hostname", "url", "sha256", "md5", "sha1"}


def parse_events(events: list[dict], source: str) -> list:
    out = []
    for wrap in events:
        e = wrap.get("Event", wrap)
        attrs = e.get("Attribute", []) + [a for o in e.get("Object", []) for a in o.get("Attribute", [])]
        tags = [t.get("name", "").lower() for t in e.get("Tag", [])]
        cves = [a["value"] for a in attrs if a.get("type") == "vulnerability"]
        iocs = [a["value"].lower() for a in attrs if a.get("type") in IOC_TYPES and a.get("to_ids", True)]
        sectors = [t.split(":", 1)[1] for t in tags if t.startswith(("sector:", "misp-galaxy:sector="))]
        sectors += [t.split("=", 1)[1].strip('"') for t in tags if t.startswith("misp-galaxy:sector=")]
        tlp = next((t.split(":", 1)[1] for t in tags if t.startswith("tlp:")), None)
        exploited = any("exploit" in t for t in tags)
        out.append(advisory_finding(
            source=source, source_kind="misp", title=e.get("info", "MISP event"), severity=THREAT_LEVEL.get(str(e.get("threat_level_id")), Severity.MEDIUM),
            published=datetime.fromtimestamp(int(e.get("timestamp", 0)), tz=timezone.utc) if e.get("timestamp") else None,
            cves=cves, sectors=sectors, iocs=iocs, exploited=exploited, tlp=tlp, advisory_id=f"misp-{e.get('uuid', e.get('id'))}"))
    return out


class MispAdapter(Adapter):
    name = "misp"
    sync_mode = "incremental"
    supported_domains = (Domain.THREAT_INTEL,)

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "api_key")
        body = {"returnFormat": "json", "last": self.settings.get("lookback", "7d"), "published": True}
        if self.settings.get("tags_filter"):
            body["tags"] = self.settings["tags_filter"]
        with http_client(90) as c:
            data = request_with_retry(c, "POST", f"{self.settings['base_url'].rstrip('/')}/events/restSearch", json=body,
                                      headers={"Authorization": self.settings["api_key"], "Accept": "application/json"}).json()
        events = data.get("response", data) if isinstance(data, dict) else data
        findings = parse_events(events, self.product or "MISP")
        return AdapterResult(findings=findings, health=ControlHealth(
            domain=Domain.THREAT_INTEL, product=self.product or "MISP", coverage_pct=100.0, data_freshness_hours=0.0,
            kpis={"events_ingested": len(events)}))
