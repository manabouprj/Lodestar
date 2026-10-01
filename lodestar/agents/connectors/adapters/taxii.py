"""STIX 2.1 over TAXII 2.1 (national CERTs, ISACs, commercial TI).

settings: api_root (https://taxii.example/api1/), collection_id, username/password or api_token (env refs),
          lookback_days (7), path (optional local folder of STIX bundles for offline / air-gapped import)
Spec: https://docs.oasis-open.org/cti/taxii/v2.1/  ·  https://docs.oasis-open.org/cti/stix/v2.1/
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ....models import ControlHealth, Domain, Severity
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .intel_common import CVE_RE, advisory_finding, parse_dt, severity_from_cvss, tlp_of

TLP_MARKINGS = {  # STIX 2.1 TLP marking-definition ids
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}
PATTERN_VALUE = re.compile(r"(?:ipv4-addr|ipv6-addr|domain-name|url|file:hashes\.'?SHA-256'?)[^=]*=\s*'([^']+)'", re.I)


def parse_bundle(objects: list[dict], source: str) -> list:
    by_id = {o.get("id"): o for o in objects}
    sectors_by_target: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") == "identity" and o.get("sectors"):
            sectors_by_target[o["id"]] = o["sectors"]
    targets: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "targets":
            targets.setdefault(o["source_ref"], []).extend(sectors_by_target.get(o["target_ref"], []))
    in_report = {r for o in objects if o.get("type") == "report" for r in o.get("object_refs", [])}
    out = []
    for o in objects:
        t = o.get("type")
        tlp = next((TLP_MARKINGS[m] for m in o.get("object_marking_refs", []) if m in TLP_MARKINGS), None)
        if t == "report":
            refs = [by_id.get(r, {}) for r in o.get("object_refs", [])]
            cves = {r.get("name", "") for r in refs if r.get("type") == "vulnerability"} | set(CVE_RE.findall(o.get("description", "")))
            iocs = [m for r in refs if r.get("type") == "indicator" for m in PATTERN_VALUE.findall(r.get("pattern", ""))]
            sectors = [s for r in o.get("object_refs", []) for s in targets.get(r, [])] + targets.get(o["id"], [])
            exploited = any(lbl in ("exploited", "active-exploitation") for lbl in o.get("labels", [])) or \
                "exploit" in (o.get("description", "") or "").lower()
            out.append(advisory_finding(
                source=source, source_kind="taxii", title=o.get("name", "Threat report"), description=o.get("description", ""),
                severity=Severity.HIGH if exploited else Severity.MEDIUM, published=parse_dt(o.get("published") or o.get("created")),
                cves=[c for c in cves if c], sectors=sectors, iocs=iocs, exploited=exploited,
                tlp=tlp or tlp_of(o.get("description", "")), advisory_id=o.get("id")))
        elif t == "indicator" and o["id"] not in in_report:
            vals = PATTERN_VALUE.findall(o.get("pattern", ""))
            if vals:
                out.append(advisory_finding(
                    source=source, source_kind="taxii", title=o.get("name") or f"Indicator: {vals[0]}",
                    severity=Severity.MEDIUM, published=parse_dt(o.get("valid_from") or o.get("created")), iocs=vals,
                    sectors=targets.get(o["id"], []), tlp=tlp, advisory_id=o.get("id")))
        elif t == "vulnerability" and o.get("name", "").upper().startswith("CVE-"):
            score = o.get("x_cvss_v3_base_score")
            out.append(advisory_finding(
                source=source, source_kind="taxii", title=f"{o['name']}: {o.get('description', '')[:120]}".strip(": "),
                severity=severity_from_cvss(score), published=parse_dt(o.get("created")), cves=[o["name"]],
                sectors=targets.get(o["id"], []), exploited="exploited" in o.get("labels", []), tlp=tlp, advisory_id=o.get("id")))
    return out


class TaxiiAdapter(Adapter):
    name = "taxii"
    sync_mode = "incremental"
    supported_domains = (Domain.THREAT_INTEL,)

    def fetch(self, ctx) -> AdapterResult:
        source = self.product or "TAXII feed"
        objects: list[dict] = []
        newest = None
        if self.settings.get("path"):
            folder = Path(self.settings["path"])
            folder = folder if folder.is_absolute() else ctx.settings.path(folder)
            for p in sorted(folder.glob("*.json")):
                data = json.loads(p.read_text(encoding="utf-8"))
                objects += data.get("objects", []) if isinstance(data, dict) else data
                mt = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
                newest = max(newest, mt) if newest else mt
        else:
            self.require("api_root", "collection_id")
            since = datetime.now(timezone.utc) - timedelta(days=int(self.settings.get("lookback_days", 7)))
            url = f"{self.settings['api_root'].rstrip('/')}/collections/{self.settings['collection_id']}/objects/"
            headers = {"Accept": "application/taxii+json;version=2.1"}
            auth = None
            if self.settings.get("api_token"):
                headers["Authorization"] = f"Bearer {self.settings['api_token']}"
            elif self.settings.get("username"):
                auth = (self.settings["username"], self.settings.get("password", ""))
            params = {"added_after": since.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
            with http_client(60) as c:
                for _ in range(50):  # pagination guard
                    data = request_with_retry(c, "GET", url, headers=headers, auth=auth, params=params).json()
                    objects += data.get("objects", [])
                    if not data.get("more"):
                        break
                    params["next"] = data.get("next")
            newest = datetime.now(timezone.utc)
        findings = parse_bundle(objects, source)
        fresh = (datetime.now(timezone.utc) - newest).total_seconds() / 3600 if newest else 999.0
        return AdapterResult(findings=findings, health=ControlHealth(
            domain=Domain.THREAT_INTEL, product=source, coverage_pct=100.0 if objects else 0.0,
            data_freshness_hours=round(fresh, 1), kpis={"objects_ingested": len(objects), "advisories_parsed": len(findings)}))
