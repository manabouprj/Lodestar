"""CSAF 2.0 advisories - CISA ICS advisories and vendor PSIRTs (Siemens, Schneider, ABB, Rockwell ...).

Critical-infrastructure focus: affected vendor/product names are turned into
`vendor:`/`product:` tags and matched to OT / IT assets carrying the same tags.
settings: urls (list of advisory JSON URLs or a provider index) or path (folder, for air-gapped import)
Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/  ·  CISA CSAF: https://github.com/cisagov/CSAF
"""
from __future__ import annotations

import json
from pathlib import Path

from ....models import ControlHealth, Domain
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .intel_common import advisory_finding, norm_product, parse_dt, severity_from_cvss


def _products(tree: dict) -> list[str]:
    out: list[str] = []

    def walk(branches, vendor=None):
        for b in branches or []:
            cat, name = b.get("category"), b.get("name")
            v = name if cat == "vendor" else vendor
            if cat == "product_name":
                out.extend(norm_product(vendor, name))
            walk(b.get("branches"), v)
    walk((tree or {}).get("branches"))
    return sorted(set(out))


def parse_csaf(doc: dict, source: str):
    d = doc.get("document", {})
    vulns = doc.get("vulnerabilities", [])
    cves = [v["cve"] for v in vulns if v.get("cve")]
    scores = [s.get("cvss_v3", {}).get("baseScore") for v in vulns for s in v.get("scores", []) if s.get("cvss_v3")]
    exploited = any("exploit" in (n.get("text", "") or "").lower() and "no known public exploit" not in (n.get("text", "") or "").lower()
                    for v in vulns for n in v.get("notes", []))
    tlp = (d.get("distribution", {}).get("tlp", {}) or {}).get("label")
    remed = "; ".join(r.get("details", "") for v in vulns for r in v.get("remediations", [])[:1])[:800]
    sectors = []
    for n in d.get("notes", []):
        if n.get("title", "").lower().startswith("critical infrastructure sectors"):
            sectors = [s.strip().lower().replace(" ", "-") for s in n.get("text", "").split(",")]
    return advisory_finding(
        source=source, source_kind="csaf", title=d.get("title", "Security advisory"),
        severity=severity_from_cvss(max([s for s in scores if s is not None], default=None)),
        published=parse_dt(d.get("tracking", {}).get("current_release_date") or d.get("tracking", {}).get("initial_release_date")),
        cves=cves, products=_products(doc.get("product_tree", {})), sectors=sectors, exploited=exploited,
        tlp=tlp.lower() if tlp else None, advisory_id=d.get("tracking", {}).get("id"), remediation=remed,
        url=next((r.get("url") for r in d.get("references", []) if r.get("category") == "self"), None))


class CsafAdapter(Adapter):
    name = "csaf"
    sync_mode = "incremental"
    supported_domains = (Domain.THREAT_INTEL,)

    def fetch(self, ctx) -> AdapterResult:
        docs, warnings = [], []
        if self.settings.get("path"):
            folder = Path(self.settings["path"])
            folder = folder if folder.is_absolute() else ctx.settings.path(folder)
            docs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))]
        else:
            with http_client(60) as c:
                for u in self.settings.get("urls", []):
                    try:
                        docs.append(request_with_retry(c, "GET", u).json())
                    except Exception as exc:
                        warnings.append(f"{u}: {exc}")
        findings = [parse_csaf(d, self.product or "CSAF advisories") for d in docs if "document" in d]
        return AdapterResult(findings=findings, warnings=warnings, health=ControlHealth(
            domain=Domain.THREAT_INTEL, product=self.product or "CSAF advisories", coverage_pct=100.0 if docs else 0.0,
            data_freshness_hours=0.0, kpis={"advisories_parsed": len(findings)}))
