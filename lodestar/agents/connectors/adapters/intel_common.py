"""Shared parsing for threat-intelligence sources (STIX 2.1, MISP, CSAF, e-mail).

Every source is reduced to the same advisory shape, then emitted as a
`threat_intel` Finding. Relevance filtering (does this touch OUR assets,
OUR sector or OUR telemetry?) happens later in ThreatIntelAgent, so all
sources are judged by one rule set.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from ....models import Domain, Finding, FindingType, Severity

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TLP_RE = re.compile(r"TLP\s*[:\-]\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+(?:\[\.\]|\.))+(?:[a-z]{2,24})\b", re.I)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SEV_WORDS = [("critical", Severity.CRITICAL), ("high", Severity.HIGH), ("important", Severity.HIGH),
             ("medium", Severity.MEDIUM), ("moderate", Severity.MEDIUM), ("low", Severity.LOW)]
# domains that are never IOCs (avoid flagging the advisory publisher's own links)
BENIGN_DOMAINS = {"cisa.gov", "www.cisa.gov", "nvd.nist.gov", "cve.org", "www.cve.org", "first.org", "mitre.org",
                  "attack.mitre.org", "github.com", "microsoft.com", "hackerone.com"}


def refang(s: str) -> str:
    return s.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http").replace("[:]", ":")


def tlp_of(text: str) -> str | None:
    m = TLP_RE.search(text or "")
    if not m:
        return None
    v = m.group(1).lower()
    return "clear" if v in ("white", "clear") else v


def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    return Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM if score >= 4 else Severity.LOW


def severity_from_text(text: str) -> Severity:
    low = (text or "").lower()
    for w, s in SEV_WORDS:
        if w in low:
            return s
    return Severity.MEDIUM


def extract_iocs(text: str) -> list[str]:
    t = refang(text or "")
    out = set(IPV4_RE.findall(t)) | {h.lower() for h in SHA256_RE.findall(t)}
    for d in DOMAIN_RE.findall(t):
        d = d.lower().strip(".")
        if d in BENIGN_DOMAINS or d.endswith((".gov", ".mil")) or "." not in d:
            continue
        out.add(d)
    return sorted(out)[:200]


def norm_product(vendor: str | None, product: str | None) -> list[str]:
    tags = []
    if vendor:
        tags.append("vendor:" + re.sub(r"\s+", "-", vendor.strip().lower()))
    if product:
        tags.append("product:" + re.sub(r"\s+", "-", product.strip().lower()))
    return tags


def advisory_finding(*, source: str, source_kind: str, title: str, severity: Severity, published: datetime | None,
                     cves: Iterable[str] = (), products: Iterable[str] = (), sectors: Iterable[str] = (),
                     iocs: Iterable[str] = (), exploited: bool = False, tlp: str | None = None, url: str | None = None,
                     advisory_id: str | None = None, remediation: str = "", description: str = "") -> Finding:
    cves = sorted({c.upper() for c in cves})
    key = advisory_id or hashlib.sha1(f"{source}|{title}|{','.join(cves)}".encode()).hexdigest()[:14]
    when = published or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    tags = ["advisory"] + (["exploited"] if exploited else [])
    return Finding(
        finding_id=f"ti-{hashlib.sha1(key.encode()).hexdigest()[:12]}", domain=Domain.THREAT_INTEL, source=source,
        finding_type=FindingType.EXPOSURE, title=title[:300], description=description[:2000], severity=severity,
        cve=cves[0] if cves else None, first_seen=when, last_seen=when, tlp=tlp, remediation=remediation[:1000],
        evidence={"tags": tags, "cves": cves, "products": sorted(set(products)), "sectors": sorted({s.lower() for s in sectors}),
                  "iocs": sorted(set(iocs)), "source_kind": source_kind, "advisory_id": advisory_id, "url": url},
    )


def parse_dt(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
