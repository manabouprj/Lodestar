import json
from datetime import datetime, timezone
from pathlib import Path

from lodestar.agents.connectors.adapters.csaf import parse_csaf
from lodestar.agents.connectors.adapters.hackerone import map_report
from lodestar.agents.connectors.adapters.mailbox import parse_message
from lodestar.agents.connectors.adapters.taxii import parse_bundle
from lodestar.agents.core.data_quality import norm_host
from lodestar.models import Severity, Status

FX = Path(__file__).parent / "fixtures"
RULES = [{"match": "@ncsc.example", "kind": "advisory", "source": "National CERT"}]


def test_hackerone_report_mapping_keeps_no_exploit_detail():
    r = json.loads((FX / "h1_report.json").read_text())
    f = map_report(r, now=datetime(2026, 10, 15, tzinfo=timezone.utc))
    assert f.severity == Severity.CRITICAL and f.status == Status.OPEN and f.asset_id == "api.example-bank.example"
    assert "triaged" in f.evidence["tags"] and "bounty_pending" in f.evidence["tags"]
    assert "bounty decision" in f.evidence["sla_breaches"]
    assert "vulnerability_information" not in json.dumps(f.evidence)


def test_stix_bundle_parsing_extracts_cve_ioc_sector_tlp():
    objs = json.loads((FX / "stix_bundle.json").read_text())["objects"]
    out = parse_bundle(objs, "ISAC")
    rep = next(f for f in out if "Campaign" in f.title)
    assert rep.evidence["cves"] == ["CVE-2024-21762"] and "update-sync-cdn.example" in rep.evidence["iocs"]
    assert set(rep.evidence["sectors"]) == {"energy", "utilities"} and rep.tlp == "amber" and "exploited" in rep.evidence["tags"]


def test_csaf_products_become_asset_tags():
    f = parse_csaf(json.loads((FX / "csaf.json").read_text()), "CISA")
    assert "product:nwa-controller-500" in f.evidence["products"] and f.severity == Severity.CRITICAL
    assert f.tlp == "clear" and "energy" in f.evidence["sectors"]


def test_email_advisory_is_parsed_deterministically():
    fs, outcome = parse_message((FX / "cert_advisory.eml").read_bytes(), RULES)
    f = fs[0]
    assert outcome == "ok" and f.cve == "CVE-2024-21762" and f.severity == Severity.CRITICAL and f.tlp == "amber"
    assert {"update-sync-cdn.example", "203.0.113.45"} <= set(f.evidence["iocs"])
    assert "cisa.gov" not in " ".join(f.evidence["iocs"])           # publisher links are not IOCs
    assert "exploited" in f.evidence["tags"]                         # injected text did not lower severity


def test_unverified_or_unknown_sender_handling():
    fs, _ = parse_message((FX / "spoofed.eml").read_bytes(), RULES)
    assert fs[0].severity == Severity.MEDIUM and "unverified_sender" in fs[0].evidence["tags"]
    fs2, outcome = parse_message((FX / "spoofed.eml").read_bytes(), [{"match": "@other.example"}])
    assert fs2 == [] and outcome == "ignored_sender"


def test_host_normalisation():
    assert norm_host("https://user@WWW.Online.Bank.example:443/x?y") == "online.bank.example"


def test_relevance_filter_and_intel_paths(banking_result):
    r = banking_result
    ti = [f for f in r.findings if f.domain.value == "threat_intel"]
    assert ti and all("relevant" in f.evidence["tags"] for f in ti)
    assert r.data_quality["external_refs_resolved"] >= 1
    rules = {c.rule_id for c in r.correlations}
    assert {"LDS-014", "LDS-015", "LDS-016"} <= rules
    assert any(f.evidence.get("sector_exploited") for f in r.findings)
    types = {d["type"] for d in r.decisions}
    assert {"regulatory_notification", "bounty_programme"} <= types
    shadow = [f for f in r.findings if f.domain.value == "bug_bounty" and "unknown_asset" in f.evidence.get("tags", [])]
    assert shadow and any("shadow IT" in w for w in shadow[0].why)


def test_hackerone_webhook_signature(client):
    import hashlib
    import hmac
    body = json.dumps({"data": {"report": json.loads((FX / "h1_report.json").read_text())}}).encode()
    assert client.post("/api/ingest/hackerone", content=body, headers={"X-H1-Signature": "sha256=bad"}).status_code == 401
    sig = "sha256=" + hmac.new(b"h1-secret-for-tests", body, hashlib.sha256).hexdigest()
    r = client.post("/api/ingest/hackerone", content=body, headers={"X-H1-Signature": sig, "X-H1-Event": "report_triaged"})
    assert r.status_code == 202 and r.json()["accepted"] == 1
