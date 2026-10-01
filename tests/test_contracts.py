"""Contract tests: native and SIEM adapters against RECORDED vendor responses (httpx.MockTransport).

They pin the request each adapter sends (endpoint, filter, auth) and the mapping of a realistic
response, so a refactor cannot silently break an integration. Response shapes follow the vendors'
published API documentation; validate against your own tenant with `lodestar test-connector`.
"""
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from lodestar.agents.connectors.adapters import build_adapter
from lodestar.agents.connectors.adapters.base import set_transport
from lodestar.agents.core.hunt import ThreatHuntAgent, classify
from lodestar.models import Domain, Severity, Status

TOKEN = {"token_type": "Bearer", "expires_in": 3599, "access_token": "eyJ0eXAi.test"}
AAD = {"tenant_id": "00000000-0000-0000-0000-000000000001", "client_id": "app", "client_secret": "s3cret"}


@pytest.fixture
def mock_http():
    calls = []

    def install(handler):
        def wrapped(req: httpx.Request):
            calls.append(req)
            return handler(req)
        set_transport(httpx.MockTransport(wrapped))
        return calls
    yield install
    set_transport(None)


def test_graph_alerts_v2_incremental_and_evidence(mock_http):
    alert = {
        "id": "da637", "title": "Suspicious PowerShell download", "severity": "high", "status": "new",
        "classification": None, "serviceSource": "microsoftDefenderForEndpoint", "category": "Execution",
        "createdDateTime": "2026-09-29T08:00:00Z", "lastUpdateDateTime": "2026-09-30T10:15:00Z",
        "firstActivityDateTime": "2026-09-29T07:58:00Z", "incidentId": "42", "alertWebUrl": "https://security.microsoft.com/alerts/da637",
        "mitreTechniques": ["T1059.001"],
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "ws-0142.corp.example",
             "mdeDeviceId": "a1b2c3", "azureAdDeviceId": "e-77"},
            {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"userPrincipalName": "j.doe@corp.example"}},
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.50"},
            {"@odata.type": "#microsoft.graph.security.urlEvidence", "url": "http://bad.example/payload.ps1"},
        ]}

    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            assert parse_qs(req.content.decode())["scope"] == ["https://graph.microsoft.com/.default"]
            return httpx.Response(200, json=TOKEN)
        assert req.url.path == "/v1.0/security/alerts_v2"
        assert "lastUpdateDateTime ge 2026-09-28T00:00:00Z" in req.url.params["$filter"]
        assert req.headers["Authorization"] == "Bearer eyJ0eXAi.test"
        return httpx.Response(200, json={"value": [alert]})

    calls = mock_http(handler)
    ad = build_adapter("ms_graph_security", Domain.EDR, "Microsoft Defender for Endpoint", AAD)
    ad.cursor = "2026-09-28T00:00:00Z"
    r = ad.fetch(None)
    assert len(calls) == 2
    f = r.findings[0]
    assert f.severity == Severity.HIGH and f.asset_id == "ws-0142.corp.example" and f.user_id == "j.doe@corp.example"
    assert f.evidence["device_ids"] == ["mde:a1b2c3", "entra:e-77"] and f.evidence["ips"] == ["203.0.113.50"]
    assert r.cursor == "2026-09-30T10:15:00Z"
    assert r.health.data_freshness_hours == 0.0


def test_graph_first_run_uses_created_window(mock_http):
    seen = {}

    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json=TOKEN)
        seen["filter"] = req.url.params["$filter"]
        return httpx.Response(200, json={"value": []})

    mock_http(handler)
    ad = build_adapter("ms_graph_security", Domain.IDENTITY, "Defender for Identity", AAD)
    r = ad.fetch(None)
    assert "createdDateTime ge" in seen["filter"] and r.findings == [] and r.cursor is None


def test_sentinel_query_maps_rows_and_advances_cursor(mock_http):
    la = {"tables": [{"name": "PrimaryResult",
                      "columns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "AlertName", "type": "string"},
                                  {"name": "AlertSeverity", "type": "string"}, {"name": "CompromisedEntity", "type": "string"},
                                  {"name": "SystemAlertId", "type": "string"}, {"name": "Status", "type": "string"}],
                      "rows": [["2026-09-30T09:00:00Z", "Malware blocked", "High", "srv-db-01", "a-1", "New"],
                               ["2026-09-30T11:30:00Z", "Ransomware behaviour", "High", "ws-0142", "a-2", "Resolved"]]}]}
    health = {"tables": [{"columns": [{"name": "coverage_pct"}, {"name": "sensors_unhealthy"}], "rows": [[96.4, 3]]}]}

    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            assert parse_qs(req.content.decode())["scope"] == ["https://api.loganalytics.io/.default"]
            return httpx.Response(200, json=TOKEN)
        assert req.url.path == "/v1/workspaces/ws-123/query"
        body = json.loads(req.content)
        if "Heartbeat" in body["query"]:
            return httpx.Response(200, json=health)
        assert "TimeGenerated > datetime(2026-09-29T00:00:00Z)" in body["query"]
        return httpx.Response(200, json=la)

    mock_http(handler)
    s = {**AAD, "workspace_id": "ws-123",
         "query": "SecurityAlert | where TimeGenerated > datetime({since}) | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, SystemAlertId, Status",
         "health_query": "Heartbeat | summarize coverage_pct=96.4, sensors_unhealthy=3",
         "field_map": {"title": "AlertName", "severity": "AlertSeverity", "asset_id": "CompromisedEntity",
                       "finding_id": "SystemAlertId", "first_seen": "TimeGenerated", "status": "Status"}}
    ad = build_adapter("sentinel", Domain.EDR, "Defender via Sentinel", s)
    assert ad.sync_mode == "incremental"
    ad.cursor = "2026-09-29T00:00:00Z"
    r = ad.fetch(None)
    assert [f.status for f in r.findings] == [Status.OPEN, Status.RESOLVED]
    assert r.findings[0].finding_id == "edr-a-1" and r.findings[0].asset_id == "srv-db-01"
    assert r.cursor.startswith("2026-09-30T11:30:00")
    assert r.health.coverage_pct == 96.4 and r.health.kpis["sensors_unhealthy"] == 3


def test_sentinel_error_raises(mock_http):
    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json=TOKEN)
        return httpx.Response(200, json={"error": {"message": "Failed to resolve table 'Foo'"}})

    mock_http(handler)
    ad = build_adapter("sentinel", Domain.EDR, "x", {**AAD, "workspace_id": "w", "query": "Foo"})
    with pytest.raises(RuntimeError, match="Foo"):
        ad.fetch(None)


def test_splunk_export_ndjson(mock_http):
    ndjson = "\n".join(json.dumps(x) for x in [
        {"preview": False, "offset": 0, "result": {"_time": "1759230000", "signature": "Cobalt Strike beacon",
                                                   "severity": "critical", "dest": "srv-app-07", "id": "nb-9"}},
        {"preview": False, "offset": 1, "result": {"_time": "1759233600", "signature": "Port scan",
                                                   "severity": "low", "dest": "fw-edge-01", "id": "nb-10"}},
        {"preview": False, "lastrow": True}])

    def handler(req):
        assert req.url.path == "/services/search/jobs/export"
        form = parse_qs(req.content.decode())
        assert form["search"][0].startswith("search index=ids _time>1759000000")
        assert form["output_mode"] == ["json"] and req.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, text=ndjson)

    mock_http(handler)
    ad = build_adapter("splunk", Domain.FIREWALL, "Palo Alto via Splunk", {
        "base_url": "https://splunk.example:8089", "token": "tok", "search": "index=ids _time>{since_epoch}",
        "field_map": {"title": "signature", "asset_id": "dest", "finding_id": "id", "first_seen": "_time"},
        "health": {"coverage_pct": 90}})
    ad.cursor = "1759000000"
    r = ad.fetch(None)
    assert [f.severity for f in r.findings] == [Severity.CRITICAL, Severity.LOW]
    assert r.cursor == "1759233600.0" and r.health.coverage_pct == 90


def test_tenable_incremental_closes_fixed(mock_http):
    body_seen = {}
    chunk = [
        {"asset": {"uuid": "11111111-aaaa", "hostname": "srv-db-01", "fqdn": "srv-db-01.corp.example", "ipv4": "10.0.4.11"},
         "plugin": {"id": 190001, "name": "OpenSSH regreSSHion", "cve": ["CVE-2024-6387"], "epss_score": 0.93,
                    "vpr": {"score": 9.0}, "cvss3_base_score": 8.1, "solution": "Upgrade OpenSSH"},
         "severity": "critical", "state": "OPEN", "first_found": "2026-08-01T00:00:00Z", "last_found": "2026-09-30T00:00:00Z",
         "port": {"port": 22}},
        {"asset": {"uuid": "22222222-bbbb", "hostname": "ws-0142"},
         "plugin": {"id": 180002, "name": "Chrome < 129", "cve": ["CVE-2026-0001"]},
         "severity": "high", "state": "FIXED", "first_found": "2026-09-01T00:00:00Z", "last_fixed": "2026-09-29T00:00:00Z"}]

    def handler(req):
        if req.method == "POST" and req.url.path == "/vulns/export":
            body_seen.update(json.loads(req.content))
            assert "accessKey=ak;secretKey=sk" in req.headers["X-ApiKeys"]
            return httpx.Response(200, json={"export_uuid": "exp-1"})
        if req.url.path == "/vulns/export/exp-1/status":
            return httpx.Response(200, json={"status": "FINISHED", "chunks_available": [1]})
        if req.url.path == "/vulns/export/exp-1/chunks/1":
            return httpx.Response(200, json=chunk)
        return httpx.Response(404)

    mock_http(handler)
    ad = build_adapter("tenable_vm", Domain.VMDR, "Tenable", {"access_key": "ak", "secret_key": "sk"})
    ad.cursor = "1759000000"
    r = ad.fetch(None)
    assert body_seen["filters"]["since"] == 1759000000 and "FIXED" in body_seen["filters"]["state"]
    open_, fixed = r.findings
    assert open_.asset_id == "srv-db-01.corp.example" and open_.cve == "CVE-2024-6387" and open_.status == Status.OPEN
    assert open_.evidence["device_ids"] == ["tenable:11111111-aaaa"] and open_.evidence["ips"] == ["10.0.4.11"]
    assert fixed.status == Status.RESOLVED
    assert int(r.cursor) >= 1759000000


def test_tenable_first_run_is_full_export(mock_http):
    body_seen = {}

    def handler(req):
        if req.method == "POST":
            body_seen.update(json.loads(req.content))
            return httpx.Response(200, json={"export_uuid": "e"})
        if req.url.path.endswith("/status"):
            return httpx.Response(200, json={"status": "FINISHED", "chunks_available": []})
        return httpx.Response(404)

    mock_http(handler)
    r = build_adapter("tenable_vm", Domain.VMDR, "Tenable", {"access_key": "a", "secret_key": "b"}).fetch(None)
    assert "since" not in body_seen["filters"] and body_seen["filters"]["state"] == ["OPEN", "REOPENED"]
    assert r.cursor is not None


def test_hackerone_reports_paginate(mock_http):
    page1 = {"data": [{"id": "2001", "type": "report", "attributes": {
        "title": "IDOR on /api/v2/accounts", "state": "triaged", "created_at": "2026-09-20T10:00:00.000Z",
        "triaged_at": "2026-09-21T10:00:00.000Z", "vulnerability_information": "Account takeover via IDOR"},
        "relationships": {"severity": {"data": {"attributes": {"rating": "critical", "score": 9.1}}},
                          "structured_scope": {"data": {"attributes": {"asset_identifier": "api.shop.example"}}}}}],
        "links": {"next": "https://api.hackerone.com/v1/reports?page[number]=2"}}
    page2 = {"data": [], "links": {}}

    def handler(req):
        assert req.headers["Authorization"].startswith("Basic ")
        return httpx.Response(200, json=page2 if "page%5Bnumber%5D=2" in str(req.url) or "page[number]=2" in str(req.url) else page1)

    calls = mock_http(handler)
    r = build_adapter("hackerone", Domain.BUG_BOUNTY, "HackerOne",
                      {"api_identifier": "id", "api_token": "tok", "program_handle": "shop"}).fetch(None)
    assert len(calls) == 2 and len(r.findings) == 1
    f = r.findings[0]
    assert f.severity == Severity.CRITICAL and f.asset_id == "api.shop.example"
    assert r.health.kpis["critical_open"] == 1


# ---------------------------------------------------------------------------- threat hunt
IOCS = {"203.0.113.50": {"kind": "ip", "severity": Severity.MEDIUM, "tlp": "amber", "title": "ISAC bulletin 12",
                         "source": "ISAC", "seen": datetime(2026, 9, 30, tzinfo=timezone.utc), "intel_id": "ti-1"},
        "bad.example": {"kind": "domain", "severity": Severity.CRITICAL, "tlp": None, "title": "Phishing kit",
                        "source": "MISP", "seen": datetime(2026, 9, 30, tzinfo=timezone.utc), "intel_id": "ti-2"}}


def test_ioc_classification():
    assert classify("203.0.113.9") == "ip" and classify("10.1.2.3") is None
    assert classify("bad.example") == "domain" and classify("https://bad.example/x") == "domain"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"
    assert classify("not an ioc") is None


def test_hunt_query_builders_escape_and_include_iocs():
    kql = ThreatHuntAgent.build_kql({**IOCS, 'x".example': {"kind": "domain"}}, 24)
    assert '"203.0.113.50"' in kql and '"bad.example"' in kql and 'x".example' not in kql and "ago(24h)" in kql
    spl = ThreatHuntAgent.build_spl(IOCS, 12)
    assert 'dest_ip IN ("203.0.113.50")' in spl and "earliest=-12h" in spl and "url=*bad.example*" in spl


def test_hunt_rows_become_sightings():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    rows = [{"Host": "ws-0142", "User": "j.doe@corp.example", "Indicator": "https://cdn.bad.example/a.js",
             "Source": "DeviceNetworkEvents", "FirstSeen": "2026-09-30T08:00:00Z", "LastSeen": "2026-09-30T09:00:00Z", "Hits": 4},
            {"Host": "fw-edge-01", "User": "", "Indicator": ["203.0.113.50", "198.51.100.1"], "Source": "pan:traffic", "Hits": "2"},
            {"Host": "ws-9", "User": "", "Indicator": "unrelated.example", "Source": "DnsEvents", "Hits": 1}]
    out = ThreatHuntAgent.to_findings(rows, IOCS, now)
    assert len(out) == 2
    dom = next(f for f in out if f.evidence["ioc"] == "bad.example")
    assert dom.severity == Severity.CRITICAL and dom.asset_id == "ws-0142" and dom.evidence["_src"] == "hunt"
    ip = next(f for f in out if f.evidence["ioc"] == "203.0.113.50")
    assert ip.severity == Severity.HIGH and ip.tlp == "amber" and ip.evidence["hits"] == 2
    # stable id -> re-hunting the same sighting updates, never duplicates
    assert ThreatHuntAgent.to_findings(rows, IOCS, now)[0].finding_id == out[0].finding_id


def test_hunt_end_to_end_marks_intel_sighted(tmp_path, mock_http, monkeypatch):
    import yaml

    from lodestar.config import ROOT, load_settings
    from lodestar.orchestrator import Orchestrator
    drop = tmp_path / "ti"
    drop.mkdir()
    (drop / "feed.csv").write_text("title,severity,ioc,first_seen\n"
                                   "C2 infrastructure for ransomware crew,high,203.0.113.50,2026-09-30T00:00:00Z\n")
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw.update({"mode": "live", "deployment_phase": 2, "storage": {"sqlite_path": str(tmp_path / "h.db")}, "assets": {"path": None},
                "connectors": {"threat_intel": {"enabled": True, "adapter": "file_drop", "product": "ISAC CSV",
                                                "settings": {"path": str(drop), "finding_type": "exposure",
                                                             "health": {"coverage_pct": 100}}}},
                "threat_hunt": {"enabled": True, "provider": "sentinel", "ioc_max_age_days": 3650,
                                "settings": {**AAD, "client_secret": "${HUNT_TEST_SECRET}", "workspace_id": "w"}}})
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("HUNT_TEST_SECRET", "s3cret")
    rows = {"tables": [{"columns": [{"name": n} for n in ("Host", "User", "Indicator", "Source", "FirstSeen", "LastSeen", "Hits")],
                        "rows": [["ws-0142", "", "203.0.113.50", "DeviceNetworkEvents", "2026-09-30T08:00:00Z", "2026-09-30T08:05:00Z", 3]]}]}

    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json=TOKEN)
        assert '"203.0.113.50"' in json.loads(req.content)["query"]
        return httpx.Response(200, json=rows)

    mock_http(handler)
    res = Orchestrator(load_settings(p)).run()
    hunt = [f for f in res.findings if f.evidence.get("_src") == "hunt"]
    intel = [f for f in res.findings if f.domain == Domain.THREAT_INTEL]
    assert len(hunt) == 1 and hunt[0].asset_id == "ws-0142"
    assert intel and "sighted" in intel[0].evidence["tags"]
    assert res.data_quality["hunt"]["hits"] == 1

    # SIEM down on the next run: the sighting is carried forward, not resolved
    mock_http(lambda req: httpx.Response(503))
    from lodestar.agents.connectors.adapters import base
    monkeypatch.setattr(base.time, "sleep", lambda s: None)
    res2 = Orchestrator(load_settings(p)).run(force=True)
    assert res2.data_quality["sources"]["hunt"]["status"] == "failed"
    assert any(f.evidence.get("_src") == "hunt" for f in res2.findings)
