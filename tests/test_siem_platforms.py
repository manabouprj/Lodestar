"""Contract tests for the SIEM platforms beyond Sentinel and Splunk: IBM QRadar, Elastic / OpenSearch / Wazuh,
Sumo Logic, Google SecOps and the generic REST adapter, plus their threat hunts and `lodestar init`.

Responses follow each vendor's published API documentation; validate against your own tenant with
`lodestar test-connector <domain>` in the first week."""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from lodestar.agents.connectors.adapters import build_adapter
from lodestar.agents.connectors.adapters.base import set_transport
from lodestar.agents.core.hunt import ThreatHuntAgent
from lodestar.models import Domain, Severity, Status


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


# ------------------------------------------------------------------ QRadar
def test_qradar_aql_search_polls_and_maps(mock_http):
    polls = {"n": 0}

    def handler(req):
        assert req.headers["SEC"] == "qr-token"
        if req.method == "POST" and req.url.path == "/api/ariel/searches":
            aql = parse_qs(urlparse(str(req.url)).query)["query_expression"][0]
            assert "starttime > " in aql and "{since_ms}" not in aql
            return httpx.Response(201, json={"search_id": "s-1", "status": "WAIT"})
        if req.url.path == "/api/ariel/searches/s-1":
            polls["n"] += 1
            return httpx.Response(200, json={"search_id": "s-1", "status": "EXECUTE" if polls["n"] == 1 else "COMPLETED"})
        if req.url.path == "/api/ariel/searches/s-1/results":
            assert req.headers["Range"] == "items=0-9999"
            return httpx.Response(200, json={"events": [
                {"starttime": 1759399200000, "detection": "Mimikatz credential theft", "severity": 9, "sourceip": "10.1.2.3",
                 "username": "j.doe", "logsource": "CrowdStrike @ fs-01"}]})
        raise AssertionError(str(req.url))
    calls = mock_http(handler)
    ad = build_adapter("qradar", Domain.EDR, "EDR via QRadar", {
        "base_url": "https://qradar.example", "token": "qr-token", "poll_seconds": 0,
        "aql": "SELECT * FROM events WHERE starttime > {since_ms} LAST {lookback_days} DAYS",
        "field_map": {"title": "detection", "severity": "severity", "asset_id": "sourceip", "user_id": "username",
                      "first_seen": "starttime"}})
    assert ad.sync_mode == "incremental"
    res = ad.fetch(None)
    f = res.findings[0]
    assert (f.title, f.severity, f.asset_id, f.user_id) == ("Mimikatz credential theft", Severity.CRITICAL, "10.1.2.3", "j.doe")
    assert res.cursor.startswith("2025-10-02") and polls["n"] == 2 and len(calls) == 4


def test_qradar_failed_search_raises(mock_http):
    def handler(req):
        if req.method == "POST":
            return httpx.Response(201, json={"search_id": "s-2", "status": "WAIT"})
        return httpx.Response(200, json={"status": "ERROR", "error_messages": [{"message": "AQL parse error"}]})
    mock_http(handler)
    ad = build_adapter("qradar", Domain.EDR, "x", {"base_url": "https://q.example", "token": "t", "aql": "bad", "poll_seconds": 0})
    with pytest.raises(RuntimeError, match="ERROR"):
        ad.fetch(None)


def test_qradar_open_offenses_snapshot(mock_http):
    def handler(req):
        assert req.url.path == "/api/siem/offenses" and req.headers["Range"] == "items=0-9999"
        assert parse_qs(urlparse(str(req.url)).query)["filter"] == ['status="OPEN"']
        return httpx.Response(200, json=[{"id": 42, "description": "Multiple login failures followed by success",
                                          "magnitude": 8, "status": "OPEN", "offense_source": "fs-01",
                                          "start_time": 1759399200000, "last_updated_time": 1759402800000,
                                          "categories": ["Authentication", "Brute Force"]}])
    mock_http(handler)
    ad = build_adapter("qradar", Domain.SOC, "IBM QRadar offenses", {
        "base_url": "https://qradar.example", "token": "t", "mode": "offenses", "finding_type": "incident",
        "field_map": {"finding_id": "id", "title": "description", "severity": "magnitude", "asset_id": "offense_source",
                      "status": "status", "first_seen": "start_time", "last_seen": "last_updated_time"}})
    assert ad.sync_mode == "snapshot"
    f = ad.fetch(None).findings[0]
    assert (f.finding_id, f.severity, f.status, f.asset_id) == ("soc-42", Severity.HIGH, Status.OPEN, "fs-01")


# ------------------------------------------------------------------ Elastic / OpenSearch / Wazuh
def test_elastic_esql_with_api_key(mock_http):
    def handler(req):
        assert req.url.path == "/_query" and req.headers["Authorization"] == "ApiKey ZW5jb2RlZA=="
        q = json.loads(req.content)["query"]
        assert "{since}" not in q and "@timestamp >" in q
        return httpx.Response(200, json={"columns": [{"name": "rule.name", "type": "keyword"},
                                                     {"name": "destination.ip", "type": "ip"},
                                                     {"name": "last_seen", "type": "date"}],
                                         "values": [["ET EXPLOIT Log4j", "10.9.0.5", "2026-10-02T09:00:00.000Z"]]})
    mock_http(handler)
    ad = build_adapter("elastic", Domain.FIREWALL, "NGFW via Elastic", {
        "base_url": "https://es.example:9200", "api_key": "ZW5jb2RlZA==", "cursor_column": "last_seen",
        "esql": 'FROM logs-* | WHERE @timestamp > "{since}" | LIMIT 10',
        "field_map": {"title": "rule.name", "asset_id": "destination.ip", "first_seen": "last_seen"}, "severity_map": {"medium": "high"}})
    res = ad.fetch(None)
    assert res.findings[0].title == "ET EXPLOIT Log4j" and res.cursor.startswith("2026-10-02T09:00")


def test_elastic_security_alerts_dsl_snapshot_and_basic_auth(mock_http):
    def handler(req):
        assert req.url.path == "/.alerts-security.alerts-*/_search"
        assert req.headers["Authorization"].startswith("Basic ")
        body = json.loads(req.content)
        assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-7d"
        return httpx.Response(200, json={"hits": {"hits": [{"_id": "a1", "_index": ".internal.alerts-security.alerts-default-000001",
            "_source": {"@timestamp": "2026-10-02T08:00:00Z", "host": {"name": "ws-0142"}, "user": {"name": "j.doe"},
                        "kibana": {"alert": {"uuid": "u-1", "rule": {"name": "Encoded PowerShell"}, "severity": "high",
                                             "workflow_status": "acknowledged"}}}}]}})
    mock_http(handler)
    ad = build_adapter("elastic", Domain.SOC, "Elastic Security alerts", {
        "base_url": "https://kibana-es.example:9200", "username": "lodestar", "password": "pw", "index": ".alerts-security.alerts-*",
        "dsl": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-{lookback_days}d"}}}]}},
        "status_map": {"acknowledged": "in_progress"}, "finding_type": "incident",
        "field_map": {"finding_id": "kibana.alert.uuid", "title": "kibana.alert.rule.name", "severity": "kibana.alert.severity",
                      "asset_id": "host.name", "user_id": "user.name", "status": "kibana.alert.workflow_status", "first_seen": "@timestamp"}})
    assert ad.sync_mode == "snapshot"
    f = ad.fetch(None).findings[0]
    assert (f.finding_id, f.title, f.status, f.asset_id) == ("soc-u-1", "Encoded PowerShell", Status.IN_PROGRESS, "ws-0142")


def test_elastic_requires_credentials():
    ad = build_adapter("elastic", Domain.SOC, "x", {"base_url": "https://es.example", "index": "i"})
    with pytest.raises(ValueError, match="api_key"):
        ad.headers()


# ------------------------------------------------------------------ Sumo Logic
def test_sumologic_search_job_lifecycle(mock_http):
    state = {"polls": 0, "deleted": False}

    def handler(req):
        assert req.headers["Authorization"].startswith("Basic ")
        p = req.url.path
        if req.method == "POST" and p == "/api/v1/search/jobs":
            body = json.loads(req.content)
            assert body["timeZone"] == "UTC" and body["query"].startswith("_sourceCategory")
            return httpx.Response(202, json={"id": "J1", "link": {"rel": "self", "href": "/api/v1/search/jobs/J1"}},
                                  headers={"Set-Cookie": "AWSELB=abc; Path=/"})
        if req.method == "GET" and p == "/api/v1/search/jobs/J1":
            assert "AWSELB=abc" in req.headers.get("cookie", "")          # cookies kept for the job session
            state["polls"] += 1
            return httpx.Response(200, json={"state": "GATHERING RESULTS" if state["polls"] == 1 else "DONE GATHERING RESULTS",
                                             "messageCount": 2, "recordCount": 0})
        if p == "/api/v1/search/jobs/J1/messages":
            return httpx.Response(200, json={"fields": [], "messages": [
                {"map": {"_messagetime": "1759395600000", "threat_name": "Cobalt Strike beacon", "severity": "critical", "dest_ip": "10.4.4.4"}},
                {"map": {"_messagetime": "1759399200000", "threat_name": "SMB brute force", "severity": "high", "dest_ip": "10.4.4.5"}}]})
        if req.method == "DELETE" and p == "/api/v1/search/jobs/J1":
            state["deleted"] = True
            return httpx.Response(200, json={"id": "J1"})
        raise AssertionError(f"{req.method} {p}")
    mock_http(handler)
    ad = build_adapter("sumologic", Domain.FIREWALL, "NGFW via Sumo Logic", {
        "base_url": "https://api.eu.sumologic.com", "access_id": "id", "access_key": "key", "poll_seconds": 0,
        "query": "_sourceCategory=*firewall* threat", "field_map": {"title": "threat_name", "severity": "severity", "asset_id": "dest_ip"}})
    res = ad.fetch(None)
    assert [f.severity for f in res.findings] == [Severity.CRITICAL, Severity.HIGH]
    assert state["deleted"] and res.cursor.startswith("2025-10-02T10:00:00")


# ------------------------------------------------------------------ Google SecOps
def test_google_secops_udm_search_with_service_account(mock_http):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    sa = {"client_email": "lodestar@proj.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "k1",
          "token_uri": "https://oauth2.googleapis.com/token"}

    def handler(req):
        if req.url.host == "oauth2.googleapis.com":
            form = parse_qs(req.content.decode())
            assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"] and form["assertion"][0].count(".") == 2
            return httpx.Response(200, json={"access_token": "ya29.test", "expires_in": 3599})
        assert req.url.path == "/v1alpha/projects/p1/locations/us/instances/abc:udmSearch"
        assert req.headers["Authorization"] == "Bearer ya29.test"
        q = parse_qs(urlparse(str(req.url)).query)
        assert q["query"][0].startswith("metadata.event_type") and "timeRange.startTime" in q
        return httpx.Response(200, json={"events": [{"name": "projects/p1/.../events/e1", "udm": {
            "metadata": {"id": "e1", "eventTimestamp": "2026-10-02T07:00:00Z", "eventType": "PROCESS_LAUNCH"},
            "principal": {"hostname": "ws-0142", "user": {"userid": "j.doe"}, "ip": ["10.1.1.1"]},
            "securityResult": [{"severity": "HIGH", "summary": "Suspicious encoded PowerShell"}]}}], "moreDataAvailable": True})
    mock_http(handler)
    ad = build_adapter("google_secops", Domain.EDR, "EDR via Google SecOps", {
        "base_url": "https://us-chronicle.googleapis.com", "project": "p1", "location": "us", "instance": "abc",
        "service_account_secret": json.dumps(sa), "query": 'metadata.event_type = "PROCESS_LAUNCH"',
        "field_map": {"finding_id": "metadata.id", "title": "securityResult.summary", "severity": "securityResult.severity",
                      "asset_id": "principal.hostname", "user_id": "principal.user.userid", "first_seen": "metadata.eventTimestamp"}})
    res = ad.fetch(None)
    f = res.findings[0]
    assert (f.title, f.severity, f.asset_id, f.user_id) == ("Suspicious encoded PowerShell", Severity.HIGH, "ws-0142", "j.doe")
    assert any("more events" in w for w in res.warnings) and res.cursor.startswith("2026-10-02T07:00:00.001")


# ------------------------------------------------------------------ generic REST
def test_http_json_oauth_pagination_and_cursor(mock_http):
    def handler(req):
        if req.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "AT"})
        assert req.headers["Authorization"] == "Bearer AT"
        if "page=2" in str(req.url):
            return httpx.Response(200, json={"data": [{"id": "c", "name": "Beaconing", "risk": 72, "entity": {"host": "db-01"},
                                                       "created": "2026-10-02T06:00:00Z"}], "links": {}})
        assert "since" in parse_qs(urlparse(str(req.url)).query)
        return httpx.Response(200, json={"data": [{"id": "a", "name": "Impossible travel", "risk": 91, "entity": {"host": "vpn"},
                                                   "created": "2026-10-02T05:00:00Z"}],
                                         "links": {"next": "https://siem.example/api/alerts?page=2"}})
    mock_http(handler)
    ad = build_adapter("http_json", Domain.SOC, "Exabeam via REST", {
        "url": "https://siem.example/api/alerts", "params": {"since": "{since}"}, "records": "data",
        "auth": {"type": "oauth2", "endpoint": "https://siem.example/oauth/token", "client_id": "c", "client_secret": "s"},
        "paginate": {"type": "next_field", "path": "links.next"}, "cursor_column": "created",
        "field_map": {"finding_id": "id", "title": "name", "severity": "risk", "asset_id": "entity.host", "first_seen": "created"}})
    res = ad.fetch(None)
    assert [(f.severity, f.asset_id) for f in res.findings] == [(Severity.CRITICAL, "vpn"), (Severity.HIGH, "db-01")]
    assert res.cursor.startswith("2026-10-02T06:00")


# ------------------------------------------------------------------ threat hunts
IOCS = {"203.0.113.9": {"kind": "ip"}, "evil.example": {"kind": "domain"}, "a" * 64: {"kind": "hash"}}


def test_hunt_builders_for_qradar_and_elastic():
    aql = ThreatHuntAgent.build_aql(IOCS, 24, domain_property="URL", hash_property="SHA256 Hash")
    assert "sourceip = '203.0.113.9'" in aql and "destinationip = '203.0.113.9'" in aql
    assert "\"URL\" = 'evil.example'" in aql and "LAST 24 HOURS" in aql
    assert "1 = 0" in ThreatHuntAgent.build_aql({}, 24)
    q = ThreatHuntAgent.build_es_query(IOCS, 12)
    fields = {list(t["terms"])[0] for t in q["bool"]["should"]}
    assert {"destination.ip", "dns.question.name", "file.hash.sha256"} <= fields
    assert q["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-12h"


def test_elastic_hunt_rows_become_sightings(mock_http):
    def handler(req):
        body = json.loads(req.content)
        assert "_source" in body and req.url.path == "/logs-*/_search"
        return httpx.Response(200, json={"hits": {"hits": [
            {"_id": "1", "_source": {"@timestamp": "2026-10-02T06:00:00Z", "host": {"name": "ws-0142"}, "user": {"name": "j.doe"},
                                     "destination": {"ip": "203.0.113.9"}, "event": {"dataset": "panw.panos"}}},
            {"_id": "2", "_source": {"@timestamp": "2026-10-02T06:05:00Z", "host": {"name": "ws-0142"}, "user": {"name": "j.doe"},
                                     "dns": {"question": {"name": "evil.example"}}, "event": {"dataset": "panw.panos"}}}]}})
    mock_http(handler)
    rows = ThreatHuntAgent()._query("elastic", {"base_url": "https://es.example", "api_key": "k", "index": "logs-*"}, IOCS, 24, None)
    assert len(rows) == 1 and rows[0]["Host"] == "ws-0142" and rows[0]["Hits"] == 2
    assert set(rows[0]["Indicator"]) == {"203.0.113.9", "evil.example"}
    iocs = {k: {**v, "severity": Severity.HIGH, "tlp": "amber", "title": "ISAC", "source": "isac",
                "seen": datetime.now(timezone.utc) - timedelta(days=1), "intel_id": "i1"} for k, v in IOCS.items()}
    findings = ThreatHuntAgent.to_findings(rows, iocs, datetime.now(timezone.utc))
    assert {f.evidence.get("ioc") for f in findings} >= {"203.0.113.9", "evil.example"}


def test_qradar_hunt_aggregates_events(mock_http):
    def handler(req):
        if req.method == "POST":
            return httpx.Response(201, json={"search_id": "h1", "status": "WAIT"})
        if req.url.path.endswith("/results"):
            return httpx.Response(200, json={"events": [
                {"starttime": 1759399200000, "sourceip": "10.1.1.7", "destinationip": "203.0.113.9", "username": "svc-backup",
                 "logsource": "PA-5200"}]})
        return httpx.Response(200, json={"status": "COMPLETED"})
    mock_http(handler)
    rows = ThreatHuntAgent()._query("qradar", {"base_url": "https://q.example", "token": "t", "poll_seconds": 0}, IOCS, 24, None)
    assert rows[0]["Host"] == "10.1.1.7" and "203.0.113.9" in rows[0]["Indicator"] and rows[0]["Source"] == "PA-5200"


# ------------------------------------------------------------------ onboarding
@pytest.mark.parametrize("siem,adapter", [("qradar", "qradar"), ("elastic", "elastic"), ("sumologic", "sumologic"),
                                          ("google_secops", "google_secops")])
def test_init_uses_the_chosen_siem(tmp_path, siem, adapter):
    import yaml

    from lodestar.onboarding import connector_for, load_catalog
    cat = load_catalog()
    domain = {"qradar": "soc", "elastic": "soc", "sumologic": "soc", "google_secops": "edr"}[siem]
    conn, kind = connector_for(domain, siem, cat)
    assert kind == siem and conn["adapter"] == adapter
    assert all(str(v).startswith("${") for k, v in conn["settings"].items() if k in ("token", "api_key", "access_key",
                                                                                     "service_account_secret"))
    assert "note" not in conn["settings"] and "permission" not in conn["settings"]
    yaml.safe_dump(conn)
