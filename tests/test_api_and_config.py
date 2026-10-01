import hashlib
import hmac
import json

import pytest
import yaml
from fastapi.testclient import TestClient

from lodestar.config import ROOT, ConfigError, load_settings


def _cfg(tmp_path, mode="demo", require_auth=False, dataset=None):
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw["mode"] = mode
    raw["storage"] = {"sqlite_path": str(tmp_path / "api.db")}
    raw["security"] = {"require_auth": require_auth}
    if dataset:
        raw["demo"] = {"dataset": str(dataset)}
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml.safe_dump(raw))
    return p


@pytest.fixture
def client(tmp_path, monkeypatch, demo_dir, banking_result):
    from lodestar.api import app as appmod
    from lodestar.store import Store
    monkeypatch.setenv("LODESTAR_CONFIG", str(_cfg(tmp_path, require_auth=True, dataset=demo_dir / "banking.json")))
    monkeypatch.setenv("LODESTAR_API_KEYS", "ciso:" + "c" * 32 + ",exec:" + "e" * 32)
    monkeypatch.setenv("LODESTAR_WEBHOOK_SECRET", "s3cret-for-tests")
    monkeypatch.setenv("LODESTAR_H1_WEBHOOK_SECRET", "h1-secret-for-tests")
    appmod.get_settings.cache_clear()
    appmod.get_store.cache_clear()
    Store(tmp_path / "api.db").save_result(banking_result)
    yield TestClient(appmod.app)
    appmod.get_settings.cache_clear()
    appmod.get_store.cache_clear()


def test_literal_secret_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("org: {name: x, vertical: banking}\nconnectors:\n  edr: {settings: {client_secret: hunter2}}\n")
    with pytest.raises(ConfigError):
        load_settings(p)


def test_auth_and_rbac(client):
    assert client.get("/api/kris").status_code == 401
    assert client.get("/api/kris", headers={"X-API-Key": "e" * 32}).status_code == 200
    assert client.get("/api/priorities", headers={"X-API-Key": "e" * 32}).status_code == 403
    r = client.get("/api/priorities?horizon=today", headers={"X-API-Key": "c" * 32})
    assert r.status_code == 200 and len(r.json()) > 0


def test_dashboard_and_reports(client):
    h = {"X-API-Key": "c" * 32}
    assert "LODESTAR" in client.get("/", headers=h).text
    assert client.get("/", follow_redirects=False).status_code in (302, 307)
    assert client.get("/api/reports/quarterly?format=md", headers=h).text.startswith("#")
    assert client.get("/healthz").text == "ok"


def test_approve_is_dry_run(client):
    h = {"X-API-Key": "c" * 32}
    action = client.get("/api/dashboard", headers=h).json()["actions"][0]
    r = client.post(f"/api/actions/{action['action_id']}/approve", headers=h).json()
    assert r["submitted"] is False


def test_webhook_requires_valid_hmac(client):
    body = json.dumps([{"finding_id": "waf-1", "source": "cf", "finding_type": "detection",
                        "title": "SQLi burst", "severity": "high"}]).encode()
    assert client.post("/api/ingest/waf", content=body, headers={"X-Lodestar-Signature": "sha256=bad"}).status_code == 401
    sig = "sha256=" + hmac.new(b"s3cret-for-tests", body, hashlib.sha256).hexdigest()
    assert client.post("/api/ingest/waf", content=body, headers={"X-Lodestar-Signature": sig}).status_code == 202


def test_file_drop_adapter_maps_csv(tmp_path):
    from lodestar.agents.connectors.adapters import build_adapter
    from lodestar.models import Domain
    (tmp_path / "x.csv").write_text("rule_issue,risk,device,detected\nAny-any rule,4,fw-01,2026-09-01T00:00:00Z\n")
    ad = build_adapter("file_drop", Domain.FIREWALL, "PAN", {"path": str(tmp_path), "finding_type": "misconfiguration",
                       "field_map": {"title": "rule_issue", "severity": "risk", "asset_id": "device", "first_seen": "detected"}})

    class Ctx:
        settings = load_settings()
    res = ad.fetch(Ctx())
    assert res.findings[0].severity.value == "high" and res.findings[0].asset_id == "fw-01"


def test_chat_and_decision_api(client):
    h = {"X-API-Key": "c" * 32}
    r = client.post("/api/chat/ask", json={"text": "brief"}, headers=h).json()
    assert r["intent"] == "brief"
    dec = client.get("/api/decisions", headers=h).json()
    target = next(d for d in dec if d["type"] == "containment")
    out = client.post(f"/api/decisions/{target['decision_id']}", json={"choice": target["options"][0]}, headers=h).json()
    assert out["status"] == "approved"
    assert all(d["decision_id"] != target["decision_id"] for d in client.get("/api/decisions", headers=h).json())
    assert client.post(f"/api/decisions/{target['decision_id']}", json={"choice": "x"}, headers={"X-API-Key": "e" * 32}).status_code == 403


def test_slack_command_endpoint_requires_signature(client):
    assert client.post("/api/chat/slack/commands", content=b"text=brief").status_code == 401
    assert client.post("/api/chat/teams/messages", content=b"{}").status_code == 401
