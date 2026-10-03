"""LODESTAR MCP server (in-process and over HTTP) and the vendor MCP client adapter."""
import asyncio
from typing import Any

import pytest
from fastapi.testclient import TestClient

from lodestar.api.auth import Principal
from lodestar.mcp_server import Hub, build_server


@pytest.fixture
def store(tmp_path, banking_result):
    from lodestar.store import Store
    st = Store(tmp_path / "m.db")
    res = banking_result.model_copy(deep=True)
    res.findings[0].tlp = "red"
    st.save_result(res)
    return st


def _call(srv, tool, args=None):
    from mcp import Client

    async def go():
        async with Client(srv) as c:
            names = [t.name for t in (await c.list_tools()).tools]
            r = await c.call_tool(tool, args or {})
            return names, r
    return asyncio.run(go())


def test_tools_are_read_only_and_scoped(store, banking_result):
    srv = build_server(Hub(lambda: store, default_principal=Principal("t", "analyst")))
    from mcp import Client

    async def tools():
        async with Client(srv) as c:
            return (await c.list_tools()).tools
    ts = asyncio.run(tools())
    assert len(ts) >= 12 and all(t.annotations and t.annotations.read_only_hint and not t.annotations.destructive_hint for t in ts)

    _, r = _call(srv, "get_overview")
    ov = r.structured_content
    assert not r.is_error and ov["posture_score"] == banking_result.snapshot.posture_score
    assert ov["org"] == "sandline-bank-demo" and "ingestion" in ov

    _, r = _call(srv, "get_priorities", {"horizon": "today", "limit": 5})
    items = r.structured_content["items"]
    assert 0 < len(items) <= 5 and items == sorted(items, key=lambda x: -x["score"])

    red = banking_result.findings[0].finding_id
    _, r = _call(srv, "get_finding", {"finding_id": red})
    f = r.structured_content["finding"]
    assert f["title"].startswith("[TLP:RED") and f["description"] == "" and f["evidence"] == {}

    _, r = _call(srv, "get_ingestion_health")
    assert r.structured_content["sources"]

    _, r = _call(srv, "get_overview", {"org": "someone-else"})
    assert r.is_error and "not permitted" in r.content[0].text


def test_roles_and_org_scoping(store):
    exec_srv = build_server(Hub(lambda: store, default_principal=Principal("e", "exec")))
    _, r = _call(exec_srv, "get_priorities")
    assert r.is_error and "requires role 'analyst'" in r.content[0].text
    _, r = _call(exec_srv, "list_decisions")
    assert not r.is_error

    other = build_server(Hub(lambda: store, default_principal=Principal("o", "ciso", orgs={"another-bank"})))
    _, r = _call(other, "list_organisations")
    assert r.structured_content["organisations"] == []

    analyst = build_server(Hub(lambda: store, lambda k: None, default_principal=Principal("a", "analyst")))
    _, r = _call(analyst, "check_ingestion")
    assert r.is_error and "ciso" in r.content[0].text


def test_mcp_over_http_requires_auth(client):
    from lodestar.api import app as appmod
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}}
    with TestClient(appmod.app) as c:
        assert c.post("/mcp/", json=body, headers=h).status_code == 401
        assert c.post("/mcp/", json=body, headers={**h, "Authorization": "Bearer wrong-key-wrong-key"}).status_code == 401
        r = c.post("/mcp/", json=body, headers={**h, "Authorization": "Bearer " + "e" * 32})
        assert r.status_code == 200
        assert r.json()["result"]["structuredContent"]["role"] == "exec"
        r = c.post("/mcp/", json={**body, "params": {"name": "get_priorities", "arguments": {}}},
                   headers={**h, "X-API-Key": "e" * 32})
        assert r.json()["result"]["isError"] is True


# ------------------------------------------------------------------ vendor MCP server -> mcp adapter
def _vendor(destructive=False, annotated=True):
    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations
    v = MCPServer("vendor")
    ann = ToolAnnotations(read_only_hint=not destructive, destructive_hint=destructive) if annotated else None

    @v.tool(annotations=ann, structured_output=True)
    def list_alerts(since: str, status: str = "open") -> dict[str, Any]:
        """Alerts since a time."""
        return {"alerts": [{"id": "A-1", "title": "Credential dumping", "severity": "critical", "device": {"name": "srv-1"},
                            "created_at": "2026-09-30T08:00:00Z"},
                           {"id": "A-2", "title": "Beacon to rare domain", "severity": "high", "device": {"name": "wks-9"},
                            "created_at": "2026-09-30T09:30:00Z"}], "since": since}
    return v


def _adapter(server, **extra):
    from lodestar.agents.connectors.adapters import build_adapter
    from lodestar.models import Domain
    ad = build_adapter("mcp", Domain.EDR, "Vendor EDR", {
        "url": "https://mcp.vendor.example/mcp", "tool": "list_alerts", "arguments": {"since": "{since}"},
        "records": "alerts", "cursor_column": "created_at",
        "field_map": {"finding_id": "id", "title": "title", "severity": "severity", "asset_id": "device.name",
                      "first_seen": "created_at"}, **extra})
    ad._target = lambda headers: (server, None)
    return ad


def test_mcp_adapter_maps_vendor_tool():
    ad = _adapter(_vendor())
    assert ad.sync_mode == "incremental"
    r = ad.fetch(None)
    assert [(f.finding_id, f.severity.value, f.asset_id) for f in r.findings] == [
        ("edr-A-1", "critical", "srv-1"), ("edr-A-2", "high", "wks-9")]
    assert r.cursor.startswith("2026-09-30T09:30")


def test_mcp_adapter_refuses_non_read_only_tools():
    with pytest.raises(PermissionError):
        _adapter(_vendor(destructive=True)).fetch(None)
    r = _adapter(_vendor(annotated=False)).fetch(None)
    assert any("readOnlyHint" in w for w in r.warnings)
    with pytest.raises(PermissionError):
        _adapter(_vendor(annotated=False), require_read_only_annotation=True).fetch(None)
    with pytest.raises(ValueError):
        _adapter(_vendor(), tool="delete_everything").fetch(None)
