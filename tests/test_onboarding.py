"""Day-one onboarding: `init` produces a config that loads, keeps secrets out of YAML and runs end to end."""
import json

import httpx

from lodestar.agents.connectors.adapters import REGISTRY
from lodestar.agents.connectors.adapters.base import set_transport
from lodestar.config import load_settings
from lodestar.onboarding import _dup_keys, connector_for, init, load_catalog

TOKEN = {"token_type": "Bearer", "expires_in": 3599, "access_token": "t"}


def test_catalog_templates_are_complete():
    cat = load_catalog()
    for domain, entry in cat.items():
        if domain.startswith("_"):
            continue
        for kind in ("sentinel", "splunk"):
            t = entry.get(kind)
            if t:
                assert t.get("field_map", {}).get("title"), f"{domain}/{kind} needs a title mapping"
                q = t.get("query") or t.get("search")
                assert q, f"{domain}/{kind} has no query"
    c, kind = connector_for("vmdr", "sentinel", cat)          # no SIEM template -> native
    assert kind == "native" and c["adapter"] == "tenable_vm"
    c, kind = connector_for("dlp", "splunk", cat)              # nothing specific -> generic file drop
    assert kind == "file_drop" and c["settings"]["path"] == "data/drop/dlp"


def test_init_generates_loadable_live_config(tmp_path, monkeypatch):
    out = init(org="Acme Bank", vertical="banking", siem="sentinel", domains=["edr", "soc", "vmdr", "threat_intel"],
               primary_domain="acme.example", root=tmp_path, out=tmp_path / "config" / "lodestar.yaml")
    cfg = tmp_path / "config" / "lodestar.yaml"
    assert not _dup_keys(cfg)
    env = (tmp_path / ".env").read_text()
    assert "LODESTAR_API_KEYS=ciso:" in env and "SENTINEL_WORKSPACE_ID=" in env and "client_secret: ${AZ_CLIENT_SECRET}" in cfg.read_text()
    assert out["templates"] == {"edr": "sentinel", "soc": "sentinel", "vmdr": "native", "threat_intel": "native"}
    # second run never overwrites existing secrets
    keys = [ln for ln in env.splitlines() if ln.startswith("LODESTAR_API_KEYS=")]
    init(org="Acme Bank", vertical="banking", siem="sentinel", domains=["edr"], primary_domain=None, root=tmp_path, out=cfg)
    assert [ln for ln in (tmp_path / ".env").read_text().splitlines() if ln.startswith("LODESTAR_API_KEYS=")] == keys
    for k in ("SENTINEL_WORKSPACE_ID", "AZ_TENANT_ID", "AZ_CLIENT_ID", "AZ_CLIENT_SECRET"):
        monkeypatch.setenv(k, "x-" + k.lower())
    s = load_settings(cfg)
    assert s.mode == "live" and s.org_name == "Acme Bank"
    for c in s.connectors.values():
        assert all(src["adapter"] in REGISTRY for src in (c.sources or [{"adapter": c.adapter}]))


def test_generated_sentinel_connector_runs(tmp_path, monkeypatch):
    from lodestar.orchestrator import Orchestrator
    cfg = tmp_path / "config" / "lodestar.yaml"
    init(org="Volt Grid", vertical="power_utilities", siem="sentinel", domains=["edr"], primary_domain="volt.example",
         root=tmp_path, out=cfg)
    text = cfg.read_text().replace("sqlite_path: data/lodestar.db", f"sqlite_path: {tmp_path / 'v.db'}")
    text = text.replace("path: config/assets.csv", f"path: {tmp_path / 'config' / 'assets.csv'}")
    cfg.write_text(text)
    (tmp_path / "config" / "assets.csv").write_text(
        "asset_id,name,asset_type,business_service,owner,criticality,exposure,aliases\n"
        "SCADA-HMI-01,SCADA HMI,server,Grid control,OT,5,internal,hmi01.volt.example\n")
    for k in ("SENTINEL_WORKSPACE_ID", "AZ_TENANT_ID", "AZ_CLIENT_ID", "AZ_CLIENT_SECRET"):
        monkeypatch.setenv(k, "v")
    rows = {"tables": [{"columns": [{"name": n} for n in ("TimeGenerated", "SystemAlertId", "AlertName", "AlertSeverity",
                                                           "CompromisedEntity", "Status", "Tactics", "ProductName")],
                        "rows": [["2026-09-30T10:00:00Z", "a-9", "Credential theft", "High", "hmi01", "New", "CredentialAccess", "MDE"]]}]}
    health = {"tables": [{"columns": [{"name": "coverage_pct"}, {"name": "sensors_stale"}], "rows": [[97.5, 2]]}]}

    def handler(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json=TOKEN)
        return httpx.Response(200, json=health if "DeviceInfo" in json.loads(req.content)["query"] else rows)
    set_transport(httpx.MockTransport(handler))
    try:
        res = Orchestrator(load_settings(cfg)).run()
    finally:
        set_transport(None)
    f = next(x for x in res.findings if x.finding_id == "edr-a-9")
    assert f.asset_id == "SCADA-HMI-01"                       # short name resolved through the CMDB alias
    edr = next(c for c in res.controls if c.domain.value == "edr")
    assert edr.coverage_pct == 97.5 and res.snapshot.kri_sources.get("edr_coverage_pct") == "connector:edr"
