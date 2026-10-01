"""Production features: tenant isolation, sessions + CSRF, OIDC/JWT, metrics, readiness, escalations, ITSM dedupe."""
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from lodestar.agents.connectors.adapters.base import set_transport
from lodestar.api.auth import OIDC, Principal, principal_for_key, sign, unsign
from lodestar.config import ROOT, ConfigError, load_tenants

C, E, A = "c" * 32, "e" * 32, "a" * 32


@pytest.fixture
def two_org_client(tmp_path, monkeypatch, demo_dir, banking_result):
    """Store holding two organisations; analyst key scoped to one of them."""
    from lodestar.api import app as appmod
    from lodestar.config import load_settings
    from lodestar.orchestrator import Orchestrator
    from lodestar.store import Store
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw.update({"storage": {"sqlite_path": str(tmp_path / "t.db")}, "security": {"require_auth": True},
                "demo": {"dataset": str(demo_dir / "banking.json")}, "ops": {"max_run_age_hours": 12}})
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("LODESTAR_CONFIG", str(cfg))
    monkeypatch.setenv("LODESTAR_API_KEYS", f"ciso:{C},exec:{E},analyst@sandline-bank-demo:{A}")
    monkeypatch.setenv("LODESTAR_METRICS_TOKEN", "m" * 24)
    store = Store(tmp_path / "t.db")
    store.save_result(banking_result)
    s2 = load_settings(cfg, overrides={"demo": {"dataset": str(demo_dir / "power_utilities.json")}})
    Orchestrator(s2, store=store).run()
    appmod.reset_caches()
    yield TestClient(appmod.app, base_url="https://testserver")
    appmod.reset_caches()


def test_org_scoped_keys_only_see_their_organisation(two_org_client):
    c = two_org_client
    assert len(c.get("/api/orgs", headers={"X-API-Key": C}).json()) == 2
    mine = c.get("/api/orgs", headers={"X-API-Key": A}).json()
    assert [o["key"] for o in mine] == ["sandline-bank-demo"]
    other = next(o["key"] for o in c.get("/api/orgs", headers={"X-API-Key": C}).json() if o["key"] != "sandline-bank-demo")
    assert c.get(f"/api/dashboard?org={other}", headers={"X-API-Key": A}).status_code == 404
    assert c.get("/api/me", headers={"X-API-Key": A}).json()["orgs"] == ["sandline-bank-demo"]


def test_session_login_requires_csrf_on_post(two_org_client):
    c = two_org_client
    r = c.post("/login", data={"key": C}, follow_redirects=False)
    assert r.status_code == 303 and "lodestar_session" in r.cookies and "lodestar_csrf" in r.cookies
    assert c.get("/api/me").json()["role"] == "ciso"                     # cookie session works for GET
    assert c.post("/api/chat/ask", json={"text": "brief"}).status_code == 403   # no CSRF header
    tok = c.cookies.get("lodestar_csrf")
    assert c.post("/api/chat/ask", json={"text": "brief"}, headers={"X-CSRF-Token": tok}).status_code == 200
    c.get("/logout")
    assert c.get("/api/me").status_code == 401


def test_signed_cookie_tamper_and_expiry():
    t = sign({"a": "x", "r": "ciso", "o": ["*"], "exp": int(time.time()) + 60})
    assert unsign(t)["r"] == "ciso"
    body, mac = t.rsplit(".", 1)
    forged = base64.urlsafe_b64encode(json.dumps({"a": "x", "r": "ciso", "o": ["*"], "exp": 9e9}).encode()).decode().rstrip("=")
    assert unsign(f"{forged}.{mac}") is None
    assert unsign(sign({"r": "ciso", "exp": int(time.time()) - 1})) is None


def test_api_key_formats(monkeypatch):
    monkeypatch.setenv("LODESTAR_API_KEYS", f"ciso:{C},analyst@acme:{A},exec:short")
    assert principal_for_key(C).orgs == {"*"}
    assert principal_for_key(A).orgs == {"acme"} and principal_for_key(A).role == "analyst"
    assert principal_for_key("short") is None


def test_metrics_and_readiness(two_org_client):
    c = two_org_client
    assert c.get("/metrics").status_code == 401
    m = c.get("/metrics", headers={"Authorization": "Bearer " + "m" * 24}).text
    assert 'lodestar_posture_score{org="sandline-bank-demo"}' in m and "lodestar_findings_open" in m
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["store"] is True


# ------------------------------------------------------------------ OIDC
@pytest.fixture
def idp():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    meta = {"issuer": "https://idp.example", "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/keys"}

    def handler(req):
        if req.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=meta)
        if req.url.path == "/keys":
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(404)
    set_transport(httpx.MockTransport(handler))

    def mint(**claims):
        now = int(time.time())
        base = {"iss": "https://idp.example", "aud": "lodestar-app", "iat": now, "exp": now + 300, "sub": "u1",
                "preferred_username": "jane@corp.example"}
        return jwt.encode({**base, **claims}, key, algorithm="RS256", headers={"kid": "k1"})
    yield mint
    set_transport(None)


def test_oidc_verify_and_group_mapping(idp):
    o = OIDC({"issuer": "https://idp.example", "client_id": "lodestar-app",
              "role_map": {"grp-soc": "analyst", "grp-ciso": "ciso"}, "org_map": {"grp-acme": "acme"}})
    claims = o.verify(idp(groups=["grp-soc", "grp-ciso", "grp-acme"], nonce="n1"), "lodestar-app", nonce="n1")
    p = o.principal(claims)
    assert p.role == "ciso" and p.orgs == {"acme"} and p.actor == "oidc:jane@corp.example"
    with pytest.raises(jwt.InvalidAudienceError):
        o.verify(idp(aud="someone-else"), "lodestar-app")
    with pytest.raises(jwt.ExpiredSignatureError):
        o.verify(idp(exp=int(time.time()) - 600), "lodestar-app")
    with pytest.raises(PermissionError):
        o.principal({"groups": ["grp-acme"]})                   # in an org group but no role group


def test_oidc_login_redirect_uses_pkce(idp):
    o = OIDC({"issuer": "https://idp.example", "client_id": "lodestar-app"})
    url, flow = o.start("https://lodestar.example/auth/callback")
    assert url.startswith("https://idp.example/authorize?") and "code_challenge_method=S256" in url
    assert unsign(flow)["v"]                                   # PKCE verifier kept server-side, signed


# ------------------------------------------------------------------ tenants
def test_tenant_files_merge_and_replace_connectors(tmp_path, monkeypatch):
    base = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    base.update({"mode": "live", "tenants": {"dir": str(tmp_path / "tenants")}, "scoring": {**base["scoring"], "today_capacity": 9}})
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(base))
    (tmp_path / "tenants").mkdir()
    (tmp_path / "tenants" / "acme.yaml").write_text(
        "org: {name: Acme Bank, vertical: banking}\nconnectors:\n  edr: {adapter: file_drop, settings: {path: data/drop/acme-edr}}\n")
    (tmp_path / "tenants" / "volt.yaml").write_text("org: {name: Volt Grid, vertical: power_utilities}\nconnectors: {}\n")
    ts = load_tenants(cfg)
    assert [t.org_key for t in ts] == ["acme-bank", "volt-grid"]
    assert list(ts[0].connectors) == [next(iter(ts[0].connectors))] and ts[0].connectors[next(iter(ts[0].connectors))].adapter == "file_drop"
    assert ts[1].connectors == {} and ts[0].scoring.today_capacity == 9
    (tmp_path / "tenants" / "dup.yaml").write_text("org: {name: ACME bank, vertical: banking}\n")
    with pytest.raises(ConfigError, match="duplicate"):
        load_tenants(cfg)


# ------------------------------------------------------------------ escalation + ITSM
def test_escalation_once_per_stage(banking_result, tmp_path, monkeypatch):
    from lodestar.chatops import notifier
    from lodestar.store import Store
    store = Store(tmp_path / "e.db")
    res = banking_result.model_copy(deep=True)
    d = next(x for x in res.decisions if x["urgency"] == "now")
    res.decisions = [d]
    store.register_decisions(res.org_name, [d["decision_id"]], datetime.now(timezone.utc) - timedelta(hours=5))
    sent = []
    monkeypatch.setattr(notifier, "send", lambda reply, cfg, only=None: sent.append(reply) or [{"ok": True}])
    now = datetime.now(timezone.utc)
    assert notifier.escalate(res, store, {}, now) and len(sent) == 1
    assert notifier.escalate(res, store, {}, now) == []                       # stage 1 only once
    assert notifier.escalate(res, store, {}, now + timedelta(hours=4)) and "SECOND" in sent[-1].lines[0]


def test_itsm_submit_once(tmp_path, monkeypatch):
    from lodestar import itsm
    from lodestar.store import Store
    store = Store(tmp_path / "i.db")
    calls = []
    monkeypatch.setattr(itsm, "submit", lambda a, c: calls.append(a) or {"submitted": True, "ticket": "SEC-12", "url": "u"})
    action = {"action_id": "ACT-1", "title": "t"}
    assert itsm.submit_once(store, "Org", action, {})["ticket"] == "SEC-12"
    again = itsm.submit_once(store, "Org", action, {})
    assert again["duplicate"] is True and again["ticket"] == "SEC-12" and len(calls) == 1


def test_principal_visibility():
    assert Principal("a", "exec", {"x"}).can_see("x") and not Principal("a", "exec", {"x"}).can_see("y")
    assert Principal("a", "exec").can_see("anything")


def test_webhook_timestamp_replay_window(client, monkeypatch):
    import hashlib
    import hmac as _h
    body = json.dumps([{"finding_id": "waf-ts-1", "source": "cf", "finding_type": "detection",
                        "title": "SQLi", "severity": "high"}]).encode()

    def sig(ts):
        return "sha256=" + _h.new(b"s3cret-for-tests", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    now = str(int(time.time()))
    ok = client.post("/api/ingest/waf", content=body, headers={"X-Lodestar-Timestamp": now, "X-Lodestar-Signature": sig(now)})
    assert ok.status_code == 202
    old = str(int(time.time()) - 900)
    stale = client.post("/api/ingest/waf", content=body, headers={"X-Lodestar-Timestamp": old, "X-Lodestar-Signature": sig(old)})
    assert stale.status_code == 401


# ------------------------------------------------------------------ regressions from the v2.0 review
def test_tenant_file_cannot_weaken_deployment_settings(tmp_path):
    base = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    base.update({"mode": "live", "tenants": {"dir": str(tmp_path / "t")}})
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(base))
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "aaa.yaml").write_text("org: {name: Evil, vertical: banking}\nmode: demo\nsecurity: {require_auth: false}\n")
    with pytest.raises(ConfigError, match="tenant file"):
        load_tenants(cfg)


def test_single_tenant_file_webhook_is_readable(tmp_path, monkeypatch):
    from lodestar.api import app as appmod
    from lodestar.store import Store
    base = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    base.update({"mode": "live", "tenants": {"dir": str(tmp_path / "t")}, "storage": {"sqlite_path": str(tmp_path / "w.db")}})
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(base))
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "acme.yaml").write_text("org: {name: Acme Bank, vertical: banking}\nconnectors: {waf: {adapter: webhook}}\n")
    monkeypatch.setenv("LODESTAR_CONFIG", str(cfg))
    monkeypatch.setenv("LODESTAR_WEBHOOK_SECRET", "s" * 20)
    appmod.reset_caches()
    try:
        import hashlib
        import hmac as _h
        body = json.dumps([{"finding_id": "waf-9", "source": "cf", "finding_type": "detection", "title": "x", "severity": "high"}]).encode()
        sig = "sha256=" + _h.new(b"s" * 20, body, hashlib.sha256).hexdigest()
        r = TestClient(appmod.app).post("/api/ingest/waf", content=body, headers={"X-Lodestar-Signature": sig})
        assert r.status_code == 202
        items = Store(tmp_path / "w.db").webhook_findings("waf", org="Acme Bank", include_unscoped=False)
        assert [i["finding_id"] for i in items] == ["waf-9"]
    finally:
        appmod.reset_caches()


def test_multi_tenant_chat_without_mapping_is_refused(monkeypatch):
    from lodestar.api import app as appmod
    monkeypatch.setattr(appmod, "get_tenants", lambda: {"a": object(), "b": object()})
    assert appmod._unmapped_chat(None) is not None and appmod._unmapped_chat("a") is None


def test_lifecycle_carries_risk_accepted_and_counts_misses():
    from lodestar.agents.base import PipelineState
    from lodestar.agents.core.lifecycle import LifecycleAgent
    from lodestar.models import Domain, Finding, FindingType, Severity, Status
    st, missed = PipelineState(), {}
    f = Finding(finding_id="x", domain=Domain.VMDR, source="t", finding_type=FindingType.VULNERABILITY, title="t",
                severity=Severity.HIGH, status=Status.RISK_ACCEPTED)
    LifecycleAgent._carry(st, f, 1, missed)
    assert st.findings == [f] and missed == {"x": 1}


def test_administrative_closures_do_not_count_as_fixes(tmp_path, banking_result):
    from lodestar.store import Store
    s = Store(tmp_path / "r.db")
    res = banking_result.model_copy(deep=True)
    vulns = [f for f in res.findings if f.domain.value == "vmdr"][:3]
    res.findings = vulns
    s.save_result(res, {"resolve": {vulns[0].finding_id: "source no longer integrated",
                                    vulns[1].finding_id: "expired: no update for 30 days",
                                    vulns[2].finding_id: "not seen in 2 consecutive full pulls"}})
    assert len(s.resolution_stats(res.org_name, 3650)) == 1


def test_kris_need_the_right_sources_and_phase():
    from lodestar.metrics import compute_kris
    from lodestar.models import ControlHealth, Domain
    now = datetime.now(timezone.utc)
    backup = ControlHealth(domain=Domain.BACKUP, product="b", coverage_pct=100, kpis={"immutable_pct": 99})
    k = compute_kris([], [backup], [], {}, now, phase=4)
    assert "internet_facing_critical_count" not in k and k["toxic_combinations_open"] == 0
    assert "toxic_combinations_open" not in compute_kris([], [backup], [], {}, now, phase=1)
    assert "critical_vuln_sla_pct" not in compute_kris([], [backup], [], {}, now, computed={"critical_vuln_sla_pct": 99.0})


def test_hunt_matches_md5_and_host_port():
    from lodestar.agents.core.hunt import KQL_TEMPLATE, ThreatHuntAgent
    from lodestar.models import Severity
    assert "SHA1 in~ (hashes), SHA1" in KQL_TEMPLATE
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    meta = {"severity": Severity.HIGH, "tlp": None, "title": "t", "source": "s", "seen": datetime.now(timezone.utc), "intel_id": "i"}
    iocs = {md5: {"kind": "hash", **meta}, "evil.example": {"kind": "domain", **meta}, "203.0.113.7": {"kind": "ip", **meta}}
    rows = [{"Host": "h1", "Indicator": md5.upper()}, {"Host": "h2", "Indicator": "evil.example:443"},
            {"Host": "h3", "Indicator": "203.0.113.7:8080"}]
    got = {f.evidence["ioc"] for f in ThreatHuntAgent.to_findings(rows, iocs, datetime.now(timezone.utc))}
    assert got == {md5, "evil.example", "203.0.113.7"}
