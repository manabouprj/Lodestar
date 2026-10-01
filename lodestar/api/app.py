"""LODESTAR REST API + dashboard.

Run:  python -m lodestar serve   (or: uvicorn lodestar.api.app:app)

Auth (see lodestar/api/auth.py and docs/PRODUCTION.md)
  * OIDC single sign-on (security.oidc) - roles and organisations from group / role claims
  * API keys  LODESTAR_API_KEYS="ciso:<key>,analyst@acme-bank:<key>,exec:<key>"  (header X-API-Key)
  * Bearer JWTs from the same identity provider (service-to-service)
  * enforced when security.require_auth=true or mode=live; cookie sessions need X-CSRF-Token on POST
Roles
  exec     dashboard, reports, KRIs
  analyst  + priorities, findings, controls, attack paths, approve actions, decide
  ciso     + run pipeline, audit log, agent catalogue, regulatory decisions
Organisations (multi-tenant, config/tenants/*.yaml): every endpoint takes ?org=<key>; principals only
see the organisations they are mapped to.
Webhook ingestion (POST /api/ingest/{domain}?org=<key>) is authenticated with an HMAC-SHA256 signature
(header X-Lodestar-Signature: sha256=<hex>) using LODESTAR_WEBHOOK_SECRET_<ORG_KEY> or LODESTAR_WEBHOOK_SECRET.
Ops: /healthz (liveness), /readyz (store + data freshness), /metrics (Prometheus, LODESTAR_METRICS_TOKEN).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .. import __version__
from ..config import Settings, load_tenants
from ..dashboard import build_payload
from ..itsm import submit_once
from ..models import Domain, Horizon, PipelineResult, Status
from ..reporting import render
from ..store import Store
from ..web import render_dashboard, slug
from .auth import (
    CSRF_COOKIE,
    FLOW_COOKIE,
    OIDC,
    SESSION_COOKIE,
    Principal,
    check_csrf,
    principal_for_key,
    principal_from_session,
    set_login_cookies,
)

MAX_INGEST_BYTES = 5 * 1024 * 1024


@lru_cache(maxsize=1)
def get_tenants() -> dict[str, Settings]:
    return {t.org_key: t for t in load_tenants()}


def get_settings() -> Settings:
    """Deployment-wide settings (security, chatops, llm): the first tenant carries the shared base config."""
    return next(iter(get_tenants().values()))


def tenant(org_key: str | None) -> Settings:
    ts = get_tenants()
    if org_key and org_key in ts:
        return ts[org_key]
    return get_settings()


@lru_cache(maxsize=1)
def get_store() -> Store:
    s = get_settings()
    return Store(s.sqlite_path, keep_runs=int((s.raw.get("storage") or {}).get("keep_runs", 5)))


@lru_cache(maxsize=1)
def get_oidc() -> OIDC:
    return OIDC((get_settings().raw.get("security") or {}).get("oidc") or {})


def reset_caches() -> None:
    """Re-read config, tenants, store and identity-provider metadata (tests, config reload)."""
    for f in (get_tenants, get_store, get_oidc):
        f.cache_clear()


def _auth_required(s: Settings) -> bool:
    return bool((s.raw.get("security") or {}).get("require_auth")) or s.mode == "live"


def _secure_cookies() -> bool:
    return bool((get_settings().raw.get("security") or {}).get("secure_cookies", True))


def current_principal(request: Request) -> Principal:
    if not _auth_required(get_settings()):
        return Principal(actor="local", role="ciso", via="open")
    key = request.headers.get("X-API-Key")
    if key:
        p = principal_for_key(key)
        if p:
            return p
        raise HTTPException(401, "Invalid API key")
    authz = request.headers.get("Authorization", "")
    if authz.lower().startswith("bearer ") and get_oidc().enabled:
        oc = get_oidc().cfg
        try:
            claims = get_oidc().verify(authz[7:].strip(), oc.get("audience") or oc["client_id"])
            return get_oidc().principal(claims, via="bearer")
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(401, "Invalid bearer token") from exc
    p = principal_from_session(request.cookies.get(SESSION_COOKIE))
    if p:
        check_csrf(request)
        return p
    raise HTTPException(401, "Sign in at /login, or send X-API-Key / Authorization: Bearer")


def need(min_role: str):
    def dep(request: Request) -> Principal:
        p = current_principal(request)
        if not p.at_least(min_role):
            raise HTTPException(403, f"Requires role '{min_role}'")
        request.state.principal = p
        return p
    return dep


app = FastAPI(title="LODESTAR", version=__version__,
              description="Security posture intelligence & prioritisation agents")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    t0 = time.perf_counter()
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
                            "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; "
                            "connect-src 'self'; frame-ancestors 'none'")
    if _secure_cookies():
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    _REQS[(request.method, resp.status_code // 100)] = _REQS.get((request.method, resp.status_code // 100), 0) + 1
    _LAT[0] += time.perf_counter() - t0
    _LAT[1] += 1
    return resp


_REQS: dict[tuple[str, int], int] = {}
_LAT = [0.0, 0]


def _results(store: Store, p: Principal | None = None) -> dict[str, PipelineResult]:
    from ..decisions import overlay
    out = {}
    for org in store.list_orgs():
        key = slug(org)
        if p is not None and not p.can_see(key):
            continue
        r = store.latest_result(org)
        if r:
            out[key] = overlay(store, r)
    return out


def _result(store: Store, org: Optional[str], p: Principal | None = None) -> PipelineResult:
    res = _results(store, p)
    if not res:
        raise HTTPException(404, "No pipeline results you can see yet - run `python -m lodestar run`")
    if org:
        if org not in res:
            raise HTTPException(404, f"Unknown or not permitted org '{org}'. Yours: {sorted(res)}")
        return res[org]
    return next(iter(res.values()))


# ---------------------------------------------------------------- public / ops
@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"


def _known_orgs() -> dict[str, str]:
    """key -> org name: configured tenants plus organisations present in the store (demo datasets)."""
    out = {slug(o): o for o in get_store().list_orgs()}
    if get_settings().mode == "live":
        out.update({k: t.org_name for k, t in get_tenants().items()})
    return out


@app.get("/readyz")
def readyz():
    """Ready = store reachable and every organisation has a run newer than ops.max_run_age_hours."""
    s = get_settings()
    max_age = float((s.raw.get("ops") or {}).get("max_run_age_hours", 12))
    try:
        store_ok = get_store().ping()
    except Exception as exc:
        return JSONResponse({"ready": False, "store": f"error: {type(exc).__name__}"}, status_code=503)
    now = datetime.now(timezone.utc)
    orgs, stale = _known_orgs(), 0
    for org_name in orgs.values():
        info = get_store().latest_run_info(org_name)
        if not info:
            stale += 1
            continue
        gen = datetime.fromisoformat(str(info["generated_at"]).replace("Z", "+00:00"))
        age = (now - (gen if gen.tzinfo else gen.replace(tzinfo=timezone.utc))).total_seconds() / 3600
        stale += age > max_age
    ok = s.mode == "demo" or stale == 0
    # unauthenticated endpoint: counts only, never organisation names
    return JSONResponse({"ready": ok, "store": store_ok, "organisations": len(orgs), "stale": stale},
                        status_code=200 if ok else 503)


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    token = os.environ.get("LODESTAR_METRICS_TOKEN", "")
    if token:
        if not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {token}"):
            raise HTTPException(401, "metrics token required")
    elif _auth_required(get_settings()):
        raise HTTPException(404, "set LODESTAR_METRICS_TOKEN to enable /metrics")
    from ..ops import prometheus
    return PlainTextResponse(prometheus(get_store(), _known_orgs(), _REQS, _LAT), media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------- sign-in
LOGIN_PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>LODESTAR sign in</title>
<body style="background:#0b0f14;color:#e6edf3;font:16px system-ui,sans-serif"><main style="max-width:360px;margin:15vh auto;display:grid;gap:12px">
<h1 style="font-size:20px;margin:0">LODESTAR</h1>{sso}{err}
<form method=post action=login style="display:grid;gap:8px"><label for=k>API key</label>
<input id=k name=key type=password autocomplete=current-password required style="padding:8px">
<button style="padding:8px">Sign in with key</button></form></main>"""


@app.get("/login", response_class=HTMLResponse)
def login_form(error: str = ""):
    from html import escape
    sso = ('<a href="auth/login" style="display:block;text-align:center;padding:10px;background:#2f81f7;color:#fff;'
           'text-decoration:none;border-radius:4px">Sign in with single sign-on</a>') if get_oidc().enabled else ""
    err = f'<p role=alert style="color:#ff7b72">{escape(error[:200])}</p>' if error else ""
    return LOGIN_PAGE.replace("{sso}", sso).replace("{err}", err)


@app.post("/login")
def login(key: str = Form(...)):
    p = principal_for_key(key)
    if not p:
        raise HTTPException(401, "Invalid key")
    resp = RedirectResponse("/", status_code=303)
    set_login_cookies(resp, p, secure=_secure_cookies())
    get_store().audit(p.actor, "login", {"via": "api-key"})
    return resp


@app.post("/logout")
@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    for c in (SESSION_COOKIE, CSRF_COOKIE, "lodestar_key"):
        resp.delete_cookie(c)
    return resp


def _redirect_uri(request: Request) -> str:
    return get_oidc().cfg.get("redirect_uri") or str(request.url_for("oidc_callback"))


@app.get("/auth/login")
def oidc_login(request: Request):
    if not get_oidc().enabled:
        raise HTTPException(404, "single sign-on is not configured (security.oidc)")
    url, flow = get_oidc().start(_redirect_uri(request))
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(FLOW_COOKIE, flow, httponly=True, samesite="lax", secure=_secure_cookies(), max_age=600)
    return resp


@app.get("/auth/callback", name="oidc_callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return RedirectResponse(f"/login?error={error_description or error}", status_code=303)
    try:
        claims = get_oidc().finish(code, state, request.cookies.get(FLOW_COOKIE), _redirect_uri(request))
        p = get_oidc().principal(claims)
    except PermissionError as exc:
        get_store().audit("oidc", "login_denied", {"reason": str(exc)})
        return RedirectResponse(f"/login?error={exc}", status_code=303)
    except Exception as exc:
        get_store().audit("oidc", "login_failed", {"error": f"{type(exc).__name__}: {exc}"[:300]})
        return RedirectResponse("/login?error=Single sign-on failed - see the audit log", status_code=303)
    resp = RedirectResponse("/", status_code=303)
    set_login_cookies(resp, p, secure=_secure_cookies())
    resp.delete_cookie(FLOW_COOKIE)
    get_store().audit(p.actor, "login", {"via": "oidc", "role": p.role, "orgs": sorted(p.orgs)})
    return resp


@app.get("/api/me")
def me(p: Principal = Depends(need("exec"))):
    return {"actor": p.actor, "role": p.role, "orgs": sorted(p.orgs), "via": p.via}


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    s = get_settings()
    try:
        p = current_principal(request)
    except HTTPException:
        return RedirectResponse("/login")
    res = _results(get_store(), p)
    payloads = [build_payload(r) for r in res.values()]
    return render_dashboard(payloads, demo=s.mode == "demo", api=True)


@app.get("/api/orgs")
def orgs(p: Principal = Depends(need("exec"))):
    return [{"key": k, "org": r.org_name, "vertical": r.vertical, "generated_at": r.generated_at}
            for k, r in _results(get_store(), p).items()]


@app.get("/api/dashboard")
def dashboard_data(org: Optional[str] = None, p: Principal = Depends(need("exec"))):
    return build_payload(_result(get_store(), org, p))


@app.get("/api/kris")
def kris(org: Optional[str] = None, p: Principal = Depends(need("exec"))):
    return build_payload(_result(get_store(), org, p))["kris"]


@app.get("/api/priorities")
def priorities(org: Optional[str] = None, horizon: Horizon = Horizon.TODAY, domain: Optional[Domain] = None,
               team: Optional[str] = None, limit: int = Query(100, le=1000), p: Principal = Depends(need("analyst"))):
    r = _result(get_store(), org, p)
    rows = [f for f in r.findings if f.status in (Status.OPEN, Status.IN_PROGRESS) and f.horizon == horizon
            and (domain is None or f.domain == domain) and (team is None or f.owner_team == team)]
    return [f.model_dump(mode="json") for f in rows[:limit]]


@app.get("/api/findings/{finding_id}")
def finding(finding_id: str, org: Optional[str] = None, p: Principal = Depends(need("analyst"))):
    r = _result(get_store(), org, p)
    for f in r.findings:
        if f.finding_id == finding_id:
            return f.model_dump(mode="json")
    raise HTTPException(404, "Finding not found")


@app.get("/api/attack-paths")
def attack_paths(org: Optional[str] = None, p: Principal = Depends(need("analyst"))):
    return [c.model_dump(mode="json") for c in _result(get_store(), org, p).correlations]


@app.get("/api/controls")
def controls(org: Optional[str] = None, p: Principal = Depends(need("analyst"))):
    return [c.model_dump(mode="json") for c in _result(get_store(), org, p).controls]


@app.get("/api/compliance")
def compliance(org: Optional[str] = None, p: Principal = Depends(need("exec"))):
    return _result(get_store(), org, p).compliance


@app.get("/api/reports/{period}")
def report(period: str, org: Optional[str] = None, format: str = Query("html", pattern="^(html|md|json)$"),
           p: Principal = Depends(need("exec"))):
    if period not in ("weekly", "monthly", "quarterly"):
        raise HTTPException(400, "period must be weekly, monthly or quarterly")
    body = render(_result(get_store(), org, p), period, format, get_settings().llm)
    media = {"html": "text/html", "md": "text/markdown", "json": "application/json"}[format]
    return Response(content=body, media_type=media)


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, org: Optional[str] = None, p: Principal = Depends(need("analyst"))):
    r = _result(get_store(), org, p)
    action = next((a for a in r.actions if a["action_id"] == action_id), None)
    if not action:
        raise HTTPException(404, "Action not found")
    outcome = submit_once(get_store(), r.org_name, action, tenant(slug(r.org_name)).itsm)
    get_store().audit(p.actor, "action_approved", {"action_id": action_id, "org": r.org_name, "itsm": outcome.get("submitted"),
                                                   "ticket": outcome.get("ticket")})
    return {"action_id": action_id, "approved_by_role": p.role, "approved_by": p.actor, **outcome}


@app.get("/api/decisions")
def decisions(org: Optional[str] = None, status: Optional[str] = "pending", p: Principal = Depends(need("exec"))):
    r = _result(get_store(), org, p)
    return [d for d in r.decisions if status in (None, "all") or d["status"] == status]


async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "Body must be a JSON object") from exc
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object")
    return body


@app.post("/api/decisions/{decision_id}")
async def decide(decision_id: str, request: Request, org: Optional[str] = None, p: Principal = Depends(need("analyst"))):
    from ..decisions import DecisionError, record
    body = await _json(request)
    try:
        r = _result(get_store(), org, p)
        return record(get_store(), r, decision_id, str(body.get("choice", "")), p.role, actor=p.actor,
                      note=str(body.get("note", "")), channel="dashboard", itsm_cfg=tenant(slug(r.org_name)).itsm)
    except DecisionError as exc:
        raise HTTPException(exc.code, str(exc)) from exc


# ---------------------------------------------------------------- chat (dashboard, Slack, Teams)
def _chat(org: Optional[str] = None, p: Principal | None = None):
    from ..chatops import ChatEngine
    s = get_settings()
    return ChatEngine(_result(get_store(), org, p), (s.chatops or {}).get("dashboard_url"))


def _chat_org(platform: str, channel: str | None = None, query_org: str | None = None) -> str | None:
    """Which organisation a Slack channel / Teams webhook talks about. Single-tenant: the only one.
    Multi-tenant: chatops.slack.channel_orgs {channel_id: org_key}, Teams ?org=<key> on the webhook URL,
    else chatops.default_org."""
    cfg = get_settings().chatops or {}
    if query_org:
        return query_org
    if platform == "slack" and channel:
        m = ((cfg.get("slack") or {}).get("channel_orgs") or {}).get(channel)
        if m:
            return m
    return cfg.get("default_org")


def _unmapped_chat(org: str | None):
    """Several organisations and no mapping for this channel / webhook: answer nothing rather than guess."""
    if org is None and len(get_tenants()) > 1:
        from ..chatops.engine import ChatReply
        return ChatReply("This channel is not linked to an organisation",
                         ["Ask an administrator to add it to chatops.slack.channel_orgs (Slack) or to append "
                          "?org=<key> to the Teams outgoing-webhook URL."], intent="help")
    return None


def _recorder(org: Optional[str], channel: str, actor: str):
    from ..decisions import record

    def rec(decision_id: str, choice: str, role: str):
        r = _result(get_store(), org)
        return record(get_store(), r, decision_id, choice, role, channel=channel,
                      actor=actor, itsm_cfg=tenant(slug(r.org_name)).itsm)
    return rec


@app.post("/api/chat/ask")
async def chat_ask(request: Request, org: Optional[str] = None, p: Principal = Depends(need("exec"))):
    body = await _json(request)
    org = org or next(iter(_results(get_store(), p)), None)
    reply = _chat(org, p).handle(str(body.get("text", ""))[:500], p.role, _recorder(org, "dashboard-chat", p.actor))
    return {"title": reply.title, "lines": reply.lines, "intent": reply.intent,
            "buttons": [b.__dict__ for b in reply.buttons]}


@app.post("/api/chat/slack/commands")
async def slack_command(request: Request):
    from urllib.parse import parse_qs

    from ..chatops import slack
    cfg = (get_settings().chatops or {}).get("slack") or {}
    body = await request.body()
    if not slack.verify(cfg.get("signing_secret", ""), request.headers.get("X-Slack-Request-Timestamp", ""), body,
                        request.headers.get("X-Slack-Signature", "")):
        raise HTTPException(401, "Invalid Slack signature")
    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
    user = form.get("user_id", "")
    role = slack.role_for(user, cfg)
    org = _chat_org("slack", form.get("channel_id"))
    refusal = _unmapped_chat(org)
    if refusal:
        return slack.message(refusal)
    reply = _chat(org).handle(form.get("text", ""), role, _recorder(org, "slack", user))
    return slack.message(reply)


@app.post("/api/chat/slack/interactions")
async def slack_interaction(request: Request):
    from urllib.parse import parse_qs

    from ..chatops import slack
    cfg = (get_settings().chatops or {}).get("slack") or {}
    body = await request.body()
    if not slack.verify(cfg.get("signing_secret", ""), request.headers.get("X-Slack-Request-Timestamp", ""), body,
                        request.headers.get("X-Slack-Signature", "")):
        raise HTTPException(401, "Invalid Slack signature")
    payload = json.loads(parse_qs(body.decode()).get("payload", ["{}"])[0])
    user = (payload.get("user") or {}).get("id", "")
    action = (payload.get("actions") or [{}])[0]
    val = json.loads(action.get("value") or "{}")
    org = _chat_org("slack", (payload.get("channel") or {}).get("id"))
    refusal = _unmapped_chat(org)
    if refusal:
        return {"replace_original": False, "response_type": "ephemeral", "text": refusal.title, "blocks": slack.blocks(refusal)}
    reply = _chat(org).handle(f"decide {val.get('d', '')} {val.get('c', '')}", slack.role_for(user, cfg),
                              _recorder(org, "slack", user))
    return {"replace_original": False, "response_type": "ephemeral", "text": reply.title, "blocks": slack.blocks(reply)}


@app.post("/api/chat/slack/events")
async def slack_events(request: Request):
    import asyncio

    from ..chatops import slack
    cfg = (get_settings().chatops or {}).get("slack") or {}
    body = await request.body()
    if not slack.verify(cfg.get("signing_secret", ""), request.headers.get("X-Slack-Request-Timestamp", ""), body,
                        request.headers.get("X-Slack-Signature", "")):
        raise HTTPException(401, "Invalid Slack signature")
    data = json.loads(body)
    if data.get("type") == "url_verification":
        return {"challenge": data.get("challenge")}
    ev = data.get("event") or {}
    if ev.get("bot_id") or ev.get("type") not in ("app_mention", "message"):
        return {"ok": True}
    import re as _re
    text = _re.sub(r"<@[A-Z0-9]+>", "", ev.get("text", "")).strip()
    user = ev.get("user", "")
    org = _chat_org("slack", ev.get("channel"))
    reply = _unmapped_chat(org) or _chat(org).handle(text, slack.role_for(user, cfg), _recorder(org, "slack", user))
    # answer asynchronously - Slack requires the HTTP ack within 3 seconds
    asyncio.get_running_loop().run_in_executor(None, lambda: slack.post(reply, cfg, ev.get("channel")))
    return {"ok": True}


@app.post("/api/chat/teams/messages")
async def teams_message(request: Request, org: Optional[str] = None):
    from ..chatops import teams
    cfg = (get_settings().chatops or {}).get("teams") or {}
    body = await request.body()
    if not teams.verify(cfg.get("outgoing_webhook_token", ""), body, request.headers.get("Authorization", "")):
        raise HTTPException(401, "Invalid Teams signature")
    act = json.loads(body)
    who = (act.get("from") or {}).get("aadObjectId", "")
    org = _chat_org("teams", query_org=org)
    refusal = _unmapped_chat(org)
    if refusal:
        return teams.activity(refusal)
    reply = _chat(org).handle(teams.strip_mention(act.get("text", "")), teams.role_for(who, cfg),
                              _recorder(org, "teams", who))
    return teams.activity(reply)


@app.post("/api/run")
def run_pipeline(org: Optional[str] = None, p: Principal = Depends(need("ciso"))):
    """Run now (another run in progress for the same organisation -> 409)."""
    from ..orchestrator import Orchestrator
    from ..store import LockBusy
    targets = [t for k, t in get_tenants().items() if p.can_see(k) and (org is None or k == org)]
    if not targets:
        raise HTTPException(404, f"Unknown or not permitted org '{org}'")
    out = []
    for t in targets:
        try:
            res = Orchestrator(t, store=get_store()).run()
        except LockBusy as exc:
            raise HTTPException(409, f"{t.org_name}: a run is already in progress") from exc
        get_store().audit(p.actor, "pipeline_run", {"org": res.org_name, "findings": len(res.findings)})
        out.append({"org": res.org_name, "posture": res.snapshot.posture_score,
                    "today": res.snapshot.open_by_horizon.get("today")})
    return out[0] if len(out) == 1 else out


@app.get("/api/audit")
def audit(limit: int = Query(200, le=2000), p: Principal = Depends(need("ciso"))):
    if "*" not in p.orgs:
        raise HTTPException(403, "The audit log spans every organisation - needs a ciso principal mapped to all organisations")
    return get_store().recent_audit(limit)


@app.get("/api/agents")
def agents(p: Principal = Depends(need("exec"))):
    from ..catalog import agent_catalog
    return agent_catalog()


# ---------------------------------------------------------------- webhook ingest
def verify_signature(body: bytes, header: str, secret: str) -> bool:
    if not secret or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.split("=", 1)[1])


def _ingest_org(request: Request) -> tuple[str, str]:
    """(org name to store under, secret suffix). Multi-tenant deployments must say which organisation."""
    key = request.query_params.get("org") or request.headers.get("X-Lodestar-Org") or ""
    ts = get_tenants()
    if key:
        if key not in ts:
            raise HTTPException(404, "Unknown org")
        return ts[key].org_name, key
    if len(ts) > 1:
        raise HTTPException(400, "Several organisations are configured - add ?org=<key> to the webhook URL")
    only_key, only = next(iter(ts.items()))
    if only.raw.get("_tenant_file"):          # one tenant file: store under that organisation, as the adapter reads it
        return only.org_name, only_key
    return "", ""


def _webhook_secret(base: str, org_key: str) -> str:
    """Per-organisation secret <BASE>_<ORG_KEY>. With several organisations it is mandatory: the ?org= parameter
    is not covered by the signature, so a shared secret would let one organisation's sender write into another."""
    if org_key:
        v = os.environ.get(f"{base}_{org_key.upper().replace('-', '_')}")
        if v:
            return v
        if len(get_tenants()) > 1:
            return ""
    return os.environ.get(base, "")


def _too_large(request: Request) -> bool:
    try:
        return int(request.headers.get("content-length") or 0) > MAX_INGEST_BYTES
    except ValueError:
        return True


@app.post("/api/ingest/hackerone")
async def ingest_hackerone(request: Request):
    """HackerOne programme webhooks (report_created, report_triaged, report_severity_updated, bounty_awarded ...).
    Signature: X-H1-Signature: sha256=<hex HMAC-SHA256 of body> with the webhook secret (LODESTAR_H1_WEBHOOK_SECRET)."""
    from ..agents.connectors.adapters.hackerone import map_report
    if _too_large(request):
        raise HTTPException(413, "Payload too large")
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(413, "Payload too large")
    org_name, org_key = _ingest_org(request)
    if not verify_signature(body, request.headers.get("X-H1-Signature", ""), _webhook_secret("LODESTAR_H1_WEBHOOK_SECRET", org_key)):
        raise HTTPException(401, "Invalid or missing signature")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Body must be JSON") from exc
    report = ((data.get("data") or {}).get("report")) or data.get("report")
    if not report or not report.get("id"):
        return JSONResponse({"accepted": 0, "ignored": "event without report"}, status_code=202)
    f = map_report(report)
    n = get_store().upsert_webhook("bug_bounty", [json.loads(f.model_dump_json())], org=org_name)
    get_store().audit("webhook:hackerone", "ingest", {"event": request.headers.get("X-H1-Event"), "report": report.get("id"),
                                                      "org": org_name})
    return JSONResponse({"accepted": n}, status_code=202)


@app.post("/api/ingest/{domain}")
async def ingest(domain: Domain, request: Request):
    if _too_large(request):
        raise HTTPException(413, "Payload too large")
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(413, "Payload too large")
    org_name, org_key = _ingest_org(request)
    ts = request.headers.get("X-Lodestar-Timestamp", "")
    require_ts = bool((get_settings().raw.get("security") or {}).get("webhook_require_timestamp"))
    if ts or require_ts:
        # replay protection: sign "<unix seconds>.<body>", accepted for 5 minutes
        try:
            fresh = abs(time.time() - int(ts)) <= 300
        except ValueError:
            fresh = False
        if not fresh:
            raise HTTPException(401, "Missing or stale X-Lodestar-Timestamp")
        signed = ts.encode() + b"." + body
    else:
        signed = body
    if not verify_signature(signed, request.headers.get("X-Lodestar-Signature", ""),
                            _webhook_secret("LODESTAR_WEBHOOK_SECRET", org_key)):
        raise HTTPException(401, "Invalid or missing signature")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Body must be JSON") from exc
    health = data.get("health") if isinstance(data, dict) else None
    items = data if isinstance(data, list) else data.get("findings", [] if health else [data])
    if not all(isinstance(i, dict) and i.get("finding_id") for i in items):
        raise HTTPException(422, "Every item needs a finding_id")
    if health is not None and not isinstance(health, dict):
        raise HTTPException(422, "health must be an object")
    for i in items:
        i["domain"] = domain.value
    n = get_store().upsert_webhook(domain.value, items, org=org_name) if items else 0
    get_store().set_webhook_health(domain.value, health, org=org_name)
    get_store().audit("webhook", "ingest", {"domain": domain.value, "items": n, "org": org_name})
    return JSONResponse({"accepted": n}, status_code=202)
