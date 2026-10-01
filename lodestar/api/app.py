"""LODESTAR REST API + dashboard.

Run:  python -m lodestar serve   (or: uvicorn lodestar.api.app:app)

Auth
  * API keys with roles via env  LODESTAR_API_KEYS="ciso:<key>,analyst:<key>,exec:<key>"
  * header  X-API-Key: <key>   or the HttpOnly cookie set by POST /login
  * enforced when security.require_auth=true or mode=live
  * for SSO, front the service with your identity-aware proxy (Entra App Proxy,
    Cloudflare Access, oauth2-proxy) - see docs/DEPLOYMENT_PHASES.md
Roles
  exec     dashboard, reports, KRIs
  analyst  + priorities, findings, controls, attack paths, approve actions
  ciso     + run pipeline, audit log, agent catalogue
Webhook ingestion (POST /api/ingest/{domain}) is authenticated with an
HMAC-SHA256 signature (header X-Lodestar-Signature: sha256=<hex>) using
LODESTAR_WEBHOOK_SECRET, not with API keys.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from functools import lru_cache
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .. import __version__
from ..config import Settings, load_settings
from ..dashboard import build_payload
from ..itsm import submit
from ..models import Domain, Horizon, PipelineResult, Status
from ..reporting import render
from ..store import Store
from ..web import render_dashboard, slug

ROLE_RANK = {"exec": 1, "analyst": 2, "ciso": 3}
MAX_INGEST_BYTES = 5 * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


@lru_cache(maxsize=1)
def get_store() -> Store:
    return Store(get_settings().sqlite_path)


def _keys() -> dict[str, str]:
    out = {}
    for pair in filter(None, (os.environ.get("LODESTAR_API_KEYS", "")).split(",")):
        role, _, key = pair.partition(":")
        if role.strip() in ROLE_RANK and len(key.strip()) >= 16:
            out[key.strip()] = role.strip()
    return out


def _auth_required(s: Settings) -> bool:
    return bool((s.raw.get("security") or {}).get("require_auth")) or s.mode == "live"


def role_of(request: Request) -> str:
    s = get_settings()
    if not _auth_required(s):
        return "ciso"
    supplied = request.headers.get("X-API-Key") or request.cookies.get("lodestar_key") or ""
    for key, role in _keys().items():
        if secrets.compare_digest(key, supplied):
            return role
    raise HTTPException(status_code=401, detail="Missing or invalid API key")


def need(min_role: str):
    def dep(request: Request) -> str:
        role = role_of(request)
        if ROLE_RANK[role] < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail=f"Requires role '{min_role}'")
        return role
    return dep


app = FastAPI(title="LODESTAR", version=__version__,
              description="Security posture intelligence & prioritisation agents")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
                            "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; "
                            "connect-src 'self'; frame-ancestors 'none'")
    return resp


def _results(store: Store) -> dict[str, PipelineResult]:
    out = {}
    for org in store.list_orgs():
        r = store.latest_result(org)
        if r:
            from ..decisions import overlay
            out[slug(org)] = overlay(store, r)
    return out


def _result(store: Store, org: Optional[str]) -> PipelineResult:
    res = _results(store)
    if not res:
        raise HTTPException(404, "No pipeline results yet - run `python -m lodestar run`")
    if org:
        if org not in res:
            raise HTTPException(404, f"Unknown org '{org}'. Known: {sorted(res)}")
        return res[org]
    return next(iter(res.values()))


# ---------------------------------------------------------------- public
@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"


@app.post("/login")
def login(key: str = Form(...)):
    if key not in _keys():
        raise HTTPException(401, "Invalid key")
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("lodestar_key", key, httponly=True, samesite="strict", secure=True, max_age=8 * 3600)
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return ("<!doctype html><title>LODESTAR sign in</title><form method=post style='font:16px sans-serif;max-width:360px;"
            "margin:15vh auto;display:grid;gap:8px'><label for=k>API key</label><input id=k name=key type=password "
            "autocomplete=current-password required><button>Sign in</button></form>")


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    s = get_settings()
    try:
        role_of(request)
    except HTTPException:
        return RedirectResponse("/login")
    res = _results(get_store())
    payloads = [build_payload(r) for r in res.values()]
    return render_dashboard(payloads, demo=s.mode == "demo", api=True)


@app.get("/api/orgs")
def orgs(role: str = Depends(need("exec"))):
    return [{"key": k, "org": r.org_name, "vertical": r.vertical, "generated_at": r.generated_at}
            for k, r in _results(get_store()).items()]


@app.get("/api/dashboard")
def dashboard_data(org: Optional[str] = None, role: str = Depends(need("exec"))):
    return build_payload(_result(get_store(), org))


@app.get("/api/kris")
def kris(org: Optional[str] = None, role: str = Depends(need("exec"))):
    return build_payload(_result(get_store(), org))["kris"]


@app.get("/api/priorities")
def priorities(org: Optional[str] = None, horizon: Horizon = Horizon.TODAY, domain: Optional[Domain] = None,
               team: Optional[str] = None, limit: int = Query(100, le=1000), role: str = Depends(need("analyst"))):
    r = _result(get_store(), org)
    rows = [f for f in r.findings if f.status in (Status.OPEN, Status.IN_PROGRESS) and f.horizon == horizon
            and (domain is None or f.domain == domain) and (team is None or f.owner_team == team)]
    return [f.model_dump(mode="json") for f in rows[:limit]]


@app.get("/api/findings/{finding_id}")
def finding(finding_id: str, org: Optional[str] = None, role: str = Depends(need("analyst"))):
    r = _result(get_store(), org)
    for f in r.findings:
        if f.finding_id == finding_id:
            return f.model_dump(mode="json")
    raise HTTPException(404, "Finding not found")


@app.get("/api/attack-paths")
def attack_paths(org: Optional[str] = None, role: str = Depends(need("analyst"))):
    return [c.model_dump(mode="json") for c in _result(get_store(), org).correlations]


@app.get("/api/controls")
def controls(org: Optional[str] = None, role: str = Depends(need("analyst"))):
    return [c.model_dump(mode="json") for c in _result(get_store(), org).controls]


@app.get("/api/compliance")
def compliance(org: Optional[str] = None, role: str = Depends(need("exec"))):
    return _result(get_store(), org).compliance


@app.get("/api/reports/{period}")
def report(period: str, org: Optional[str] = None, format: str = Query("html", pattern="^(html|md|json)$"),
           role: str = Depends(need("exec"))):
    if period not in ("weekly", "monthly", "quarterly"):
        raise HTTPException(400, "period must be weekly, monthly or quarterly")
    body = render(_result(get_store(), org), period, format, get_settings().llm)
    media = {"html": "text/html", "md": "text/markdown", "json": "application/json"}[format]
    return Response(content=body, media_type=media)


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, org: Optional[str] = None, role: str = Depends(need("analyst"))):
    r = _result(get_store(), org)
    action = next((a for a in r.actions if a["action_id"] == action_id), None)
    if not action:
        raise HTTPException(404, "Action not found")
    outcome = submit(action, get_settings().itsm)
    get_store().audit(role, "action_approved", {"action_id": action_id, "org": r.org_name, "itsm": outcome.get("submitted")})
    return {"action_id": action_id, "approved_by_role": role, **outcome}


@app.get("/api/decisions")
def decisions(org: Optional[str] = None, status: Optional[str] = "pending", role: str = Depends(need("exec"))):
    r = _result(get_store(), org)
    return [d for d in r.decisions if status in (None, "all") or d["status"] == status]


@app.post("/api/decisions/{decision_id}")
async def decide(decision_id: str, request: Request, org: Optional[str] = None, role: str = Depends(need("analyst"))):
    from ..decisions import DecisionError, record
    body = await request.json()
    try:
        return record(get_store(), _result(get_store(), org), decision_id, str(body.get("choice", "")), role,
                      note=str(body.get("note", "")), channel="dashboard", itsm_cfg=get_settings().itsm)
    except DecisionError as exc:
        raise HTTPException(exc.code, str(exc)) from exc


# ---------------------------------------------------------------- chat (dashboard, Slack, Teams)
def _chat(org: Optional[str] = None):
    from ..chatops import ChatEngine
    s = get_settings()
    return ChatEngine(_result(get_store(), org), (s.chatops or {}).get("dashboard_url"))


def _recorder(org: Optional[str], channel: str, actor: str):
    from ..decisions import record

    def rec(decision_id: str, choice: str, role: str):
        return record(get_store(), _result(get_store(), org), decision_id, choice, role, channel=channel,
                      actor=actor, itsm_cfg=get_settings().itsm)
    return rec


@app.post("/api/chat/ask")
async def chat_ask(request: Request, org: Optional[str] = None, role: str = Depends(need("exec"))):
    body = await request.json()
    reply = _chat(org).handle(str(body.get("text", ""))[:500], role, _recorder(org, "dashboard-chat", role))
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
    reply = _chat().handle(form.get("text", ""), role, _recorder(None, "slack", user))
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
    reply = _chat().handle(f"decide {val.get('d', '')} {val.get('c', '')}", slack.role_for(user, cfg),
                           _recorder(None, "slack", user))
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
    reply = _chat().handle(text, slack.role_for(user, cfg), _recorder(None, "slack", user))
    # answer asynchronously - Slack requires the HTTP ack within 3 seconds
    asyncio.get_running_loop().run_in_executor(None, lambda: slack.post(reply, cfg, ev.get("channel")))
    return {"ok": True}


@app.post("/api/chat/teams/messages")
async def teams_message(request: Request):
    from ..chatops import teams
    cfg = (get_settings().chatops or {}).get("teams") or {}
    body = await request.body()
    if not teams.verify(cfg.get("outgoing_webhook_token", ""), body, request.headers.get("Authorization", "")):
        raise HTTPException(401, "Invalid Teams signature")
    act = json.loads(body)
    who = (act.get("from") or {}).get("aadObjectId", "")
    reply = _chat().handle(teams.strip_mention(act.get("text", "")), teams.role_for(who, cfg),
                           _recorder(None, "teams", who))
    return teams.activity(reply)


@app.post("/api/run")
def run_pipeline(role: str = Depends(need("ciso"))):
    from ..orchestrator import Orchestrator
    res = Orchestrator(get_settings(), store=get_store()).run()
    get_store().audit(role, "pipeline_run", {"org": res.org_name, "findings": len(res.findings)})
    return {"org": res.org_name, "posture": res.snapshot.posture_score, "today": res.snapshot.open_by_horizon.get("today")}


@app.get("/api/audit")
def audit(limit: int = Query(200, le=2000), role: str = Depends(need("ciso"))):
    return get_store().recent_audit(limit)


@app.get("/api/agents")
def agents(role: str = Depends(need("exec"))):
    from ..catalog import agent_catalog
    return agent_catalog()


# ---------------------------------------------------------------- webhook ingest
def verify_signature(body: bytes, header: str, secret: str) -> bool:
    if not secret or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.split("=", 1)[1])


@app.post("/api/ingest/hackerone")
async def ingest_hackerone(request: Request):
    """HackerOne programme webhooks (report_created, report_triaged, report_severity_updated, bounty_awarded ...).
    Signature: X-H1-Signature: sha256=<hex HMAC-SHA256 of body> with the webhook secret (LODESTAR_H1_WEBHOOK_SECRET)."""
    from ..agents.connectors.adapters.hackerone import map_report
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(413, "Payload too large")
    if not verify_signature(body, request.headers.get("X-H1-Signature", ""), os.environ.get("LODESTAR_H1_WEBHOOK_SECRET", "")):
        raise HTTPException(401, "Invalid or missing signature")
    data = json.loads(body)
    report = ((data.get("data") or {}).get("report")) or data.get("report")
    if not report or not report.get("id"):
        return JSONResponse({"accepted": 0, "ignored": "event without report"}, status_code=202)
    f = map_report(report)
    n = get_store().upsert_webhook("bug_bounty", [json.loads(f.model_dump_json())])
    get_store().audit("webhook:hackerone", "ingest", {"event": request.headers.get("X-H1-Event"), "report": report.get("id")})
    return JSONResponse({"accepted": n}, status_code=202)


@app.post("/api/ingest/{domain}")
async def ingest(domain: Domain, request: Request):
    body = await request.body()
    if len(body) > MAX_INGEST_BYTES:
        raise HTTPException(413, "Payload too large")
    if not verify_signature(body, request.headers.get("X-Lodestar-Signature", ""),
                            os.environ.get("LODESTAR_WEBHOOK_SECRET", "")):
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
    n = get_store().upsert_webhook(domain.value, items) if items else 0
    get_store().set_webhook_health(domain.value, health)
    get_store().audit("webhook", "ingest", {"domain": domain.value, "items": n})
    return JSONResponse({"accepted": n}, status_code=202)
