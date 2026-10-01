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
            out[slug(org)] = r
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
    items = data if isinstance(data, list) else data.get("findings", [data])
    if not all(isinstance(i, dict) and i.get("finding_id") for i in items):
        raise HTTPException(422, "Every item needs a finding_id")
    for i in items:
        i["domain"] = domain.value
    n = get_store().upsert_webhook(domain.value, items)
    get_store().audit("webhook", "ingest", {"domain": domain.value, "items": n})
    return JSONResponse({"accepted": n}, status_code=202)
