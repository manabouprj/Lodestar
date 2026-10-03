"""Generic REST / JSON adapter - any SIEM or security product with a read API that returns JSON.

For platforms without a dedicated adapter (LogRhythm, Exabeam, Securonix, FortiSIEM, Rapid7 InsightIDR,
OpenText ArcSight, CrowdStrike Falcon Next-Gen SIEM, Datadog, Graylog ...), point this adapter at the
product's search, incident or alert endpoint and map the fields. No code needed.

settings:
  url: https://siem.example/api/v1/alerts
  method: GET | POST                       (default GET)
  params: {status: open, since: "{since}"}  query parameters; placeholders {since} (ISO) {since_epoch} {since_ms}
  body: {...}                              JSON body for POST, same placeholders
  auth: {type: bearer, token: ${SIEM_TOKEN}, scheme: Bearer}
        | {type: header, name: X-Api-Key, token: ${SIEM_KEY}}
        | {type: basic, username: svc-lodestar, password: ${SIEM_PASSWORD}}
        | {type: oauth2, endpoint: https://idp.example/token, client_id: ..., client_secret: ${SIEM_SECRET}, scope: ...}
  records: data.items                      dotted path to the list in the response ("" = the body is the list)
  paginate: {type: link} | {type: next_field, path: links.next} | {type: none}
  max_pages: 20
  cursor_column: createdAt                 incremental when a placeholder is used
  ca_bundle: path
  field_map / severity_map / status_map / finding_type
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import Adapter, AdapterResult, http_client, request_with_retry
from .file_drop import parse_dt
from .siem import flatten, newest, siem_result

PLACEHOLDERS = ("{since}", "{since_epoch}", "{since_ms}")


def _get(d: Any, path: str) -> Any:
    if not path:
        return d
    for part in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


def _fill(obj: Any, subs: dict[str, str]) -> Any:
    if isinstance(obj, str):
        for k, v in subs.items():
            obj = obj.replace(k, v)
        return obj
    if isinstance(obj, dict):
        return {k: _fill(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, subs) for v in obj]
    return obj


class HttpJsonAdapter(Adapter):
    name = "http_json"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            blob = json.dumps({"p": settings.get("params"), "b": settings.get("body"), "u": settings.get("url")})
            self.sync_mode = "incremental" if any(p in blob for p in PLACEHOLDERS) else "snapshot"

    def _auth(self, c) -> dict[str, str]:
        a = self.settings.get("auth") or {"type": "none"}
        kind = str(a.get("type", "none")).lower()
        if kind == "bearer":
            return {"Authorization": f"{a.get('scheme', 'Bearer')} {a['token']}"}
        if kind == "header":
            return {a["name"]: str(a["token"])}
        if kind == "basic":
            return {"Authorization": "Basic " + base64.b64encode(f"{a['username']}:{a.get('password', '')}".encode()).decode()}
        if kind == "oauth2":
            r = request_with_retry(c, "POST", a["endpoint"], data={"grant_type": "client_credentials", "client_id": a["client_id"],
                                                                   "client_secret": a["client_secret"], "scope": a.get("scope", "")})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}
        if kind == "none":
            return {}
        raise ValueError(f"http_json: unknown auth type {kind!r}")

    def fetch(self, ctx) -> AdapterResult:
        self.require("url")
        lookback = int(self.settings.get("lookback_days", 7))
        since = parse_dt(self.cursor) if self.cursor else datetime.now(timezone.utc) - timedelta(days=lookback)
        subs = {"{since}": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "{since_epoch}": str(int(since.timestamp())),
                "{since_ms}": str(int(since.timestamp() * 1000))}
        method = str(self.settings.get("method", "GET")).upper()
        pag = self.settings.get("paginate") or {"type": "none"}
        pag = {"type": pag} if isinstance(pag, str) else pag
        rows: list[dict[str, Any]] = []
        with http_client(120, verify=self.settings.get("ca_bundle") or True) as c:
            headers = {"Accept": "application/json", **self._auth(c)}
            url: str | None = _fill(self.settings["url"], subs)
            params = _fill(self.settings.get("params") or {}, subs)
            body = _fill(self.settings.get("body"), subs)
            pages = 0
            while url and pages < int(self.settings.get("max_pages", 20)):
                r = request_with_retry(c, method, url, params=params if pages == 0 else None,
                                       json=body if method != "GET" else None, headers=headers)
                data = r.json()
                items = _get(data, self.settings.get("records", ""))
                items = items if isinstance(items, list) else []
                rows += [flatten(i) if isinstance(i, dict) else {"value": i} for i in items]
                pages += 1
                kind = pag.get("type", "none")
                if kind == "link":
                    nxt = r.links.get("next", {}).get("url")
                elif kind == "next_field":
                    nxt = _get(data, pag.get("path", "next"))
                else:
                    nxt = None
                url = str(nxt) if nxt and str(nxt) != url else None
        cursor = self.cursor
        if self.sync_mode == "incremental":
            t = newest(rows, self.settings.get("cursor_column", "timestamp"))
            cursor = t.isoformat() if t else self.cursor
        return siem_result(self, rows, None, cursor, "REST API")
