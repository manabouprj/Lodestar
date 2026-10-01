"""SIEM-first adapters: pull ANY control domain from the SIEM you already feed.

Most enterprises already forward EDR, identity, e-mail, firewall, proxy, WAF and cloud alerts to
Microsoft Sentinel or Splunk. Querying the SIEM turns ~20 product integrations into 1-2, which
is what makes a 1-2 day onboarding realistic. Each connector domain gets its own query and a
field_map (same mapping engine as file_drop). Ready-made queries: config/templates/catalog.yaml.

sentinel (Azure Monitor Logs query API, read-only):
  permission: Azure RBAC "Log Analytics Reader" (or "Microsoft Sentinel Reader") on the workspace
  settings: workspace_id, tenant_id, client_id, client_secret, query (KQL), field_map, finding_type,
            severity_map, status_map, lookback_days (7), cursor_column (TimeGenerated), health_query (optional)
  placeholders in query: {since} (ISO datetime: cursor or now-lookback), {lookback_days}
splunk (REST search export, read-only):
  permission: a role with search on the relevant indexes + an authentication token
  settings: base_url (https://splunk.example:8089), token, search (SPL), field_map, ..., earliest (-7d),
            ca_bundle (path; TLS verification cannot be disabled), health_search (optional)
  placeholders: {since_epoch}
Sync mode is incremental when the query uses {since}/{since_epoch} (cursor = newest event time),
otherwise snapshot (the query returns the complete current set, e.g. open incidents).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ....models import ControlHealth
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .file_drop import map_rows, parse_dt
from .ms_graph_security import get_token

LA_SCOPE = "https://api.loganalytics.io/.default"


def _kpis_from_row(row: dict[str, Any] | None) -> tuple[float | None, dict[str, Any]]:
    if not row:
        return None, {}
    cov = row.get("coverage_pct")
    kpis = {k: v for k, v in row.items() if isinstance(v, (int, float)) and k != "coverage_pct"}
    return (float(cov) if cov is not None else None), kpis


class SentinelQueryAdapter(Adapter):
    name = "sentinel"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            self.sync_mode = "incremental" if "{since}" in settings.get("query", "") else "snapshot"

    def _query(self, c, token: str, kql: str, timespan_days: int) -> list[dict[str, Any]]:
        base = self.settings.get("endpoint", "https://api.loganalytics.io").rstrip("/")
        r = request_with_retry(c, "POST", f"{base}/v1/workspaces/{self.settings['workspace_id']}/query",
                               json={"query": kql, "timespan": f"P{max(1, timespan_days)}D"},
                               headers={"Authorization": f"Bearer {token}"})
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"Log Analytics error: {data['error'].get('message')}")
        tables = data.get("tables") or []
        if not tables:
            return []
        cols = [col["name"] for col in tables[0]["columns"]]
        return [dict(zip(cols, row, strict=False)) for row in tables[0]["rows"]]

    def fetch(self, ctx) -> AdapterResult:
        self.require("workspace_id", "tenant_id", "client_id", "client_secret", "query")
        lookback = int(self.settings.get("lookback_days", 7))
        since = parse_dt(self.cursor) if self.cursor else datetime.now(timezone.utc) - timedelta(days=lookback)
        kql = self.settings["query"].replace("{since}", since.strftime("%Y-%m-%dT%H:%M:%SZ")).replace("{lookback_days}", str(lookback))
        span = max(lookback, (datetime.now(timezone.utc) - since).days + 1)
        with http_client(120) as c:
            token = get_token(c, self.settings["tenant_id"], self.settings["client_id"], self.settings["client_secret"], scope=LA_SCOPE)
            rows = self._query(c, token, kql, span)
            hrow = self._query(c, token, self.settings["health_query"], lookback)[:1] if self.settings.get("health_query") else []
        findings, warnings = map_rows(rows, domain=self.domain, product=self.product, settings=self.settings)
        col = self.settings.get("cursor_column", "TimeGenerated")
        times = [parse_dt(r.get(col)) for r in rows if r.get(col)]
        cursor = max(times).isoformat() if times and self.sync_mode == "incremental" else self.cursor
        cov, kpis = _kpis_from_row(hrow[0] if hrow else None)
        static = self.settings.get("health") or {}
        cov = cov if cov is not None else static.get("coverage_pct")
        health = ControlHealth(domain=self.domain, product=self.product, coverage_pct=float(cov if cov is not None else 100.0),
                               data_freshness_hours=0.0, kpis={**static.get("kpis", {}), **kpis},
                               health_issues=[] if cov is not None else ["Coverage not reported - add a health_query or health.coverage_pct"])
        return AdapterResult(findings=findings, health=health, warnings=warnings + [f"{len(rows)} rows from Sentinel"], cursor=cursor)


class SplunkSearchAdapter(Adapter):
    name = "splunk"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            self.sync_mode = "incremental" if "{since_epoch}" in settings.get("search", "") else "snapshot"

    def _search(self, c, spl: str, earliest: str) -> list[dict[str, Any]]:
        spl = spl.strip()
        if not spl.startswith(("search ", "|")):
            spl = "search " + spl
        r = request_with_retry(c, "POST", f"{self.settings['base_url'].rstrip('/')}/services/search/jobs/export",
                               data={"search": spl, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"},
                               headers={"Authorization": f"Bearer {self.settings['token']}"})
        out = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("result") is not None:
                out.append(obj["result"])
        return out

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "token", "search")
        lookback = int(self.settings.get("lookback_days", 7))
        since = float(self.cursor) if self.cursor else (datetime.now(timezone.utc) - timedelta(days=lookback)).timestamp()
        spl = self.settings["search"].replace("{since_epoch}", str(int(since)))
        earliest = self.settings.get("earliest", f"-{lookback}d")
        with http_client(180, verify=self.settings.get("ca_bundle") or True) as c:
            rows = self._search(c, spl, earliest)
            hrow = self._search(c, self.settings["health_search"], earliest)[:1] if self.settings.get("health_search") else []
        findings, warnings = map_rows(rows, domain=self.domain, product=self.product, settings=self.settings)
        times = [t for t in (_epoch(r.get("_time")) for r in rows) if t is not None]
        cursor = str(max(times)) if times and self.sync_mode == "incremental" else self.cursor
        hr = {k: _num(v) for k, v in (hrow[0] if hrow else {}).items()}
        cov, kpis = _kpis_from_row(hr if hrow else None)
        static = self.settings.get("health") or {}
        cov = cov if cov is not None else static.get("coverage_pct")
        health = ControlHealth(domain=self.domain, product=self.product, coverage_pct=float(cov if cov is not None else 100.0),
                               data_freshness_hours=0.0, kpis={**static.get("kpis", {}), **kpis},
                               health_issues=[] if cov is not None else ["Coverage not reported - add a health_search or health.coverage_pct"])
        return AdapterResult(findings=findings, health=health, warnings=warnings + [f"{len(rows)} results from Splunk"], cursor=cursor)


def _epoch(v) -> float | None:
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        d = parse_dt(v)
        return d.timestamp() if d else None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return v
