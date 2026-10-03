"""IBM QRadar SIEM (on-premises or QRadar SIEM SaaS) - read-only, through the QRadar REST API.

Two modes:
  aql (default)   an Ariel (AQL) search: POST /api/ariel/searches?query_expression=..., poll
                  GET /api/ariel/searches/{id} until COMPLETED, then GET .../results with a Range header.
                  Use it to pull any control domain QRadar already receives (EDR, firewall, proxy, e-mail ...).
  offenses        GET /api/siem/offenses with a filter (default: status="OPEN") - QRadar's incidents, for the
                  SOC domain. Snapshot: an offense that is no longer returned has been closed.

Permission: an authorised service token (Admin > Authorized Services) for a user role that can run searches
and view offenses; no write capability is needed or used.

settings:
  base_url: https://qradar.example            console URL (no /api)
  token: ${QRADAR_TOKEN}                      sent as the SEC header
  mode: aql | offenses
  aql: "SELECT ... FROM events WHERE starttime > {since_ms} ... LAST {lookback_days} DAYS"
  offense_filter: status="OPEN"               offenses mode only
  offense_fields: "id,description,magnitude,severity,status,offense_source,categories,start_time,last_updated_time"
  max_rows: 10000                             Range: items=0-(max_rows-1)
  poll_seconds: 2, timeout_seconds: 300       AQL search polling
  api_version: "20.0"                         optional Version header
  ca_bundle: path                             private CA; TLS verification cannot be disabled
  cursor_column: starttime                    epoch milliseconds; incremental when the AQL uses {since_ms}
  health_aql: optional AQL returning one row with coverage_pct and numeric KPIs
  field_map / severity_map / status_map / finding_type: as for every SIEM adapter
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import Adapter, AdapterResult, http_client, request_with_retry
from .file_drop import parse_dt
from .siem import flatten, newest, siem_result

DONE, FAILED = "COMPLETED", ("CANCELED", "ERROR")


class QRadarAdapter(Adapter):
    name = "qradar"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            incremental = settings.get("mode", "aql") == "aql" and "{since_ms}" in settings.get("aql", "")
            self.sync_mode = "incremental" if incremental else "snapshot"

    # ------------------------------------------------------------------ HTTP
    def _headers(self, range_items: int | None = None) -> dict[str, str]:
        h = {"SEC": self.settings["token"], "Accept": "application/json"}
        if self.settings.get("api_version"):
            h["Version"] = str(self.settings["api_version"])
        if range_items:
            h["Range"] = f"items=0-{range_items - 1}"
        return h

    def _url(self, path: str) -> str:
        return f"{self.settings['base_url'].rstrip('/')}/api/{path.lstrip('/')}"

    def run_aql(self, c, aql: str) -> list[dict[str, Any]]:
        """Run one AQL search to completion and return its rows (events or flows)."""
        r = request_with_retry(c, "POST", self._url("ariel/searches"), params={"query_expression": aql},
                               headers=self._headers())
        sid = r.json()["search_id"]
        deadline = time.monotonic() + float(self.settings.get("timeout_seconds", 300))
        poll = float(self.settings.get("poll_seconds", 2))
        while True:
            st = request_with_retry(c, "GET", self._url(f"ariel/searches/{sid}"), headers=self._headers()).json()
            status = str(st.get("status", "")).upper()
            if status == DONE:
                break
            if status in FAILED:
                raise RuntimeError(f"QRadar search {sid} ended {status}: {st.get('error_messages') or ''}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"QRadar search {sid} still {status} after {self.settings.get('timeout_seconds', 300)} s")
            time.sleep(poll)
        res = request_with_retry(c, "GET", self._url(f"ariel/searches/{sid}/results"),
                                 headers=self._headers(int(self.settings.get("max_rows", 10000)))).json()
        rows = next((v for v in res.values() if isinstance(v, list)), []) if isinstance(res, dict) else res
        return [flatten(r) for r in rows]

    def offenses(self, c) -> list[dict[str, Any]]:
        params = {"filter": self.settings.get("offense_filter", 'status="OPEN"')}
        if self.settings.get("offense_fields"):
            params["fields"] = self.settings["offense_fields"]
        r = request_with_retry(c, "GET", self._url("siem/offenses"), params=params,
                               headers=self._headers(int(self.settings.get("max_rows", 10000))))
        return [flatten(o) for o in r.json()]

    # ------------------------------------------------------------------ fetch
    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "token")
        mode = self.settings.get("mode", "aql")
        lookback = int(self.settings.get("lookback_days", 7))
        since = parse_dt(self.cursor) if self.cursor else datetime.now(timezone.utc) - timedelta(days=lookback)
        with http_client(180, verify=self.settings.get("ca_bundle") or True) as c:
            if mode == "offenses":
                rows = self.offenses(c)
            elif mode == "aql":
                self.require("aql")
                aql = self.settings["aql"].replace("{since_ms}", str(int(since.timestamp() * 1000))) \
                    .replace("{lookback_days}", str(lookback))
                rows = self.run_aql(c, aql)
            else:
                raise ValueError("qradar: mode must be aql or offenses")
            hrow = self.run_aql(c, self.settings["health_aql"])[:1] if self.settings.get("health_aql") else []
        cursor = self.cursor
        if self.sync_mode == "incremental":
            t = newest(rows, self.settings.get("cursor_column", "starttime"))
            cursor = t.isoformat() if t else self.cursor
        return siem_result(self, rows, hrow[0] if hrow else None, cursor, "QRadar")
