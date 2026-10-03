"""Sumo Logic (Log Analytics and Cloud SIEM log data) - read-only, through the Search Job API.

Flow: POST /api/v1/search/jobs {query, from, to, timeZone} -> poll GET /api/v1/search/jobs/{id} until
"DONE GATHERING RESULTS" -> page GET .../messages (raw results) or .../records (aggregate results, when the
query ends in count / sum / ...) -> DELETE the job, so the 200 concurrent-job limit is never reached.
The HTTP client keeps cookies between calls, which the search-job session requires.

Authentication: an access ID and key (Basic) for a user whose role can run searches on the relevant data.

settings:
  base_url: https://api.<deployment>.sumologic.com      (e.g. api.eu.sumologic.com, api.us2.sumologic.com)
  access_id: ${SUMO_ACCESS_ID}
  access_key: ${SUMO_ACCESS_KEY}
  query: '_sourceCategory=security/edr severity=high'
  results: messages | records          (default messages)
  lookback_days: 7                     the search window starts at the cursor (messages) or now - lookback
  max_rows: 10000                      per run (the API pages 10,000 at a time; 100,000 messages per search)
  poll_seconds: 5, timeout_seconds: 600
  cursor_column: _messagetime          epoch milliseconds; messages are incremental by default
  health_query: optional aggregate query returning one record with coverage_pct and numeric KPIs
  field_map / severity_map / status_map / finding_type
"""
from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import Adapter, AdapterResult, http_client, request_with_retry
from .file_drop import parse_dt
from .siem import siem_result

DONE, FAILED = "DONE GATHERING RESULTS", ("CANCELLED", "CANCELED", "FORCE PAUSED")
PAGE = 10_000


class SumoLogicAdapter(Adapter):
    name = "sumologic"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            self.sync_mode = "incremental" if settings.get("results", "messages") == "messages" else "snapshot"

    def _headers(self) -> dict[str, str]:
        raw = f"{self.settings['access_id']}:{self.settings['access_key']}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode(), "Content-Type": "application/json",
                "Accept": "application/json"}

    def search(self, c, query: str, start: datetime, end: datetime, kind: str, limit: int) -> list[dict[str, Any]]:
        base = f"{self.settings['base_url'].rstrip('/')}/api/v1/search/jobs"
        body = {"query": query, "from": start.strftime("%Y-%m-%dT%H:%M:%S"), "to": end.strftime("%Y-%m-%dT%H:%M:%S"),
                "timeZone": "UTC"}
        r = request_with_retry(c, "POST", base, json=body, headers=self._headers())
        jid = r.json().get("id") or r.headers.get("Location", "").rstrip("/").rsplit("/", 1)[-1]
        if not jid:
            raise RuntimeError("Sumo Logic did not return a search job id")
        try:
            deadline = time.monotonic() + float(self.settings.get("timeout_seconds", 600))
            poll = float(self.settings.get("poll_seconds", 5))
            while True:
                st = request_with_retry(c, "GET", f"{base}/{jid}", headers=self._headers()).json()
                state = str(st.get("state", "")).upper()
                if state == DONE:
                    break
                if state in FAILED:
                    raise RuntimeError(f"Sumo Logic search job {jid} ended {state}")
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Sumo Logic search job {jid} still {state}")
                time.sleep(poll)
            total = int(st.get("messageCount" if kind == "messages" else "recordCount", 0))
            rows: list[dict[str, Any]] = []
            offset = 0
            while offset < min(total, limit):
                page = request_with_retry(c, "GET", f"{base}/{jid}/{kind}", headers=self._headers(),
                                          params={"offset": offset, "limit": min(PAGE, limit - offset)}).json()
                items = page.get(kind) or []
                if not items:
                    break
                rows += [dict(i.get("map") or {}) for i in items]
                offset += len(items)
            return rows
        finally:
            try:                                   # free the job slot; failure here never fails the run
                c.request("DELETE", f"{base}/{jid}", headers=self._headers())
            except Exception:
                pass

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "access_id", "access_key", "query")
        lookback = int(self.settings.get("lookback_days", 7))
        now = datetime.now(timezone.utc)
        start = parse_dt(self.cursor) if self.cursor else now - timedelta(days=lookback)
        kind = self.settings.get("results", "messages")
        if kind not in ("messages", "records"):
            raise ValueError("sumologic: results must be messages or records")
        limit = int(self.settings.get("max_rows", PAGE))
        with http_client(120) as c:
            rows = self.search(c, self.settings["query"], start, now, kind, limit)
            hrow = self.search(c, self.settings["health_query"], now - timedelta(days=lookback), now, "records", 1) \
                if self.settings.get("health_query") else []
        cursor = self.cursor
        if self.sync_mode == "incremental":
            col = self.settings.get("cursor_column", "_messagetime")
            ts = [float(r[col]) for r in rows if str(r.get(col, "")).replace(".", "", 1).isdigit()]
            if ts:
                cursor = datetime.fromtimestamp(max(ts) / 1000 + 0.001, tz=timezone.utc).isoformat()
        return siem_result(self, rows, hrow[0] if hrow else None, cursor, "Sumo Logic")
