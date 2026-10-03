"""Elastic Security / Elasticsearch, OpenSearch and the Wazuh indexer - read-only search APIs.

Two query styles (pick one per connector):
  esql    ES|QL through POST /_query (Elasticsearch 8.14 or later). Placeholders: {since} (ISO time),
          {lookback_days}. The response columns become the row fields.
  index + dsl   Query DSL through POST /<index>/_search - works on any Elasticsearch version, on OpenSearch
          and on the Wazuh indexer (wazuh-alerts-*). `dsl` is the "query" object (YAML or JSON) with {since}
          placeholders; hits' _source documents are flattened to dotted keys (kibana.alert.rule.name ...).

Authentication: api_key (Elastic "encoded" API key, sent as "Authorization: ApiKey <key>") or
username + password (basic; usual for OpenSearch and Wazuh). Use a role with read on the indices only.

settings:
  base_url: https://es.example:9200
  api_key: ${ELASTIC_API_KEY}            or  username / password: ${ELASTIC_PASSWORD}
  esql: "FROM .alerts-security.alerts-default | WHERE @timestamp > \\"{since}\\" | KEEP ... | LIMIT 5000"
  index: ".alerts-security.alerts-*"     with dsl: {bool: {filter: [{range: {"@timestamp": {gte: "{since}"}}}]}}
  sort: "@timestamp:desc"                 dsl only
  max_rows: 5000                          dsl size (Elasticsearch caps a single page at 10,000)
  cursor_column: "@timestamp"             incremental when the query uses {since}
  health_esql: optional ES|QL returning one row with coverage_pct and numeric KPIs
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


def _fill(obj: Any, subs: dict[str, str]) -> Any:
    if isinstance(obj, str):
        for k, v in subs.items():
            obj = obj.replace("{" + k + "}", v)
        return obj
    if isinstance(obj, dict):
        return {k: _fill(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, subs) for v in obj]
    return obj


class ElasticAdapter(Adapter):
    name = "elastic"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            q = settings.get("esql") or json.dumps(settings.get("dsl") or "")
            self.sync_mode = "incremental" if "{since}" in q else "snapshot"

    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.settings.get("api_key"):
            h["Authorization"] = f"ApiKey {self.settings['api_key']}"
        elif self.settings.get("username"):
            raw = f"{self.settings['username']}:{self.settings.get('password', '')}".encode()
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        else:
            raise ValueError("elastic: set api_key, or username and password")
        return h

    def esql(self, c, query: str) -> list[dict[str, Any]]:
        r = request_with_retry(c, "POST", f"{self.settings['base_url'].rstrip('/')}/_query", params={"format": "json"},
                               json={"query": query}, headers=self.headers())
        data = r.json()
        cols = [col["name"] for col in data.get("columns") or []]
        return [dict(zip(cols, row, strict=False)) for row in data.get("values") or []]

    def search(self, c, index: str, query: Any, size: int, sort: str | None, source: list[str] | None = None) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"query": query, "size": size, "track_total_hits": False}
        if sort:
            field, _, order = sort.partition(":")
            body["sort"] = [{field: {"order": order or "desc", "unmapped_type": "date"}}]
        if source:
            body["_source"] = source
        r = request_with_retry(c, "POST", f"{self.settings['base_url'].rstrip('/')}/{index}/_search",
                               json=body, headers=self.headers())
        hits = ((r.json().get("hits") or {}).get("hits")) or []
        return [{**flatten(h.get("_source") or {}), "_id": h.get("_id"), "_index": h.get("_index")} for h in hits]

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url")
        lookback = int(self.settings.get("lookback_days", 7))
        since = parse_dt(self.cursor) if self.cursor else datetime.now(timezone.utc) - timedelta(days=lookback)
        subs = {"since": since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z", "lookback_days": str(lookback)}
        with http_client(180, verify=self.settings.get("ca_bundle") or True) as c:
            if self.settings.get("esql"):
                rows = self.esql(c, _fill(self.settings["esql"], subs))
            elif self.settings.get("index"):
                dsl = self.settings.get("dsl") or {"match_all": {}}
                if isinstance(dsl, str):
                    dsl = json.loads(dsl)
                rows = self.search(c, self.settings["index"], _fill(dsl, subs), int(self.settings.get("max_rows", 5000)),
                                   self.settings.get("sort", "@timestamp:desc"))
            else:
                raise ValueError("elastic: set esql, or index (+ dsl)")
            hrow = self.esql(c, _fill(self.settings["health_esql"], subs))[:1] if self.settings.get("health_esql") else []
        cursor = self.cursor
        if self.sync_mode == "incremental":
            t = newest(rows, self.settings.get("cursor_column", "@timestamp"))
            cursor = t.isoformat() if t else self.cursor
        return siem_result(self, rows, hrow[0] if hrow else None, cursor, "Elastic")
