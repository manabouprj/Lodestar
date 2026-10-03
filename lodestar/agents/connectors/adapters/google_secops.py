"""Google Security Operations (Chronicle) SIEM - read-only UDM search through the Chronicle API (preview).

Request: GET {base_url}/v1alpha/projects/{project}/locations/{location}/instances/{instance}:udmSearch
         with query, timeRange.startTime, timeRange.endTime and limit. The response's events[].udm documents
         are flattened to dotted keys (metadata.eventTimestamp, principal.hostname, security_result.severity ...).
         The API accepts a time range of at most 90 days.
Authentication: a Google Cloud service account (JSON key) with a role that can run UDM searches on the
         instance; LODESTAR signs a JWT with the key and exchanges it for an access token (OAuth 2.0 JWT bearer).

Status: built to the published Chronicle API and covered by contract tests on its documented response
shape; the regional endpoint and API version differ per tenant, so confirm them with
`lodestar test-connector <domain>` in the first week.

settings:
  base_url: https://<region>-chronicle.googleapis.com     your tenant's regional Chronicle API endpoint
  api_version: v1alpha
  project: my-gcp-project            location: us            instance: <SecOps customer id (GUID)>
  service_account_secret: ${GOOGLE_SECOPS_SA_JSON}         the JSON key content (never a literal in YAML)
  query: 'metadata.event_type = "NETWORK_CONNECTION" AND security_result.action = "BLOCK"'
  lookback_days: 7 (max 90)          limit: 1000
  cursor_column: metadata.eventTimestamp                    incremental by default
  field_map / severity_map / status_map / finding_type
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from .base import Adapter, AdapterResult, http_client, request_with_retry
from .file_drop import parse_dt
from .siem import flatten, newest, siem_result

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
MAX_DAYS = 90


def google_token(c, sa: dict[str, Any], scope: str = SCOPE) -> str:
    """OAuth 2.0 JWT-bearer grant for a service account key."""
    now = int(time.time())
    token_uri = sa.get("token_uri", "https://oauth2.googleapis.com/token")
    assertion = jwt.encode({"iss": sa["client_email"], "scope": scope, "aud": token_uri, "iat": now, "exp": now + 3600},
                           sa["private_key"], algorithm="RS256", headers={"kid": sa.get("private_key_id")})
    r = request_with_retry(c, "POST", token_uri, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                       "assertion": assertion})
    return r.json()["access_token"]


class GoogleSecOpsAdapter(Adapter):
    name = "google_secops"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            self.sync_mode = "incremental"

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "project", "location", "instance", "service_account_secret", "query")
        sa = self.settings["service_account_secret"]
        sa = json.loads(sa) if isinstance(sa, str) else sa
        lookback = min(int(self.settings.get("lookback_days", 7)), MAX_DAYS)
        now = datetime.now(timezone.utc)
        start = parse_dt(self.cursor) if self.cursor else now - timedelta(days=lookback)
        start = max(start, now - timedelta(days=MAX_DAYS))
        s = self.settings
        url = (f"{s['base_url'].rstrip('/')}/{s.get('api_version', 'v1alpha')}/projects/{s['project']}/locations/"
               f"{s['location']}/instances/{s['instance']}:udmSearch")
        params = {"query": s["query"], "timeRange.startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "timeRange.endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "limit": int(s.get("limit", 1000))}
        with http_client(180) as c:
            token = google_token(c, sa)
            data = request_with_retry(c, "GET", url, params=params, headers={"Authorization": f"Bearer {token}"}).json()
        rows = [{**flatten(e.get("udm") or {}), "name": e.get("name")} for e in data.get("events") or []]
        warn = ["more events matched than the limit - narrow the query or raise limit"] if data.get("moreDataAvailable") else []
        cursor = self.cursor
        if self.sync_mode == "incremental":
            t = newest(rows, s.get("cursor_column", "metadata.eventTimestamp"))
            cursor = (t + timedelta(milliseconds=1)).isoformat() if t else self.cursor
        res = siem_result(self, rows, None, cursor, "Google SecOps")
        res.warnings = warn + res.warnings
        return res
