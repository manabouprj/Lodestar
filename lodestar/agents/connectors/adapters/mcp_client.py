"""MCP client adapter - ingest from a vendor's Model Context Protocol server (remote, streamable HTTP).

More security vendors now ship an MCP server next to (or instead of) a REST API. This adapter connects to
one, calls ONE read-only tool you name with the arguments you give, and maps the JSON it returns exactly
like the generic REST adapter (field_map / severity_map / status_map). No code per vendor.

Read-only by construction:
  * only the tool named in settings.tool is ever called, with the arguments in settings.arguments;
  * the tool must exist on the server and must NOT be annotated destructiveHint=true or readOnlyHint=false
    (LODESTAR refuses, whatever the configuration says);
  * a tool without annotations is called with a warning, unless require_read_only_annotation: true;
  * TLS verification stays on (ca_bundle for a private CA); credentials only from environment references.

settings:
  url: https://mcp.vendor.example/mcp                  the server's streamable-HTTP endpoint
  auth: {type: bearer, token: ${VENDOR_MCP_TOKEN}}     | header | basic | oauth2 (same as http_json) | none
  tool: list_alerts
  arguments: {since: "{since}", status: open, limit: 500}   placeholders {since} {since_epoch} {since_ms}
  records: alerts                    dotted path into the tool's structured result ("" = the result is the list)
  cursor_column: created_at          incremental when a placeholder is used
  require_read_only_annotation: false
  timeout_seconds: 120   ca_bundle: path   lookback_days: 7
  field_map / severity_map / status_map / finding_type
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import AdapterResult, http_client
from .file_drop import parse_dt
from .http_json import HttpJsonAdapter, _fill, _get
from .siem import flatten, newest, siem_result

PLACEHOLDERS = ("{since}", "{since_epoch}", "{since_ms}")


def _run(coro):
    """Run a coroutine from sync code, also when the caller already runs an event loop (API / MCP server)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: dict[str, Any] = {}

    def target():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as exc:  # re-raised in the caller's thread
            box["e"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box["v"]


class McpClientAdapter(HttpJsonAdapter):
    name = "mcp"

    def __init__(self, domain, product, settings):
        super().__init__(domain, product, settings)
        if "sync_mode" not in settings:
            blob = json.dumps(settings.get("arguments") or {})
            self.sync_mode = "incremental" if any(p in blob for p in PLACEHOLDERS) else "snapshot"

    def _target(self, headers: dict[str, str]):
        """Transport for mcp.Client: a URL over streamable HTTP (tests substitute an in-process server)."""
        import httpx2
        from mcp.client.streamable_http import streamable_http_client
        http = httpx2.AsyncClient(headers=headers, timeout=float(self.settings.get("timeout_seconds", 120)),
                                  verify=self.settings.get("ca_bundle") or True, trust_env=True)
        return streamable_http_client(self.settings["url"], http_client=http), http

    async def _call(self, headers: dict[str, str], tool: str, args: dict[str, Any]) -> tuple[Any, list[str]]:
        try:
            return await self._call_inner(headers, tool, args)
        except BaseExceptionGroup as eg:          # the client's task group wraps errors raised inside it
            leaf = eg
            while isinstance(leaf, BaseExceptionGroup) and len(leaf.exceptions) == 1:
                leaf = leaf.exceptions[0]
            raise leaf if not isinstance(leaf, BaseExceptionGroup) else RuntimeError(str(eg)) from None

    async def _call_inner(self, headers: dict[str, str], tool: str, args: dict[str, Any]) -> tuple[Any, list[str]]:
        from mcp import Client
        target, http = self._target(headers)
        warnings: list[str] = []
        try:
            async with Client(target) as client:
                tools = {t.name: t for t in (await client.list_tools()).tools}
                if tool not in tools:
                    raise ValueError(f"mcp: tool '{tool}' not offered by the server (has: {sorted(tools)[:20]})")
                ann = tools[tool].annotations
                if ann is not None and (ann.destructive_hint is True or ann.read_only_hint is False):
                    raise PermissionError(f"mcp: tool '{tool}' is not read-only (annotations) - LODESTAR adapters "
                                          "never call tools that can change the source")
                if ann is None or ann.read_only_hint is None:
                    if self.settings.get("require_read_only_annotation"):
                        raise PermissionError(f"mcp: tool '{tool}' is not annotated readOnlyHint=true")
                    warnings.append(f"tool '{tool}' has no readOnlyHint annotation - confirm with the vendor it is read-only")
                r = await client.call_tool(tool, args)
        finally:
            if http is not None:
                await http.aclose()
        if r.is_error:
            text = " ".join(getattr(c, "text", "") for c in r.content)[:300]
            raise RuntimeError(f"mcp: tool '{tool}' returned an error: {text}")
        if r.structured_content is not None:
            return r.structured_content, warnings
        texts = [getattr(c, "text", None) for c in r.content if getattr(c, "text", None)]
        for t in texts:
            try:
                return json.loads(t), warnings
            except ValueError:
                continue
        raise ValueError(f"mcp: tool '{tool}' returned no JSON (structured content or JSON text)")

    def fetch(self, ctx) -> AdapterResult:
        self.require("url", "tool")
        lookback = int(self.settings.get("lookback_days", 7))
        since = parse_dt(self.cursor) if self.cursor else datetime.now(timezone.utc) - timedelta(days=lookback)
        subs = {"{since}": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "{since_epoch}": str(int(since.timestamp())),
                "{since_ms}": str(int(since.timestamp() * 1000))}
        args = _fill(self.settings.get("arguments") or {}, subs)
        with http_client(60, verify=self.settings.get("ca_bundle") or True) as c:   # token exchange (oauth2) only
            headers = self._auth(c)
        data, warnings = _run(self._call(headers, str(self.settings["tool"]), args))
        path = self.settings.get("records", "")
        if isinstance(data, dict) and not path and isinstance(data.get("result"), list):
            path = "result"                        # list results are wrapped as {"result": [...]}
        items = _get(data, path)
        items = items if isinstance(items, list) else []
        rows = [flatten(i) if isinstance(i, dict) else {"value": i} for i in items]
        cursor = self.cursor
        if self.sync_mode == "incremental":
            t = newest(rows, self.settings.get("cursor_column", "timestamp"))
            cursor = t.isoformat() if t else self.cursor
        res = siem_result(self, rows, None, cursor, f"MCP tool {self.settings['tool']}")
        res.warnings = warnings + res.warnings
        return res
