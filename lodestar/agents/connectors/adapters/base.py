"""Adapter contract: translate one vendor/product API into LODESTAR models."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from ....models import ControlHealth, Domain, Finding


@dataclass
class AdapterResult:
    findings: list[Finding] = field(default_factory=list)
    health: Optional[ControlHealth] = None
    warnings: list[str] = field(default_factory=list)
    cursor: Optional[str] = None        # new sync position (incremental adapters); stored only after success


class Adapter:
    """Subclass and implement `fetch`. Adapters must be READ-ONLY."""

    name = "base"
    supported_domains: tuple[Domain, ...] = tuple(Domain)
    # snapshot    = every successful fetch returns the complete current set; absence means fixed
    # incremental = fetch returns only new/changed items since `self.cursor`; absence means "no change"
    sync_mode = "snapshot"
    cursor: Optional[str] = None

    def __init__(self, domain: Domain, product: str, settings: dict[str, Any]):
        if domain not in self.supported_domains:
            raise ValueError(f"Adapter '{self.name}' does not support domain '{domain.value}'")
        self.domain = domain
        self.product = product or self.name
        self.settings = settings
        if settings.get("sync_mode") in ("snapshot", "incremental"):
            self.sync_mode = settings["sync_mode"]

    def fetch(self, ctx) -> AdapterResult:  # pragma: no cover
        raise NotImplementedError

    def require(self, *keys: str) -> None:
        missing = [k for k in keys if not self.settings.get(k)]
        if missing:
            raise ValueError(f"{self.name}: missing settings {missing} (set via env references in config)")


_TRANSPORT: httpx.BaseTransport | None = None     # tests inject httpx.MockTransport with recorded vendor responses


def set_transport(transport: httpx.BaseTransport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = transport


def http_client(timeout: float = 30.0, verify: bool | str = True) -> httpx.Client:
    """trust_env=True honours HTTPS_PROXY and SSL_CERT_FILE (corporate CA). TLS verification is always on;
    `verify` may point to a CA bundle (e.g. Splunk's own CA) but can never be False."""
    if verify is False:
        raise ValueError("Disabling TLS verification is not allowed; provide a CA bundle path instead")
    kw = {"transport": _TRANSPORT} if _TRANSPORT is not None else {}
    return httpx.Client(timeout=timeout, trust_env=True, verify=verify,
                        headers={"User-Agent": "LODESTAR/2.0 (read-only)"}, **kw)


def request_with_retry(client: httpx.Client, method: str, url: str, retries: int = 4, **kw) -> httpx.Response:
    """Retry on 429/5xx with exponential back-off, honouring Retry-After."""
    delay = 2.0
    for attempt in range(retries + 1):
        try:
            resp = client.request(method, url, **kw)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
            if attempt == retries:
                raise
            time.sleep(min(delay, 60))
            delay *= 2
            continue
        if resp.status_code not in (429, 500, 502, 503, 504) or attempt == retries:
            resp.raise_for_status()
            return resp
        wait = float(resp.headers.get("Retry-After", delay))
        time.sleep(min(wait, 60))
        delay *= 2
    raise RuntimeError("unreachable")
