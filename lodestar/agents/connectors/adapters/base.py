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


class Adapter:
    """Subclass and implement `fetch`. Adapters must be READ-ONLY."""

    name = "base"
    supported_domains: tuple[Domain, ...] = tuple(Domain)

    def __init__(self, domain: Domain, product: str, settings: dict[str, Any]):
        if domain not in self.supported_domains:
            raise ValueError(f"Adapter '{self.name}' does not support domain '{domain.value}'")
        self.domain = domain
        self.product = product or self.name
        self.settings = settings

    def fetch(self, ctx) -> AdapterResult:  # pragma: no cover
        raise NotImplementedError

    def require(self, *keys: str) -> None:
        missing = [k for k in keys if not self.settings.get(k)]
        if missing:
            raise ValueError(f"{self.name}: missing settings {missing} (set via env references in config)")


def http_client(timeout: float = 30.0) -> httpx.Client:
    # trust_env=True honours HTTPS_PROXY / corporate CA via SSL_CERT_FILE; TLS verification is always on.
    return httpx.Client(timeout=timeout, trust_env=True, headers={"User-Agent": "LODESTAR/1.0 (read-only)"})


def request_with_retry(client: httpx.Client, method: str, url: str, retries: int = 4, **kw) -> httpx.Response:
    """Retry on 429/5xx with exponential back-off, honouring Retry-After."""
    delay = 2.0
    for attempt in range(retries + 1):
        resp = client.request(method, url, **kw)
        if resp.status_code not in (429, 500, 502, 503, 504) or attempt == retries:
            resp.raise_for_status()
            return resp
        wait = float(resp.headers.get("Retry-After", delay))
        time.sleep(min(wait, 60))
        delay *= 2
    raise RuntimeError("unreachable")
