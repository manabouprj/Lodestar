"""Push-based ingestion: products/SOAR POST normalised findings to
`/api/ingest/{domain}` (HMAC-signed). Payloads are upserted into the store
(keyed by finding_id, so re-sends update rather than duplicate) and this adapter
reads the current, non-expired set on every pipeline run."""
from __future__ import annotations

from ....models import Finding
from .base import Adapter, AdapterResult


class WebhookInboxAdapter(Adapter):
    name = "webhook"

    def fetch(self, ctx) -> AdapterResult:
        if ctx.store is None:
            return AdapterResult(warnings=["webhook adapter requires a store"])
        items = ctx.store.webhook_findings(self.domain.value, retention_days=int(self.settings.get("retention_days", 30)))
        findings = []
        warnings = []
        for raw in items:
            try:
                raw.setdefault("domain", self.domain.value)
                findings.append(Finding.model_validate(raw))
            except Exception as exc:  # reject bad payloads, keep the rest
                warnings.append(f"rejected webhook payload: {exc}")
        return AdapterResult(findings=findings, warnings=warnings)
