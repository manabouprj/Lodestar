"""Push-based ingestion: products / SOAR POST to `/api/ingest/{domain}` (HMAC-signed).

Body: a list of findings, or {"findings": [...], "health": {...}}. Findings are upserted
(keyed by finding_id, so re-sends update rather than duplicate) and read on every run.
The optional `health` block lets a product report control health without a pull API:
  {"coverage_pct": 97.5, "policy_drift_items": 2, "health_issues": ["..."], "kpis": {"vaulted_pct": 91}}
Data freshness is the time since the last webhook of any kind for that domain.
settings: retention_days (30), health (static fallback, same shape as above)
"""
from __future__ import annotations

from datetime import datetime, timezone

from ....models import ControlHealth, Finding
from .base import Adapter, AdapterResult


class WebhookInboxAdapter(Adapter):
    name = "webhook"

    def fetch(self, ctx) -> AdapterResult:
        if ctx.store is None:
            return AdapterResult(warnings=["webhook adapter requires a store"])
        items = ctx.store.webhook_findings(self.domain.value, retention_days=int(self.settings.get("retention_days", 30)))
        findings, warnings = [], []
        for raw in items:
            try:
                raw.setdefault("domain", self.domain.value)
                findings.append(Finding.model_validate(raw))
            except Exception as exc:  # reject bad payloads, keep the rest
                warnings.append(f"rejected webhook payload: {exc}")
        last, pushed = ctx.store.webhook_health(self.domain.value)
        if last is None and not findings:
            return AdapterResult(warnings=warnings + ["no webhook received yet for this domain"])
        h = {**(self.settings.get("health") or {}), **pushed}
        issues = list(h.get("health_issues", []))
        if "coverage_pct" not in h:
            issues.append("Coverage not reported - push a health block or set settings.health.coverage_pct")
        age = (datetime.now(timezone.utc) - last).total_seconds() / 3600 if last else 999.0
        health = ControlHealth(domain=self.domain, product=self.product, coverage_pct=float(h.get("coverage_pct", 100.0)),
                               data_freshness_hours=round(age, 1), policy_drift_items=int(h.get("policy_drift_items", 0)),
                               health_issues=issues, kpis=h.get("kpis", {}))
        return AdapterResult(findings=findings, health=health, warnings=warnings)
