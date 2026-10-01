"""Universal adapter: ingest JSON / CSV exports dropped into a folder.

Works for ANY product that can export or forward findings (scheduled report,
SIEM search export, SOAR playbook output, S3/Blob sync). A field_map converts
vendor column names into the LODESTAR schema, so new products need YAML only.

settings:
  path: data/drop/edr              # folder to read
  field_map: {title: AlertName, severity: Severity, asset_id: Hostname, ...}
  severity_map: {"5": critical, "4": high, ...}   # optional
  finding_type: detection                          # default type
  health: {coverage_pct: 97.5}                     # optional static KPIs
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ....models import ControlHealth, Finding, FindingType, Severity
from .base import Adapter, AdapterResult

_SEV_DEFAULT = {
    "critical": "critical", "crit": "critical", "very high": "critical", "5": "critical",
    "high": "high", "4": "high", "medium": "medium", "moderate": "medium", "3": "medium",
    "low": "low", "2": "low", "informational": "info", "info": "info", "1": "info", "0": "info",
}


def _parse_dt(v):
    if not v:
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    s = str(v).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class FileDropAdapter(Adapter):
    name = "file_drop"

    def _rows(self, folder: Path):
        for p in sorted(folder.glob("*")):
            if p.suffix.lower() == ".json":
                data = json.loads(p.read_text(encoding="utf-8"))
                rows = data if isinstance(data, list) else data.get("items") or data.get("value") or [data]
                yield from ((p, r) for r in rows)
            elif p.suffix.lower() == ".csv":
                with p.open(newline="", encoding="utf-8-sig") as fh:
                    yield from ((p, r) for r in csv.DictReader(fh))

    def fetch(self, ctx) -> AdapterResult:
        self.require("path")
        folder = Path(self.settings["path"])
        if not folder.is_absolute():
            folder = ctx.settings.path(folder)
        if not folder.exists():
            return AdapterResult(warnings=[f"drop folder not found: {folder}"])
        fmap = self.settings.get("field_map") or {}
        smap = {**_SEV_DEFAULT, **{str(k).lower(): v for k, v in (self.settings.get("severity_map") or {}).items()}}
        ftype = FindingType(self.settings.get("finding_type", "detection"))

        findings, warnings, newest = [], [], None
        for path, row in self._rows(folder):
            get = lambda key, default=None, _r=row: _r.get(fmap.get(key, key), default)  # noqa: E731
            sev_raw = str(get("severity", "medium")).strip().lower()
            sev = smap.get(sev_raw)
            if sev is None:
                warnings.append(f"{path.name}: unknown severity '{sev_raw}', defaulted to medium")
                sev = "medium"
            title = get("title") or "Untitled finding"
            fid = get("finding_id") or hashlib.sha1(
                f"{self.domain.value}|{title}|{get('asset_id')}|{get('user_id')}".encode()).hexdigest()[:16]
            first = _parse_dt(get("first_seen")) or datetime.now(timezone.utc)
            last = _parse_dt(get("last_seen")) or first
            newest = max(newest, last) if newest else last
            findings.append(Finding(
                finding_id=f"{self.domain.value}-{fid}", domain=self.domain, source=self.product,
                finding_type=FindingType(get("finding_type") or ftype.value), title=str(title),
                description=str(get("description", "") or ""), severity=Severity(sev),
                asset_id=get("asset_id"), user_id=get("user_id"), app_id=get("app_id"),
                cve=get("cve"), first_seen=first, last_seen=last, remediation=str(get("remediation", "") or ""),
            ))
        h = self.settings.get("health") or {}
        fresh = (datetime.now(timezone.utc) - newest).total_seconds() / 3600 if newest else 999.0
        health = ControlHealth(domain=self.domain, product=self.product,
                               coverage_pct=float(h.get("coverage_pct", 0)), data_freshness_hours=round(fresh, 1),
                               policy_drift_items=int(h.get("policy_drift_items", 0)), kpis=h.get("kpis", {}))
        return AdapterResult(findings=findings, health=health, warnings=warnings)
