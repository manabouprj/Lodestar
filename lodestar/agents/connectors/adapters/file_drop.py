"""Universal adapter: ingest JSON / CSV exports dropped into a folder.

Works for ANY product that can export or forward findings (scheduled report,
SIEM search export, SOAR playbook output, S3/Blob/SFTP sync). A field_map
converts vendor column names into the LODESTAR schema, so new products need YAML only.

Snapshot semantics: by default only the NEWEST file (or newest per `pattern`)
is read and it is treated as the complete current set - so an item missing from
two consecutive exports is resolved. Set `latest_only: false` to merge all files.
An empty / missing folder is reported as "no data" and never resolves anything.

settings:
  path: data/drop/edr              # folder to read
  pattern: "*.csv"                 # optional glob (default *.csv and *.json)
  latest_only: true                # read only the newest matching file
  field_map: {title: AlertName, severity: Severity, asset_id: Hostname, ...}
  severity_map: {"5": critical, "4": high, ...}   # optional
  status_map: {"Closed": resolved, "New": open}   # optional
  finding_type: detection                          # default type
  evidence_fields: [rule, category]                # extra columns copied into evidence
  health: {coverage_pct: 97.5}                     # optional static KPIs
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ....models import ControlHealth, Domain, Finding, FindingType, Severity, Status
from .base import Adapter, AdapterResult

_SEV_DEFAULT = {
    "critical": "critical", "crit": "critical", "very high": "critical", "5": "critical", "sev1": "critical",
    "high": "high", "4": "high", "sev2": "high", "medium": "medium", "moderate": "medium", "3": "medium", "sev3": "medium",
    "low": "low", "2": "low", "informational": "info", "info": "info", "1": "info", "0": "info", "none": "info",
}
_STATUS_DEFAULT = {
    "open": "open", "new": "open", "active": "open", "reopened": "open", "detected": "open", "unresolved": "open",
    "in progress": "in_progress", "in_progress": "in_progress", "investigating": "in_progress", "inprogress": "in_progress",
    "resolved": "resolved", "closed": "resolved", "fixed": "resolved", "remediated": "resolved", "dismissed": "false_positive",
    "false positive": "false_positive", "false_positive": "false_positive", "benign": "false_positive",
}


def parse_dt(v):
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
    s = str(v).strip().replace("Z", "+00:00")
    for cand in (s, s.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(cand)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except ValueError:
        return None


def map_rows(rows: Iterable[dict[str, Any]], *, domain: Domain, product: str, settings: dict[str, Any],
             id_prefix: str = "") -> tuple[list[Finding], list[str]]:
    """Map vendor rows to Findings with field_map / severity_map / status_map. Shared by file_drop and SIEM adapters."""
    fmap = settings.get("field_map") or {}
    smap = {**_SEV_DEFAULT, **{str(k).lower(): v for k, v in (settings.get("severity_map") or {}).items()}}
    stmap = {**_STATUS_DEFAULT, **{str(k).lower(): v for k, v in (settings.get("status_map") or {}).items()}}
    ftype_default = str(settings.get("finding_type", "detection")).lower()
    if ftype_default not in {t.value for t in FindingType}:
        raise ValueError(f"settings.finding_type '{ftype_default}' is not valid - use one of "
                         f"{', '.join(t.value for t in FindingType)}")
    extra = settings.get("evidence_fields") or []
    findings, warnings = [], []
    now = datetime.now(timezone.utc)
    for row in rows:
        def get(key, default=None, _r=row):
            v = _r.get(fmap.get(key, key), default)
            return default if v in ("", None) else v
        sev_raw = str(get("severity", "medium")).strip().lower()
        sev = smap.get(sev_raw)
        if sev is None:
            try:                                         # numeric scores such as CVSS 9.8 or 0-100 risk
                n = float(sev_raw)
                sev = "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low"
                if n > 10:
                    sev = "critical" if n >= 90 else "high" if n >= 70 else "medium" if n >= 40 else "low"
            except ValueError:
                warnings.append(f"unknown severity '{sev_raw}' defaulted to medium")
                sev = "medium"
        st_raw = str(get("status", "open")).strip().lower()
        status = stmap.get(st_raw, "open")
        title = str(get("title") or "Untitled finding")
        asset = get("asset_id")
        user = get("user_id")
        fid = get("finding_id") or hashlib.sha1(f"{domain.value}|{title}|{asset}|{user}|{get('cve')}".encode()).hexdigest()[:16]
        first = parse_dt(get("first_seen")) or now
        last = parse_dt(get("last_seen")) or first
        ev: dict[str, Any] = {k: row.get(k) for k in extra if row.get(k) not in (None, "")}
        for key in ("ioc", "ip", "device_id", "mac"):
            if get(key):
                ev[key] = get(key)
        try:
            ftype = FindingType(str(get("finding_type") or ftype_default).lower())
        except ValueError:
            ftype = FindingType(ftype_default)
        findings.append(Finding(
            finding_id=f"{id_prefix or domain.value}-{fid}", domain=domain, source=product,
            finding_type=ftype, title=title[:300], description=str(get("description", "") or "")[:2000],
            severity=Severity(sev), status=Status(status), asset_id=str(asset) if asset else None,
            user_id=str(user) if user else None, app_id=str(get("app_id")) if get("app_id") else None,
            cve=str(get("cve")).split(",")[0].strip().upper() if get("cve") else None,
            first_seen=first, last_seen=last, remediation=str(get("remediation", "") or "")[:1000], evidence=ev))
    # collapse repeated warnings
    uniq = sorted(set(warnings))
    return findings, [f"{w} ({warnings.count(w)}x)" if warnings.count(w) > 1 else w for w in uniq]


class FileDropAdapter(Adapter):
    name = "file_drop"
    sync_mode = "snapshot"

    def _files(self, folder: Path) -> list[Path]:
        pats = [self.settings["pattern"]] if self.settings.get("pattern") else ["*.csv", "*.json"]
        files = sorted({p for pat in pats for p in folder.glob(pat) if p.is_file()}, key=lambda p: p.stat().st_mtime)
        if self.settings.get("latest_only", True) and files:
            return [files[-1]]
        return files

    @staticmethod
    def _read(p: Path):
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            return data if isinstance(data, list) else data.get("items") or data.get("value") or data.get("results") or [data]
        with p.open(newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def fetch(self, ctx) -> AdapterResult:
        self.require("path")
        folder = Path(self.settings["path"])
        if not folder.is_absolute():
            folder = ctx.settings.path(folder)
        if not folder.exists():
            return AdapterResult(warnings=[f"drop folder not found: {folder}"])
        files = self._files(folder)
        if not files:
            return AdapterResult(warnings=[f"no export files in {folder}"])
        rows = [r for p in files for r in self._read(p)]
        findings, warnings = map_rows(rows, domain=self.domain, product=self.product, settings=self.settings)
        newest = max(datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc) for p in files)
        h = self.settings.get("health") or {}
        fresh = (datetime.now(timezone.utc) - newest).total_seconds() / 3600
        issues = [] if "coverage_pct" in h else ["Coverage not reported - set settings.health.coverage_pct"]
        health = ControlHealth(domain=self.domain, product=self.product, coverage_pct=float(h.get("coverage_pct", 100.0)),
                               data_freshness_hours=round(fresh, 1), policy_drift_items=int(h.get("policy_drift_items", 0)),
                               health_issues=issues, kpis=h.get("kpis", {}))
        return AdapterResult(findings=findings, health=health,
                             warnings=warnings + [f"read {', '.join(p.name for p in files[-3:])}"])
