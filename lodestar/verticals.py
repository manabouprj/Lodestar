"""Industry vertical profiles.

A vertical is pure configuration (config/verticals/<id>.yaml). Adding a new
industry = adding one YAML file; no code changes. Profiles inherit from
`_default.yaml` and may append KRIs via `kris_extra`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .models import Domain

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "config" / "verticals"


@dataclass
class VerticalProfile:
    id: str
    name: str
    description: str
    frameworks: list[str]
    regulators: list[str]
    mandatory_domains: list[str]
    domain_weights: dict[str, float]
    sla_days: dict[str, int]
    financial_exposure: dict[str, Any]
    threat_landscape: list[str]
    kris: list[dict[str, Any]]
    crown_jewel_services: list[str]
    terminology: dict[str, str] = field(default_factory=dict)
    sectors: list[str] = field(default_factory=list)          # STIX industry-sector vocabulary, for intel matching
    critical_infrastructure: bool = False
    incident_reporting: dict[str, Any] = field(default_factory=dict)  # authority, hours

    def weight(self, domain: Domain | str) -> float:
        key = domain.value if isinstance(domain, Domain) else domain
        return float(self.domain_weights.get(key, 1.0))

    def sla(self, severity: str) -> int:
        return int(self.sla_days.get(severity, 120))

    def label(self, key: str, default: str) -> str:
        return self.terminology.get(key, default)


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k == "kris_extra":
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            merged = dict(out[k])
            merged.update(v)
            out[k] = merged
        else:
            out[k] = v
    extra = override.get("kris_extra") or []
    if extra:
        existing = {k["metric"] for k in out.get("kris", [])}
        out["kris"] = list(out.get("kris", [])) + [k for k in extra if k["metric"] not in existing]
    return out


def _load_raw(vertical_id: str, directory: Path) -> dict:
    path = directory / f"{vertical_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Vertical profile not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = data.get("inherits")
    if parent:
        return _merge(_load_raw(parent, directory), data)
    return data


@lru_cache(maxsize=64)
def load_vertical(vertical_id: str, directory: str | None = None) -> VerticalProfile:
    d = Path(directory) if directory else DEFAULT_DIR
    raw = _load_raw(vertical_id, d)
    valid_domains = {x.value for x in Domain}
    unknown = [k for k in (raw.get("domain_weights") or {}) if k not in valid_domains]
    unknown += [k for k in (raw.get("mandatory_domains") or []) if k not in valid_domains]
    if unknown:
        raise ValueError(f"Vertical '{vertical_id}' references unknown domains: {unknown}")
    return VerticalProfile(
        id=raw.get("id", vertical_id),
        name=raw["name"],
        description=raw.get("description", ""),
        frameworks=raw.get("frameworks", []),
        regulators=raw.get("regulators", []),
        mandatory_domains=raw.get("mandatory_domains", []),
        domain_weights={k: float(v) for k, v in (raw.get("domain_weights") or {}).items()},
        sla_days=raw.get("sla_days", {}),
        financial_exposure=raw.get("financial_exposure", {}),
        threat_landscape=raw.get("threat_landscape", []),
        kris=raw.get("kris", []),
        crown_jewel_services=raw.get("crown_jewel_services", []),
        terminology=raw.get("terminology") or {},
        sectors=[s.lower() for s in raw.get("sectors", [])],
        critical_infrastructure=bool(raw.get("critical_infrastructure", False)),
        incident_reporting=raw.get("incident_reporting") or {},
    )


def list_verticals(directory: str | None = None) -> list[str]:
    d = Path(directory) if directory else DEFAULT_DIR
    return sorted(p.stem for p in d.glob("*.yaml") if not p.stem.startswith("_"))
