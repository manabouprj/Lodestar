"""Platform configuration loader.

* YAML file (default config/lodestar.yaml, override with LODESTAR_CONFIG)
* `${ENV_VAR}` references are resolved at load time
* Secrets must NEVER be literal in YAML: any key containing secret/password/
  token/api_key/client_secret must be an env reference, otherwise load fails.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Domain
from .scoring import ScoringConfig

ROOT = Path(__file__).resolve().parent.parent
ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
SECRET_KEY_RE = re.compile(r"(secret|password|token|api_key|apikey|access_key|private_key|webhook_url|workflow_url)", re.I)


class ConfigError(ValueError):
    pass


def _resolve_env(value: Any, path: str = "") -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            child = f"{path}.{k}" if path else str(k)
            if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and v and not ENV_RE.fullmatch(v.strip()):
                raise ConfigError(
                    f"Literal secret found at '{child}'. Use an environment reference like ${{MY_SECRET}}."
                )
            out[k] = _resolve_env(v, child)
        return out
    if isinstance(value, list):
        return [_resolve_env(v, path) for v in value]
    if isinstance(value, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    return value


@dataclass
class ConnectorConfig:
    domain: Domain
    enabled: bool = True
    adapter: str = "mock"
    product: str = ""
    settings: dict[str, Any] = field(default_factory=dict)
    # several sources for one domain (e.g. threat_intel: TAXII + MISP + CSAF + mailbox)
    sources: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Settings:
    org_name: str
    vertical: str
    mode: str
    deployment_phase: int
    sqlite_path: Path
    demo_dataset: Path | None
    assets_path: Path | None
    reports_dir: Path
    connectors: dict[Domain, ConnectorConfig]
    scoring: ScoringConfig
    llm: dict[str, Any]
    itsm: dict[str, Any]
    raw: dict[str, Any]
    chatops: dict[str, Any] = field(default_factory=dict)

    def path(self, p: str | Path) -> Path:
        p = Path(p)
        return p if p.is_absolute() else ROOT / p


def load_settings(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    cfg_path = Path(path or os.environ.get("LODESTAR_CONFIG", ROOT / "config" / "lodestar.yaml"))
    if not cfg_path.is_absolute():
        cfg_path = ROOT / cfg_path
    if not cfg_path.exists():
        raise ConfigError(f"Config file not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    for k, v in (overrides or {}).items():
        raw[k] = v
    raw = _resolve_env(raw)

    org = raw.get("org", {})
    mode = raw.get("mode", "demo")
    if mode not in {"demo", "live"}:
        raise ConfigError("mode must be 'demo' or 'live'")
    phase = int(raw.get("deployment_phase", 1))
    if phase not in range(0, 5):
        raise ConfigError("deployment_phase must be 0-4")

    connectors: dict[Domain, ConnectorConfig] = {}
    for key, c in (raw.get("connectors") or {}).items():
        try:
            d = Domain(key)
        except ValueError as exc:
            raise ConfigError(f"Unknown connector domain '{key}'") from exc
        c = c or {}
        connectors[d] = ConnectorConfig(
            domain=d, enabled=bool(c.get("enabled", True)), adapter=c.get("adapter", "mock"),
            product=c.get("product", ""), settings=c.get("settings") or {},
            sources=[{"adapter": x.get("adapter", "mock"), "product": x.get("product", ""), "settings": x.get("settings") or {}}
                     for x in (c.get("sources") or [])],
        )

    sc = raw.get("scoring") or {}
    scoring = ScoringConfig(**{k: v for k, v in sc.items() if k in ScoringConfig.__dataclass_fields__})
    scoring.validate()

    def opt_path(v: str | None) -> Path | None:
        if not v:
            return None
        p = Path(v)
        return p if p.is_absolute() else ROOT / p

    return Settings(
        org_name=org.get("name", "Unnamed Org"),
        vertical=org.get("vertical", "_default"),
        mode=mode,
        deployment_phase=phase,
        sqlite_path=opt_path((raw.get("storage") or {}).get("sqlite_path", "data/lodestar.db")),
        demo_dataset=opt_path((raw.get("demo") or {}).get("dataset")),
        assets_path=opt_path((raw.get("assets") or {}).get("path")),
        reports_dir=opt_path((raw.get("reporting") or {}).get("output_dir", "reports")),
        connectors=connectors,
        scoring=scoring,
        llm=raw.get("llm") or {"provider": "none"},
        itsm=raw.get("itsm") or {"provider": "none", "dry_run": True},
        raw=raw,
        chatops=raw.get("chatops") or {},
    )
