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
    interval_minutes: int = 0          # minimum minutes between fetches (0 = every pipeline run)


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

    @property
    def org_key(self) -> str:
        """URL-safe tenant key (?org=...), derived from org.name."""
        return slugify(self.org_name)


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")


def deep_merge(base: dict[str, Any], over: dict[str, Any], replace: tuple[str, ...] = ()) -> dict[str, Any]:
    out = dict(base)
    for k, v in (over or {}).items():
        if k in replace or not (isinstance(v, dict) and isinstance(out.get(k), dict)):
            out[k] = v
        else:
            out[k] = deep_merge(out[k], v)
    return out


def load_dotenv(path: Path | None = None) -> int:
    """Load KEY=VALUE pairs from .env (repo root) without overriding variables already set.
    Lets Windows / local runs use the same .env file as docker compose. Returns number loaded."""
    p = path or (ROOT / ".env")
    if os.environ.get("LODESTAR_NO_DOTENV") or not p.exists():
        return 0
    n = 0
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip().removeprefix("export ").strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        if key and key not in os.environ and val != "":
            os.environ[key] = val
            n += 1
    return n


def config_path(path: str | Path | None = None) -> Path:
    cfg_path = Path(path or os.environ.get("LODESTAR_CONFIG", ROOT / "config" / "lodestar.yaml"))
    return cfg_path if cfg_path.is_absolute() else ROOT / cfg_path


def read_raw(path: str | Path | None = None) -> dict[str, Any]:
    cfg_path = config_path(path)
    if not cfg_path.exists():
        raise ConfigError(f"Config file not found: {cfg_path}")
    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{cfg_path.name} is not valid YAML: {exc}") from exc
    raw["_path"] = str(cfg_path)
    return raw


def load_settings(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    load_dotenv()
    raw = read_raw(path)
    for k, v in (overrides or {}).items():
        raw[k] = v
    return settings_from_raw(raw)


DEPLOYMENT_KEYS = {"mode", "security", "chatops", "storage", "tenants", "ops", "demo"}


def tenant_files(base_raw: dict[str, Any]) -> list[Path]:
    tdir = (base_raw.get("tenants") or {}).get("dir", "config/tenants")
    p = Path(tdir) if Path(tdir).is_absolute() else ROOT / tdir
    return sorted(x for x in p.glob("*.yaml") if not x.name.startswith(("_", "example"))) if p.is_dir() else []


def load_tenants(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> list[Settings]:
    """Every organisation this deployment serves.

    Single organisation: just config/lodestar.yaml.
    Several (group companies, an MSSP, a regulator's sector view): one file per organisation in
    config/tenants/*.yaml. Each file is deep-merged over lodestar.yaml (so shared settings such as
    scoring, chatops and llm are written once) EXCEPT `connectors`, which each tenant declares in full.
    Storage is shared (all tables are org-scoped); use separate deployments if regulation requires
    physical separation."""
    load_dotenv()
    base = read_raw(path)
    for k, v in (overrides or {}).items():
        base[k] = v
    files = tenant_files(base)
    if not files or base.get("mode", "demo") == "demo":
        return [settings_from_raw(base)]
    out, keys = [], set()
    for f in files:
        try:
            over = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{f.name} is not valid YAML: {exc}") from exc
        if not (over.get("org") or {}).get("name"):
            raise ConfigError(f"{f.name}: org.name is required for a tenant")
        shared = sorted(k for k in over if k in DEPLOYMENT_KEYS)
        if shared:      # access control, storage and chat routing are deployment-wide: a tenant must not weaken them
            raise ConfigError(f"{f.name}: {shared} can only be set in {Path(base['_path']).name}, not in a tenant file")
        raw = deep_merge(base, over, replace=("connectors",))
        raw["_path"], raw["_tenant_file"] = base["_path"], str(f)
        s = settings_from_raw(raw)
        if s.org_key in keys:
            raise ConfigError(f"{f.name}: duplicate tenant key '{s.org_key}'")
        keys.add(s.org_key)
        out.append(s)
    return out


def settings_from_raw(raw: dict[str, Any]) -> Settings:
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
            sources=[{"adapter": x.get("adapter", "mock"), "product": x.get("product", ""), "settings": x.get("settings") or {},
                      "interval_minutes": int(x.get("interval_minutes", c.get("interval_minutes", 0)))}
                     for x in (c.get("sources") or [])],
            interval_minutes=int(c.get("interval_minutes", 0)),
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
