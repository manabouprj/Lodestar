"""Day-one onboarding: `lodestar init` (generate a working live config) and `lodestar doctor` (readiness report).

init  : organisation + industry + SIEM choice -> config with every connector pre-filled from
        config/templates/catalog.yaml (SIEM-first where the SIEM can supply the domain), a .env with
        generated API keys / secrets, CMDB + identity templates and drop folders.
doctor: one screen that says what is ready, what is missing and what to do next - config, secrets,
        store, CMDB quality, every connector source (last success / error), KRI coverage, SSO,
        backups, and (with --online) network reachability through the corporate proxy.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import ENV_RE, ROOT, ConfigError, read_raw, slugify

CATALOG = ROOT / "config" / "templates" / "catalog.yaml"
ASSET_COLS = "asset_id,name,asset_type,business_service,owner,criticality,exposure,data_classification,tags,aliases,ips,macs,external_ids"
IDENTITY_COLS = "identity_id,display_name,upn,email,sam,entra_object_id,aliases,privileged,department"
SIEM_SETTINGS = {
    "sentinel": {"workspace_id": "${SENTINEL_WORKSPACE_ID}", "tenant_id": "${AZ_TENANT_ID}", "client_id": "${AZ_CLIENT_ID}",
                 "client_secret": "${AZ_CLIENT_SECRET}"},
    "splunk": {"base_url": "${SPLUNK_URL}", "token": "${SPLUNK_TOKEN}"},
    "qradar": {"base_url": "${QRADAR_URL}", "token": "${QRADAR_TOKEN}"},
    "elastic": {"base_url": "${ELASTIC_URL}", "api_key": "${ELASTIC_API_KEY}"},
    "sumologic": {"base_url": "${SUMO_API_URL}", "access_id": "${SUMO_ACCESS_ID}", "access_key": "${SUMO_ACCESS_KEY}"},
    "google_secops": {"base_url": "${SECOPS_API_URL}", "project": "${SECOPS_PROJECT}", "location": "${SECOPS_LOCATION}",
                      "instance": "${SECOPS_INSTANCE}", "service_account_secret": "${GOOGLE_SECOPS_SA_JSON}"},
}
HUNT_PROVIDERS = ("sentinel", "splunk", "qradar", "elastic")         # SIEMs the ThreatHuntAgent can query


# ------------------------------------------------------------------ YAML helpers
class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data.rstrip() + ("\n" if "\n" in data else ""), style=style)


_Dumper.add_representer(str, _str)


def dump(data: dict[str, Any]) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=120)


def load_catalog() -> dict[str, Any]:
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8")) or {}


# ------------------------------------------------------------------ init
def connector_for(domain: str, siem: str, catalog: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Pick the best template for a domain: the chosen SIEM, then a native adapter, then file drop / webhook."""
    entry = catalog.get(domain) or {}
    generic = catalog.get("_generic") or {}
    for kind in ([siem] if siem in SIEM_SETTINGS else []) + ["native", "file_drop", "webhook"]:
        t = entry.get(kind)
        if t is None:
            continue
        t = dict(t)
        t.pop("note", None)
        t.pop("permission", None)
        if kind in SIEM_SETTINGS:
            settings = {**SIEM_SETTINGS[kind], **{k: v for k, v in t.items() if k != "product"}}
            return {"enabled": True, "adapter": kind, "product": t.get("product", domain), "settings": settings}, kind
        if kind == "native":
            if "sources" in t:
                return {"enabled": True, "product": entry.get("title", domain), "sources": t["sources"]}, kind
            return {"enabled": True, "adapter": t["adapter"], "product": t.get("product", domain),
                    "settings": t.get("settings", {})}, kind
        if kind == "file_drop":
            settings = {"path": f"data/drop/{domain}", **{k: v for k, v in t.items() if k != "product"}}
            return {"enabled": True, "adapter": "file_drop", "product": t.get("product", entry.get("title", domain)),
                    "settings": settings}, kind
        if kind == "webhook":
            return {"enabled": True, "adapter": "webhook", "product": t.get("product", entry.get("title", domain))}, kind
    t = generic.get("file_drop") or {}
    return {"enabled": True, "adapter": "file_drop", "product": domain,
            "settings": {"path": f"data/drop/{domain}", **t}}, "file_drop"


def _env_refs(obj: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for v in obj.values():
            out |= _env_refs(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _env_refs(v)
    elif isinstance(obj, str):
        out |= {m.group(1) for m in ENV_RE.finditer(obj)}
    return out


def _read_env(p: Path) -> dict[str, str]:
    out = {}
    if p.exists():
        for line in p.read_text(encoding="utf-8-sig").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def write_env(p: Path, needed: set[str], org_key: str) -> dict[str, str]:
    """Add missing variables to .env (never overwrites). Returns the values it generated."""
    have = _read_env(p)
    generated: dict[str, str] = {}
    if "LODESTAR_API_KEYS" not in have:
        keys = {r: secrets.token_urlsafe(24) for r in ("ciso", "analyst", "exec")}
        generated["LODESTAR_API_KEYS"] = ",".join(f"{r}:{k}" for r, k in keys.items())
    for k, n in (("LODESTAR_WEBHOOK_SECRET", 32), ("LODESTAR_SESSION_SECRET", 48), ("LODESTAR_METRICS_TOKEN", 24)):
        if k not in have:
            generated[k] = secrets.token_urlsafe(n)
    blanks = sorted(v for v in needed if v not in have and v not in generated)
    lines = []
    if not p.exists():
        lines.append("# LODESTAR secrets - NEVER commit this file (.gitignore covers it). Fill the blank values.")
    lines.append(f"\n# ---- added by `lodestar init` for {org_key} on {datetime.now():%Y-%m-%d}")
    lines += [f"{k}={v}" for k, v in generated.items()]
    lines += [f"{k}=" for k in blanks]
    with p.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return generated


def init(*, org: str, vertical: str, siem: str, domains: list[str], primary_domain: str | None,
         tenant: bool = False, out: Path | None = None, root: Path = ROOT) -> dict[str, Any]:
    from .verticals import list_verticals, load_vertical
    if vertical not in list_verticals():
        raise ConfigError(f"unknown vertical '{vertical}'. Choose: {', '.join(list_verticals())}")
    catalog = load_catalog()
    v = load_vertical(vertical)
    key = slugify(org)
    connectors, chosen = {}, {}
    for d in domains:
        connectors[d], chosen[d] = connector_for(d, siem, catalog)
    body: dict[str, Any] = {"org": {"name": org, "vertical": vertical}}
    if not tenant:
        body.update({"mode": "live", "deployment_phase": 1,
                     "assets": {"path": "config/assets.csv"}})
    body["identity"] = {"path": "config/identities.csv", "primary_domain": primary_domain or "", "domains": []}
    if siem in HUNT_PROVIDERS:
        hunt_settings = dict(SIEM_SETTINGS[siem])
        if siem == "elastic":
            hunt_settings["index"] = "logs-*"
        body["threat_hunt"] = {"enabled": "threat_intel" in domains, "provider": siem, "lookback_hours": 24,
                               "max_iocs": 500, "ioc_max_age_days": 30, "settings": hunt_settings}
    body["connectors"] = connectors

    created: list[str] = []
    if tenant:
        dest = out or (root / "config" / "tenants" / f"{key}.yaml")
        if tenant and body.get("identity"):
            body["assets"] = {"path": f"config/assets-{key}.csv"}
            body["identity"]["path"] = f"config/identities-{key}.csv"
        text = dump(body)
    else:
        dest = out or (root / "config" / "lodestar.yaml")
        base = read_raw(dest) if dest.exists() else read_raw(ROOT / "config" / "lodestar.yaml")
        base.pop("_path", None)
        for k in ("org", "mode", "deployment_phase", "assets", "identity", "threat_hunt"):
            if k in body:
                base[k] = body[k]
        base["connectors"] = connectors
        base.setdefault("security", {})["require_auth"] = True
        text = dump(base)
        if dest.exists():
            bak = dest.with_suffix(f".yaml.{datetime.now():%Y%m%d-%H%M%S}.bak")
            shutil.copy2(dest, bak)
            created.append(f"backup of previous config: {bak.relative_to(root)}")
    header = (f"# LODESTAR configuration for {org} ({v.name}) - generated by `lodestar init` on {datetime.now():%Y-%m-%d}.\n"
              "# Templates come from config/templates/catalog.yaml. Secrets are ${ENV} references filled from .env.\n"
              "# Start at deployment_phase 1; raise it as `lodestar doctor` turns green (docs/QUICKSTART.md).\n")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(header + text, encoding="utf-8")
    created.append(f"config: {dest.relative_to(root) if dest.is_relative_to(root) else dest}")

    assets = root / (body.get("assets") or {}).get("path", "config/assets.csv")
    if not assets.exists():
        assets.write_text(ASSET_COLS + "\n", encoding="utf-8")
        created.append(f"CMDB template: {assets.relative_to(root)} (fill from your CMDB export - see docs/QUICKSTART.md)")
    idp = root / body["identity"]["path"]
    if not idp.exists():
        idp.write_text(IDENTITY_COLS + "\n", encoding="utf-8")
        created.append(f"identity template: {idp.relative_to(root)} (optional HR / directory export)")
    for c in connectors.values():
        for src in c.get("sources") or [c]:
            path = (src.get("settings") or {}).get("path")
            if path and src.get("adapter") in ("file_drop", "csaf", "mailbox"):
                (root / path).mkdir(parents=True, exist_ok=True)
    needed = _env_refs(connectors) | _env_refs(body.get("threat_hunt") or {}) | {"LODESTAR_PUBLIC_URL"}
    generated = write_env(root / ".env", needed, key)
    created.append(".env: generated " + ", ".join(generated) + " (existing values kept)" if generated else ".env: kept as is")
    missing_mandatory = [m for m in v.mandatory_domains if m not in domains]
    return {"org_key": key, "files": created, "templates": chosen, "generated": generated,
            "mandatory_missing": missing_mandatory, "env_to_fill": sorted(needed)}


# ------------------------------------------------------------------ doctor
class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, level: str, area: str, msg: str, fix: str = "") -> None:
        self.rows.append((level, area, msg, fix))

    def ok(self, area, msg):
        self.add("PASS", area, msg)

    def warn(self, area, msg, fix=""):
        self.add("WARN", area, msg, fix)

    def fail(self, area, msg, fix=""):
        self.add("FAIL", area, msg, fix)

    @property
    def failed(self) -> bool:
        return any(r[0] == "FAIL" for r in self.rows)

    def render(self) -> str:
        out = []
        for level, area, msg, fix in self.rows:
            out.append(f"[{level}] {area:<14} {msg}")
            if fix:
                out.append(f"       {'':<14} -> {fix}")
        n = {k: sum(1 for r in self.rows if r[0] == k) for k in ("PASS", "WARN", "FAIL")}
        out.append(f"\n{n['PASS']} passed, {n['WARN']} warnings, {n['FAIL']} failures - "
                   + ("fix the FAIL items first" if n["FAIL"] else "ready to run" if not n["WARN"] else "usable; warnings reduce accuracy"))
        return "\n".join(out)


def _dup_keys(path: Path) -> list[str]:
    dups: list[str] = []

    class L(yaml.SafeLoader):
        pass

    def cm(loader, node, deep=False):
        keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
        dups.extend(str(k) for k in set(keys) if keys.count(k) > 1)
        return yaml.SafeLoader.construct_mapping(loader, node, deep)
    L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, cm)
    yaml.load(path.read_text(encoding="utf-8"), Loader=L)
    return dups


def doctor(config: str | None = None, online: bool = False) -> Report:
    from .agents.connectors.adapters import REGISTRY
    from .agents.connectors.domains import SPECS
    from .config import config_path, load_tenants, tenant_files
    from .entities import EntityResolver
    from .verticals import load_vertical
    r = Report()
    # runtime
    if sys.version_info < (3, 11):
        r.fail("runtime", f"Python {sys.version.split()[0]} - 3.11+ required", "install Python 3.12")
    else:
        r.ok("runtime", f"Python {sys.version.split()[0]}")
    try:
        import cryptography  # noqa: F401
        import jwt  # noqa: F401
        r.ok("runtime", "dependencies importable")
    except ImportError as exc:
        r.fail("runtime", f"missing dependency: {exc.name}", "pip install -r requirements.txt")
    # config
    cp = config_path(config)
    try:
        dups = _dup_keys(cp)
        if dups:
            r.fail("config", f"duplicate keys in {cp.name}: {sorted(set(dups))} (only the last one counts)", "merge them")
        tenants = load_tenants(config)
    except ConfigError as exc:
        r.fail("config", str(exc), "fix the file, then run doctor again")
        return r
    base = tenants[0]
    raw = read_raw(config)
    r.ok("config", f"{cp.name}: mode={base.mode}, phase={base.deployment_phase}, "
         f"{len(tenants)} organisation(s): {', '.join(t.org_key for t in tenants)}"
         + (f" from {len(tenant_files(raw))} tenant file(s)" if len(tenants) > 1 else ""))
    live = base.mode == "live"
    if not live:
        r.warn("config", "mode is demo - synthetic data only", "run `lodestar init` or set mode: live")
    # secrets
    env_file = ROOT / ".env"
    if live and not env_file.exists():
        r.warn("secrets", ".env not found - secrets must come from the environment / secret store")
    keys = os.environ.get("LODESTAR_API_KEYS", "")
    if live and "ciso" not in keys and not (raw.get("security") or {}).get("oidc", {}).get("issuer"):
        r.fail("secrets", "no ciso API key and no SSO - nobody can administer LODESTAR", "run `lodestar init` or set LODESTAR_API_KEYS")
    elif live:
        r.ok("secrets", "API keys / SSO configured")
    if live and len(os.environ.get("LODESTAR_SESSION_SECRET", "")) < 32:
        r.warn("secrets", "LODESTAR_SESSION_SECRET missing or short - sign-ins reset on restart",
               "set 32+ random characters (generated by `lodestar init`)")
    uses_webhook = any((s.get("adapter") if isinstance(s, dict) else None) == "webhook" or c.adapter == "webhook"
                       for t in tenants for c in t.connectors.values() if c.enabled for s in (c.sources or [{}]))
    if live and uses_webhook and not os.environ.get("LODESTAR_WEBHOOK_SECRET"):
        r.fail("secrets", "webhook connectors configured but LODESTAR_WEBHOOK_SECRET is empty", "set it in .env")
    if live and not os.environ.get("LODESTAR_METRICS_TOKEN"):
        r.warn("ops", "LODESTAR_METRICS_TOKEN not set - /metrics disabled", "set it to enable Prometheus scraping")
    if live and not (raw.get("ops") or {}).get("backup_dir"):
        r.warn("ops", "no ops.backup_dir - nightly backups are off", "set ops.backup_dir and keep copies off the host")
    # store
    from .store import Store
    try:
        store = Store(base.sqlite_path)
        store.ping()
        r.ok("store", f"{base.sqlite_path} writable, schema v{store.schema_version()}")
    except Exception as exc:
        r.fail("store", f"cannot open {base.sqlite_path}: {exc}", "check the folder exists and is writable")
        return r
    # per organisation
    for t in tenants:
        tag = t.org_key[:14]
        v = load_vertical(t.vertical)
        from .agents.base import AgentContext, PipelineState
        from .agents.core.asset_context import AssetContextAgent
        st = PipelineState()
        try:
            st = AssetContextAgent().run(AgentContext(settings=t, vertical=v, now=datetime.now(timezone.utc)), st)
        except Exception as exc:
            r.fail(tag, f"CMDB / identity file unreadable: {exc}", "check column names against the template")
        n_assets = len(st.assets)
        if live and n_assets == 0:
            r.fail(tag, "CMDB is empty - findings cannot be tied to business services",
                   f"export your CMDB to {t.assets_path} (columns: {ASSET_COLS[:60]}...)")
        elif live:
            crown = sum(1 for a in st.assets.values() if a.criticality >= 4)
            res = EntityResolver(st.assets, st.identities)
            amb = len(res.ambiguous)
            msg = f"CMDB {n_assets} assets, {crown} crown jewels (criticality >= 4)"
            (r.ok if crown else r.warn)(tag, msg + ("" if crown else " - none marked critical"),
                                        "" if crown else "set criticality 4-5 on crown-jewel systems")
            if amb:
                r.warn(tag, f"{amb} ambiguous short names in the CMDB", "add FQDN aliases so findings match one asset")
            if not st.identities:
                r.warn(tag, "no identities file - user spellings are only normalised by primary_domain",
                       "optional: export UPN / mail / sAMAccountName to config/identities.csv")
        missing = [m for m in v.mandatory_domains if not (t.connectors.get(m) and t.connectors[m].enabled)]
        if missing:
            r.warn(tag, f"{v.name} expects {missing} - posture confidence will be lower", "enable them when available")
        if not live:
            r.ok(tag, "demo mode: connectors use the synthetic dataset (source checks start in live mode)")
            continue
        state = store.all_connector_state(t.org_name)
        for d, c in sorted(t.connectors.items(), key=lambda x: (SPECS[x[0]].phase, x[0].value)):
            if not c.enabled or SPECS[d].phase > t.deployment_phase:
                continue
            srcs = c.sources or [{"adapter": c.adapter, "product": c.product, "settings": c.settings}]
            seen: dict[str, int] = {}
            for src in srcs:
                label = f"{d.value}/{src['adapter']}"
                seen[label] = seen.get(label, 0) + 1
                key = label if seen[label] == 1 else f"{label}#{seen[label]}"     # same keys as ConnectorAgent
                if src["adapter"] not in REGISTRY:
                    r.fail(tag, f"{label}: unknown adapter", f"one of {', '.join(sorted(REGISTRY))}")
                    continue
                if live and src["adapter"] == "mock":
                    r.fail(tag, f"{label}: mock adapter in live mode", "pick a template from config/templates/catalog.yaml")
                    continue
                empty = [k for k, val in (src.get("settings") or {}).items() if val in ("", None)]
                if empty and live:
                    names = sorted(_env_refs(_raw_source(t, config, d.value, src["adapter"], seen[label]) or {})) or empty
                    r.fail(tag, f"{label}: empty settings {empty}",
                           f"set {', '.join(names)} in .env - or disable this source if you do not have it yet")
                    continue
                path = (src.get("settings") or {}).get("path")
                if path and src["adapter"] in ("file_drop", "csaf", "mailbox") and (src.get("settings") or {}).get("mode", "path") == "path":
                    folder = t.path(path)
                    if not folder.exists():
                        r.fail(tag, f"{label}: drop folder {path} missing", f"mkdir {path} and schedule the export into it")
                        continue
                    if not any(folder.iterdir()):
                        r.warn(tag, f"{label}: drop folder {path} is empty", "schedule the product's export into it")
                        continue
                s = state.get(key) or state.get(label) or {}
                if s.get("last_error"):
                    r.fail(tag, f"{label}: last attempt failed - {s['last_error'][:120]}",
                           f"lodestar test-connector {d.value}")
                elif s.get("last_success"):
                    age = (datetime.now(timezone.utc) - s["last_success"]).total_seconds() / 3600
                    (r.ok if age < 48 else r.warn)(tag, f"{label}: last success {age:.1f}h ago, {s.get('items')} items",
                                                   "" if age < 48 else "is the scheduler running?")
                elif live:
                    r.warn(tag, f"{label}: configured, never run", f"lodestar test-connector {d.value}")
        res = store.latest_result(t.org_name)
        if res:
            snap = res.snapshot
            (r.ok if (snap.kri_coverage_pct or 0) >= 60 else r.warn)(
                tag, f"latest run {res.generated_at:%Y-%m-%d %H:%M}: posture {snap.posture_score}, "
                     f"KRIs measured {snap.kri_coverage_pct}%", "" if (snap.kri_coverage_pct or 0) >= 60 else "lodestar kpis")
        elif live:
            r.warn(tag, "no pipeline run yet", f"lodestar run --org {t.org_key}")
    # SSO
    oidc = (raw.get("security") or {}).get("oidc") or {}
    if oidc.get("issuer") and not ENV_RE.search(str(oidc.get("issuer"))):
        if not oidc.get("role_map"):
            r.warn("sso", "OIDC configured but role_map is empty - only default_role users can sign in",
                   "map your Entra / Okta group ids to ciso / analyst / exec")
        else:
            r.ok("sso", f"OIDC issuer {oidc['issuer']} with {len(oidc['role_map'])} role mapping(s)")
    # network
    if online:
        _online_checks(r, tenants, raw)
    return r


def _raw_source(t, config, domain: str, adapter: str, nth: int) -> dict[str, Any] | None:
    """The unresolved (${VAR}) settings of one source, to tell the user which variables to set."""
    try:
        if t.raw.get("_tenant_file"):
            raw = yaml.safe_load(Path(t.raw["_tenant_file"]).read_text(encoding="utf-8")) or {}
        else:
            raw = read_raw(config)
        c = (raw.get("connectors") or {}).get(domain) or {}
        srcs = c.get("sources") or [{"adapter": c.get("adapter"), "settings": c.get("settings")}]
        same = [x for x in srcs if x.get("adapter") == adapter]
        return (same[nth - 1] if len(same) >= nth else same[0]).get("settings")
    except Exception:
        return None


def _hosts(obj: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and re.match(r"https?://", v):
                out.add(v.split("/")[0] + "//" + v.split("/")[2])
            if k == "tenant_id" and v:
                out.add("https://login.microsoftonline.com")
            if k == "workspace_id" and v:
                out.add("https://api.loganalytics.io")
            if k == "service_account_secret" and v:
                out.add("https://oauth2.googleapis.com")
            out |= _hosts(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _hosts(v)
    return out


def _online_checks(r: Report, tenants, raw) -> None:
    from .agents.connectors.adapters.base import http_client
    hosts: set[str] = set()
    for t in tenants:
        for c in t.connectors.values():
            if c.enabled:
                hosts |= _hosts(c.settings) | _hosts(c.sources)
        hosts |= _hosts((t.raw.get("threat_hunt") or {}).get("settings") or {})
    if (raw.get("security") or {}).get("oidc", {}).get("issuer"):
        hosts |= _hosts({"x": t.raw["security"]["oidc"]["issuer"]})
    if hosts == set():
        r.ok("network", "no outbound API endpoints configured")
    for h in sorted(hosts):
        try:
            with http_client(8) as c:
                resp = c.get(h)
            r.ok("network", f"{h} reachable (HTTP {resp.status_code}, TLS verified)")
        except Exception as exc:
            r.fail("network", f"{h} unreachable: {type(exc).__name__}: {str(exc)[:100]}",
                   "allow egress / set HTTPS_PROXY and SSL_CERT_FILE for the corporate proxy")

