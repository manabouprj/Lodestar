"""Entity resolution - make different tools agree on "which machine" and "which person".

Security tools name the same thing differently:
  host : FQDN (srv01.corp.example), short name (SRV01), IP, MAC, EDR device id, cloud resource id, URL
  user : UPN (j.doe@corp.example), e-mail alias, DOMAIN\\jdoe, sAMAccountName, Entra object id
Correlation, asset context and scoring all depend on resolving these to ONE asset / ONE identity.

Asset keys come from the CMDB export (asset_id, name, aliases incl. *.wildcards, ips, macs, external_ids).
Identity keys come from an optional identities export (config/identities.csv) plus normalisation rules.
Ambiguous keys (e.g. a short name shared by two FQDNs) are never guessed - they are reported.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Asset

MAC_RE = re.compile(r"^[0-9a-f]{2}([-:.]?[0-9a-f]{2}){5}$", re.I)


def norm_host(value: str) -> str:
    v = str(value).strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)       # scheme
    v = v.split("/", 1)[0].split("@")[-1]              # path, credentials
    v = re.sub(r":\d+$", "", v)                         # port
    v = v.rstrip(".")
    return v[4:] if v.startswith("www.") else v


def norm_mac(value: str) -> str | None:
    v = str(value).strip().lower()
    if not MAC_RE.match(v):
        return None
    h = re.sub(r"[^0-9a-f]", "", v)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def short_name(host: str) -> str | None:
    if norm_ip(host):
        return None
    return host.split(".", 1)[0] if "." in host else None


@dataclass
class Identity:
    identity_id: str                      # canonical id - use the UPN
    display_name: str = ""
    upn: str = ""
    email: str = ""
    sam: str = ""
    entra_object_id: str = ""
    aliases: list[str] = field(default_factory=list)
    privileged: bool = False
    department: str = ""


def load_identities(path: Path | None) -> list[Identity]:
    if not path or not Path(path).exists():
        return []
    out = []
    with Path(path).open(newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            if not (r.get("identity_id") or r.get("upn")):
                continue
            out.append(Identity(
                identity_id=(r.get("identity_id") or r.get("upn")).strip().lower(), display_name=r.get("display_name", ""),
                upn=(r.get("upn") or "").strip().lower(), email=(r.get("email") or "").strip().lower(),
                sam=(r.get("sam") or "").strip().lower(), entra_object_id=(r.get("entra_object_id") or "").strip().lower(),
                aliases=[a.strip().lower() for a in (r.get("aliases") or "").split(";") if a.strip()],
                privileged=str(r.get("privileged", "")).strip().lower() in ("1", "true", "yes", "y"),
                department=r.get("department", "")))
    return out


class EntityResolver:
    def __init__(self, assets: dict[str, Asset], identities: Iterable[Identity] = (), *,
                 primary_domain: str | None = None, domains: Iterable[str] = ()):
        self.assets = assets
        self.exact: dict[str, str] = {}
        self.short: dict[str, set[str]] = {}
        self.wild: list[tuple[str, str]] = []
        self.ambiguous: set[str] = set()
        for a in assets.values():
            keys = [a.asset_id, a.name, *a.aliases, *a.external_ids]
            for k in keys:
                self._add_host(k, a.asset_id)
            for ip in a.ips:
                if norm_ip(ip):
                    self._add_exact(norm_ip(ip), a.asset_id)
            for mac in a.macs:
                if norm_mac(mac):
                    self._add_exact(norm_mac(mac), a.asset_id)
        self.primary_domain = (primary_domain or "").lower() or None
        self.domains = {d.lower() for d in domains} | ({self.primary_domain} if self.primary_domain else set())
        self.ids: dict[str, str] = {}
        self.identities = {i.identity_id: i for i in identities}
        for i in self.identities.values():
            for k in [i.identity_id, i.upn, i.email, i.sam, i.entra_object_id, *i.aliases]:
                if k:
                    self.ids.setdefault(k.lower(), i.identity_id)
                    if "\\" in k:
                        self.ids.setdefault(k.split("\\", 1)[1].lower(), i.identity_id)

    def _add_exact(self, key: str, aid: str) -> None:
        if key in self.exact and self.exact[key] != aid:
            self.ambiguous.add(key)
        self.exact.setdefault(key, aid)

    def _add_host(self, value: str, aid: str) -> None:
        if not value:
            return
        k = norm_host(value)
        if k.startswith("*."):
            self.wild.append((k[1:], aid))
            return
        self._add_exact(k, aid)
        s = short_name(k)
        if s:
            self.short.setdefault(s, set()).add(aid)
        else:                                       # a bare short name in the CMDB also answers for FQDNs
            self.short.setdefault(k, set()).add(aid)

    # ---------------------------------------------------------------- assets
    def asset(self, *candidates: Any) -> tuple[str | None, str]:
        """Return (asset_id, how) for the first candidate that resolves unambiguously."""
        for c in candidates:
            if c in (None, ""):
                continue
            if isinstance(c, (list, tuple, set)):
                aid, how = self.asset(*c)
                if aid:
                    return aid, how
                continue
            raw = str(c)
            if raw in self.assets:
                return raw, "id"
            for key, how in ((norm_ip(raw), "ip"), (norm_mac(raw), "mac")):
                if key and key in self.exact and key not in self.ambiguous:
                    return self.exact[key], how
            k = norm_host(raw)
            if k in self.exact and k not in self.ambiguous:
                return self.exact[k], "name"
            s = short_name(k) or k
            hits = self.short.get(s, set())
            if len(hits) == 1:
                return next(iter(hits)), "short-name"
            if len(hits) > 1:
                self.ambiguous.add(s)
                continue
            w = next((aid for suffix, aid in self.wild if k.endswith(suffix)), None)
            if w:
                return w, "wildcard"
        return None, "unmatched"

    # ---------------------------------------------------------------- users
    def user(self, value: Any) -> tuple[str | None, str]:
        if value in (None, ""):
            return None, "none"
        v = str(value).strip().lower()
        if v in self.ids:
            return self.ids[v], "identity"
        if "\\" in v:                                   # DOMAIN\user
            local, dom = v.split("\\", 1)[1], None
        elif "@" in v:
            local, dom = v.split("@", 1)
        else:
            local, dom = v, None
        if local in self.ids:
            return self.ids[local], "identity"
        if self.primary_domain and (dom is None or dom in self.domains):
            cand = f"{local}@{self.primary_domain}"
            if cand in self.ids:
                return self.ids[cand], "identity"
            return cand, "normalised"
        return v, "normalised"

    def privileged(self, user_id: str | None) -> bool:
        i = self.identities.get(user_id or "")
        return bool(i and i.privileged)
