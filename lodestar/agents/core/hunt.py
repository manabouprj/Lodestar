"""ThreatHuntAgent (Phase 1) - turns threat-intel indicators into sightings in YOUR telemetry.

Feeds (TAXII, MISP, ISAC e-mails, CSAF, bug bounty) deliver indicators; on their own they are noise.
This agent takes the recent indicators LODESTAR already holds and asks the SIEM one question:
"did any of our hosts or users touch these in the last N hours?". Every hit becomes a SOC
detection finding (source key "hunt") that carries the indicator, so the ThreatIntelAgent can
mark the advisory as SIGHTED and the CorrelationAgent can join it to the asset / identity.

Read-only: it runs ONE query per run against Sentinel (Log Analytics Reader), Splunk (search role),
IBM QRadar (AQL search) or Elastic / OpenSearch (read on the indices).
Config:
  threat_hunt:
    enabled: true
    provider: sentinel            # sentinel | splunk | qradar | elastic
    settings: {workspace_id: ${SENTINEL_WORKSPACE_ID}, tenant_id: ..., client_id: ..., client_secret: ...}
                                  # splunk:  {base_url, token, ca_bundle, scope: "index=*"}
                                  # qradar:  {base_url, token, ca_bundle, domain_property: "URL", hash_property: "SHA256 Hash"}
                                  #          (IPs use sourceip/destinationip; domains and hashes need the custom
                                  #           properties your DSMs extract - leave out what you do not have)
                                  # elastic: {base_url, api_key | username+password, index: "logs-*", ca_bundle}
                                  #          (ECS fields: source/destination.ip, dns.question.name, url.domain,
                                  #           destination.domain, file.hash.*, process.hash.*)
    lookback_hours: 24
    max_iocs: 500                 # newest first
    ioc_max_age_days: 30          # ignore older indicators
    query: null                   # optional override; placeholders {ips} {domains} {hashes} {hours}
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ...models import Domain, Finding, FindingType, Severity, Status
from ..base import AgentContext, BaseAgent, PipelineState

HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$", re.I)
TLP_ORDER = ["clear", "white", "green", "amber", "amber+strict", "red"]
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

KQL_TEMPLATE = """let ips = dynamic({ips});
let domains = dynamic({domains});
let hashes = dynamic({hashes});
let since = ago({hours}h);
union isfuzzy=true
 (DeviceNetworkEvents | where TimeGenerated > since
    | where RemoteIP in (ips) or RemoteUrl has_any (domains)
    | project TimeGenerated, Host=DeviceName, User=InitiatingProcessAccountUpn, Indicator=iff(RemoteIP in (ips), RemoteIP, RemoteUrl), Source="DeviceNetworkEvents"),
 (DeviceFileEvents | where TimeGenerated > since
    | where SHA256 in~ (hashes) or SHA1 in~ (hashes) or MD5 in~ (hashes)
    | project TimeGenerated, Host=DeviceName, User=InitiatingProcessAccountUpn, Indicator=case(SHA256 in~ (hashes), SHA256, SHA1 in~ (hashes), SHA1, MD5), Source="DeviceFileEvents"),
 (DnsEvents | where TimeGenerated > since
    | where Name in~ (domains)
    | project TimeGenerated, Host=Computer, User="", Indicator=Name, Source="DnsEvents"),
 (CommonSecurityLog | where TimeGenerated > since
    | where DestinationIP in (ips) or SourceIP in (ips) or RequestURL has_any (domains)
    | project TimeGenerated, Host=coalesce(SourceHostName, SourceIP), User=SourceUserName,
              Indicator=case(DestinationIP in (ips), DestinationIP, SourceIP in (ips), SourceIP, RequestURL), Source=strcat("CEF:", DeviceVendor)),
 (EmailUrlInfo | where TimeGenerated > since
    | where UrlDomain in~ (domains)
    | join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress) on NetworkMessageId
    | project TimeGenerated, Host="", User=RecipientEmailAddress, Indicator=UrlDomain, Source="EmailUrlInfo")
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Hits=count() by Host, User, Indicator, Source
| top 1000 by Hits desc"""

SPL_TEMPLATE = """search {scope} earliest=-{hours}h ({terms})
| eval lds_values=mvappend(dest_ip, src_ip, dest, query, url, file_hash, sha256, md5)
| stats min(_time) as FirstSeen max(_time) as LastSeen count as Hits values(lds_values) as Indicator
        by host, user, sourcetype
| rename host as Host, user as User, sourcetype as Source
| head 1000"""


ECS_IP = ("source.ip", "destination.ip")
ECS_DOMAIN = ("dns.question.name", "url.domain", "destination.domain")
ECS_HASH = ("file.hash.sha256", "file.hash.sha1", "file.hash.md5", "process.hash.sha256", "process.hash.md5")


def _aql_quote(v: str) -> str:
    return "'" + v.replace("\\", "").replace("'", "") + "'"


def _aggregate(hits: list[dict[str, Any]], indicator_fields: tuple[str, ...], host_fields: tuple[str, ...],
               user_fields: tuple[str, ...], time_field: str, source_field: str) -> list[dict[str, Any]]:
    """Raw matching events -> hunt rows (Host, User, Indicator[], Source, FirstSeen, LastSeen, Hits)."""
    from ..connectors.adapters.file_drop import parse_dt
    rows: dict[tuple, dict[str, Any]] = {}
    for h in hits:
        host = next((str(h[f]) for f in host_fields if h.get(f)), "")
        user = next((str(h[f]) for f in user_fields if h.get(f)), "")
        src = str(h.get(source_field) or "")
        vals = sorted({str(h[f]).lower() for f in indicator_fields if h.get(f) not in (None, "")})
        t = parse_dt(h.get(time_field))
        r = rows.setdefault((host, user, src), {"Host": host, "User": user, "Source": src, "Indicator": set(),
                                                "FirstSeen": t, "LastSeen": t, "Hits": 0})
        r["Indicator"].update(vals)
        r["Hits"] += 1
        if t:
            r["FirstSeen"] = min(x for x in (r["FirstSeen"], t) if x)
            r["LastSeen"] = max(x for x in (r["LastSeen"], t) if x)
    out = []
    for r in rows.values():
        out.append({**r, "Indicator": sorted(r["Indicator"]),
                    "FirstSeen": r["FirstSeen"].isoformat() if r["FirstSeen"] else None,
                    "LastSeen": r["LastSeen"].isoformat() if r["LastSeen"] else None})
    return out


def classify(ioc: str) -> str | None:
    v = ioc.strip().lower()
    try:
        ip = ipaddress.ip_address(v)
        internal = any(ip in n for n in INTERNAL_NETS if n.version == ip.version)
        return None if (internal or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified) else "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if v.startswith(("http://", "https://")):
        v = v.split("/")[2]
    return "domain" if DOMAIN_RE.match(v) else None


def _kql_list(vals: list[str]) -> str:
    return "[" + ", ".join('"' + v.replace("\\", "").replace('"', "") + '"' for v in vals) + "]"


def _spl_quote(v: str) -> str:
    return '"' + v.replace("\\", "").replace('"', "") + '"'


class ThreatHuntAgent(BaseAgent):
    name = "ThreatHuntAgent"
    phase = 1
    description = "Hunts recent threat-intel indicators across SIEM telemetry; every sighting becomes a SOC detection."

    # ------------------------------------------------------------------ indicators
    def _indicators(self, ctx: AgentContext, state: PipelineState, max_age: int) -> dict[str, dict[str, Any]]:
        """{ioc: {kind, severity, tlp, title, source, seen}} from current + still-open intel findings."""
        now = ctx.now if ctx.now.tzinfo else ctx.now.replace(tzinfo=timezone.utc)
        intel = [f for f in state.findings if f.domain == Domain.THREAT_INTEL]
        if ctx.store is not None:
            from ...models import Finding as F
            have = {f.finding_id for f in intel}
            for fid, st in ctx.store.open_findings(ctx.settings.org_name).items():
                if fid not in have and st.get("domain") in (None, Domain.THREAT_INTEL.value):
                    f = F.model_validate_json(st["data"])
                    if f.domain == Domain.THREAT_INTEL:
                        intel.append(f)
        out: dict[str, dict[str, Any]] = {}
        for f in intel:
            seen = f.last_seen if f.last_seen.tzinfo else f.last_seen.replace(tzinfo=timezone.utc)
            if now - seen > timedelta(days=max_age):
                continue
            for raw in list(f.evidence.get("iocs", []) or []) + ([f.evidence["ioc"]] if f.evidence.get("ioc") else []):
                ioc = str(raw).strip().lower()
                kind = classify(ioc)
                if not kind:
                    continue
                if kind == "domain" and ioc.startswith("http"):
                    ioc = ioc.split("/")[2]
                cur = out.get(ioc)
                if cur is None or seen > cur["seen"]:
                    out[ioc] = {"kind": kind, "severity": f.severity, "tlp": f.tlp, "title": f.title,
                                "source": f.source, "seen": seen, "intel_id": f.finding_id}
        return out

    # ------------------------------------------------------------------ query builders
    @staticmethod
    def build_kql(iocs: dict[str, dict], hours: int, template: str | None = None) -> str:
        ips = [i for i, m in iocs.items() if m["kind"] == "ip"]
        doms = [i for i, m in iocs.items() if m["kind"] == "domain"]
        hashes = [i for i, m in iocs.items() if m["kind"] == "hash"]
        return (template or KQL_TEMPLATE).replace("{ips}", _kql_list(ips)).replace("{domains}", _kql_list(doms)) \
            .replace("{hashes}", _kql_list(hashes)).replace("{hours}", str(int(hours)))

    @staticmethod
    def build_spl(iocs: dict[str, dict], hours: int, scope: str = "index=*", template: str | None = None) -> str:
        ips = [_spl_quote(i) for i, m in iocs.items() if m["kind"] == "ip"]
        doms = [_spl_quote(i) for i, m in iocs.items() if m["kind"] == "domain"]
        hashes = [_spl_quote(i) for i, m in iocs.items() if m["kind"] == "hash"]
        terms = []
        if ips:
            terms += [f"dest_ip IN ({', '.join(ips)})", f"src_ip IN ({', '.join(ips)})"]
        if doms:
            terms += [f"dest IN ({', '.join(doms)})", f"query IN ({', '.join(doms)})"] + \
                     [f"url=*{d.strip(chr(34))}*" for d in doms[:100]]
        if hashes:
            terms += [f"file_hash IN ({', '.join(hashes)})", f"sha256 IN ({', '.join(hashes)})"]
        return (template or SPL_TEMPLATE).replace("{scope}", scope).replace("{hours}", str(int(hours))) \
            .replace("{terms}", " OR ".join(terms) or "NOT *")

    @staticmethod
    def build_aql(iocs: dict[str, dict], hours: int, domain_property: str | None = None,
                  hash_property: str | None = None, template: str | None = None) -> str:
        ips = [_aql_quote(i) for i, m in iocs.items() if m["kind"] == "ip"]
        doms = [_aql_quote(i) for i, m in iocs.items() if m["kind"] == "domain"]
        hashes = [_aql_quote(i) for i, m in iocs.items() if m["kind"] == "hash"]
        terms = [f"sourceip = {v}" for v in ips] + [f"destinationip = {v}" for v in ips]
        if domain_property:
            terms += [f'"{domain_property}" = {v}' for v in doms]
        if hash_property:
            terms += [f'LOWER("{hash_property}") = {v}' for v in hashes]
        extra = (f', "{domain_property}" AS domain_value' if domain_property else "") + \
                (f', "{hash_property}" AS hash_value' if hash_property else "")
        base = template or ("SELECT starttime, sourceip, destinationip, username, LOGSOURCENAME(logsourceid) AS logsource"
                            "{extra} FROM events WHERE ({terms}) LAST {hours} HOURS")
        return base.replace("{extra}", extra).replace("{terms}", " OR ".join(terms) or "1 = 0").replace("{hours}", str(int(hours)))

    @staticmethod
    def build_es_query(iocs: dict[str, dict], hours: int) -> dict[str, Any]:
        ips = [i for i, m in iocs.items() if m["kind"] == "ip"]
        doms = [i for i, m in iocs.items() if m["kind"] == "domain"]
        hashes = [i for i, m in iocs.items() if m["kind"] == "hash"]
        should = [{"terms": {f: ips}} for f in ECS_IP if ips] + [{"terms": {f: doms}} for f in ECS_DOMAIN if doms] + \
                 [{"terms": {f: hashes}} for f in ECS_HASH if hashes]
        return {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{int(hours)}h"}}}],
                         "should": should or [{"match_none": {}}], "minimum_should_match": 1}}

    # ------------------------------------------------------------------ run
    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        cfg = ctx.settings.raw.get("threat_hunt") or {}
        sources = state.data_quality.setdefault("sources", {})
        if not cfg.get("enabled"):
            return state
        if ctx.settings.mode == "demo":
            sources["hunt"] = {"status": "skipped", "mode": "incremental", "domain": "soc", "reason": "demo mode"}
            return state
        hours = int(cfg.get("lookback_hours", 24))
        iocs = self._indicators(ctx, state, int(cfg.get("ioc_max_age_days", 30)))
        ranked = sorted(iocs.items(), key=lambda kv: kv[1]["seen"], reverse=True)[: int(cfg.get("max_iocs", 500))]
        iocs = dict(ranked)
        if not iocs:
            sources["hunt"] = {"status": "no_data", "mode": "incremental", "domain": "soc", "reason": "no recent indicators"}
            state.data_quality["hunt"] = {"indicators": 0, "hits": 0}
            return state
        provider = str(cfg.get("provider", "sentinel")).lower()
        s = cfg.get("settings") or {}
        try:
            rows = self._query(provider, s, iocs, hours, cfg.get("query"))
        except Exception as exc:          # a failed hunt must never resolve earlier sightings
            err = f"{type(exc).__name__}: {exc}"[:300]
            sources["hunt"] = {"status": "failed", "mode": "incremental", "domain": "soc", "error": err}
            state.data_quality.setdefault("agent_failures", []).append({"agent": self.name, "source": "hunt", "error": err})
            ctx.record(self.name, "source_failed", source="hunt", error=err)
            return state
        findings = self.to_findings(rows, iocs, ctx.now)
        have = {f.finding_id for f in state.findings}
        state.findings += [f for f in findings if f.finding_id not in have]
        sources["hunt"] = {"status": "ok", "mode": "incremental", "domain": "soc", "items": len(findings)}
        state.data_quality["hunt"] = {"provider": provider, "indicators": len(iocs), "rows": len(rows), "hits": len(findings),
                                      "by_kind": {k: sum(1 for m in iocs.values() if m["kind"] == k) for k in ("ip", "domain", "hash")}}
        ctx.record(self.name, "hunted", provider=provider, indicators=len(iocs), hits=len(findings))
        return state

    def _query(self, provider: str, s: dict, iocs: dict, hours: int, override: str | None) -> list[dict[str, Any]]:
        from ..connectors.adapters.base import http_client
        if provider == "sentinel":
            from ..connectors.adapters.ms_graph_security import get_token
            from ..connectors.adapters.siem import LA_SCOPE, SentinelQueryAdapter
            ad = SentinelQueryAdapter(Domain.SOC, "Threat hunt", {**s, "query": "hunt"})
            ad.require("workspace_id", "tenant_id", "client_id", "client_secret")
            with http_client(180) as c:
                token = get_token(c, s["tenant_id"], s["client_id"], s["client_secret"], scope=LA_SCOPE)
                return ad._query(c, token, self.build_kql(iocs, hours, override), max(1, hours // 24 + 1))
        if provider == "splunk":
            from ..connectors.adapters.siem import SplunkSearchAdapter
            ad = SplunkSearchAdapter(Domain.SOC, "Threat hunt", {**s, "search": "hunt"})
            ad.require("base_url", "token")
            with http_client(300, verify=s.get("ca_bundle") or True) as c:
                return ad._search(c, self.build_spl(iocs, hours, s.get("scope", "index=*"), override), f"-{hours}h")
        if provider == "qradar":
            from ..connectors.adapters.qradar import QRadarAdapter
            ad = QRadarAdapter(Domain.SOC, "Threat hunt", {**s, "aql": "hunt"})
            ad.require("base_url", "token")
            with http_client(300, verify=s.get("ca_bundle") or True) as c:
                hits = ad.run_aql(c, self.build_aql(iocs, hours, s.get("domain_property"), s.get("hash_property"), override))
            return _aggregate(hits, ("sourceip", "destinationip", "domain_value", "hash_value"), ("sourceip",),
                              ("username",), "starttime", "logsource")
        if provider == "elastic":
            from ..connectors.adapters.elastic import ElasticAdapter
            ad = ElasticAdapter(Domain.SOC, "Threat hunt", s)
            ad.require("base_url", "index")
            fields = ["@timestamp", "host.name", "user.name", "event.dataset", "event.module", *ECS_IP, *ECS_DOMAIN, *ECS_HASH]
            with http_client(300, verify=s.get("ca_bundle") or True) as c:
                hits = ad.search(c, s["index"], self.build_es_query(iocs, hours), int(s.get("max_rows", 5000)),
                                 "@timestamp:desc", fields)
            return _aggregate(hits, (*ECS_IP, *ECS_DOMAIN, *ECS_HASH), ("host.name", "source.ip"), ("user.name",),
                              "@timestamp", "event.dataset")
        raise ValueError(f"threat_hunt.provider must be sentinel, splunk, qradar or elastic, not {provider!r}")

    @staticmethod
    def to_findings(rows: list[dict[str, Any]], iocs: dict[str, dict], now: datetime) -> list[Finding]:
        """One finding per (indicator, host, user). Indicator values are matched back to the IOC list
        (a URL that contains an IOC domain counts), so any query shape works."""
        from ..connectors.adapters.file_drop import parse_dt
        doms = [i for i, m in iocs.items() if m["kind"] == "domain"]
        out: dict[str, Finding] = {}
        for r in rows:
            vals = r.get("Indicator")
            vals = vals if isinstance(vals, list) else [vals]
            matched = set()
            for v in vals:
                v = str(v or "").strip().lower()
                if not v:
                    continue
                if v in iocs:
                    matched.add(v)
                    continue
                host_part = v.split("/")[2] if v.startswith(("http://", "https://")) and v.count("/") >= 2 else v.split("/")[0]
                if host_part.count(":") == 1 and host_part.rsplit(":", 1)[1].isdigit():
                    host_part = host_part.rsplit(":", 1)[0]          # evil.example:443 / 203.0.113.5:8080
                    if host_part in iocs:
                        matched.add(host_part)
                        continue
                for d in doms:
                    if host_part == d or host_part.endswith("." + d):
                        matched.add(d)
            host = str(r.get("Host") or "").strip() or None
            user = str(r.get("User") or "").strip() or None
            first = parse_dt(r.get("FirstSeen")) or now
            last = parse_dt(r.get("LastSeen")) or first
            for ioc in matched:
                meta = iocs[ioc]
                fid = "soc-hunt-" + hashlib.sha1(f"{ioc}|{(host or '').lower()}|{(user or '').lower()}".encode()).hexdigest()[:16]
                sev = max(Severity.HIGH, meta["severity"], key=SEV_ORDER.index)
                f = out.get(fid)
                hits = int(float(r.get("Hits") or 1))
                if f:
                    f.evidence["hits"] += hits
                    f.first_seen, f.last_seen = min(f.first_seen, first), max(f.last_seen, last)
                    continue
                tlp = meta.get("tlp")
                out[fid] = Finding(
                    finding_id=fid, domain=Domain.SOC, source="lodestar.hunt", finding_type=FindingType.DETECTION,
                    title=f"Threat-intel indicator {ioc} seen on {host or user or 'unknown host'}",
                    description=f"Indicator from {meta['source']} ({meta['title'][:160]}) matched {r.get('Source', 'telemetry')}.",
                    severity=sev, status=Status.OPEN, asset_id=host, user_id=user, first_seen=first, last_seen=last,
                    tlp=tlp if tlp and tlp.lower() in TLP_ORDER else None,
                    remediation="Triage the sighting: confirm the connection / file, isolate the host if malicious, "
                                "block the indicator at proxy / firewall / EDR, and hunt for lateral movement.",
                    evidence={"ioc": ioc, "ioc_kind": meta["kind"], "telemetry": r.get("Source"), "hits": hits,
                              "intel_finding": meta["intel_id"], "_src": "hunt", "_sync": "incremental",
                              "tags": ["ioc_sighting"]})
        return list(out.values())
