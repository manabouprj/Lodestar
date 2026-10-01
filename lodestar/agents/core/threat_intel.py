"""ThreatIntelAgent (Phase 1) - exploitability context.

* CISA Known Exploited Vulnerabilities (KEV) catalogue
* FIRST EPSS probability of exploitation (next 30 days)
* in-environment exploitation: a detection (EDR/WAF/SOC/IPS) that references
  the same CVE on the same asset flips `actively_exploited_in_env`

Offline-first: uses a local cache (data/intel/*.json) or the demo dataset.
Live refresh (threat_intel.live: true) pulls the public feeds daily.
"""
from __future__ import annotations

import json
from pathlib import Path

from ...models import Domain, FindingType, Severity, Status
from ..base import AgentContext, BaseAgent, PipelineState

SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _at_least(s: Severity, floor: Severity) -> Severity:
    return s if SEV_ORDER.index(s) >= SEV_ORDER.index(floor) else floor

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class ThreatIntelAgent(BaseAgent):
    name = "ThreatIntelAgent"
    phase = 1
    description = "Enriches vulnerabilities with CISA KEV, FIRST EPSS and in-environment exploitation evidence."

    def _load(self, ctx: AgentContext) -> tuple[set[str], dict[str, float]]:
        if ctx.dataset and ctx.dataset.get("intel"):
            intel = ctx.dataset["intel"]
            return set(intel.get("kev", [])), {k: float(v) for k, v in intel.get("epss", {}).items()}
        cfg = (ctx.settings.raw.get("threat_intel") or {})
        cache = ctx.settings.path(cfg.get("cache_dir", "data/intel"))
        kev, epss = set(), {}
        if cfg.get("live"):
            self._refresh(cache, ctx)
        kev_file, epss_file = cache / "kev.json", cache / "epss.json"
        if kev_file.exists():
            data = json.loads(kev_file.read_text(encoding="utf-8"))
            kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
        if epss_file.exists():
            epss = {k: float(v) for k, v in json.loads(epss_file.read_text(encoding="utf-8")).items()}
        return kev, epss

    def _refresh(self, cache: Path, ctx: AgentContext) -> None:
        from ..connectors.adapters.base import http_client, request_with_retry
        cache.mkdir(parents=True, exist_ok=True)
        try:
            with http_client(60) as c:
                (cache / "kev.json").write_text(request_with_retry(c, "GET", KEV_URL).text, encoding="utf-8")
        except Exception as exc:
            ctx.record(self.name, "kev_refresh_failed", error=str(exc))

    def _refresh_epss(self, cves: list[str], cache: Path, ctx: AgentContext) -> dict[str, float]:
        from ..connectors.adapters.base import http_client, request_with_retry
        out: dict[str, float] = {}
        try:
            with http_client(60) as c:
                for i in range(0, len(cves), 100):
                    batch = ",".join(cves[i:i + 100])
                    for row in request_with_retry(c, "GET", EPSS_URL, params={"cve": batch}).json().get("data", []):
                        out[row["cve"]] = float(row["epss"])
            cache.mkdir(parents=True, exist_ok=True)
            (cache / "epss.json").write_text(json.dumps(out), encoding="utf-8")
        except Exception as exc:
            ctx.record(self.name, "epss_refresh_failed", error=str(exc))
        return out

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        kev, epss = self._load(ctx)
        cfg = (ctx.settings.raw.get("threat_intel") or {})
        if cfg.get("live") and not ctx.dataset:
            cves = sorted({f.cve for f in state.findings if f.cve and f.cve not in epss})
            if cves:
                epss.update(self._refresh_epss(cves, ctx.settings.path(cfg.get("cache_dir", "data/intel")), ctx))
        exploited = {(f.asset_id, f.evidence.get("cve")) for f in state.findings
                     if f.finding_type in (FindingType.DETECTION, FindingType.INCIDENT) and f.evidence.get("cve")}
        kev_hits = 0
        for f in state.findings:
            if not f.cve:
                continue
            if f.cve in kev:
                f.kev = True
                kev_hits += 1
            if f.cve in epss and not f.epss:
                f.epss = epss[f.cve]
            if (f.asset_id, f.cve) in exploited:
                f.actively_exploited_in_env = True
        state.intel = {"kev_catalogue_size": len(kev), "kev_matches": kev_hits, "epss_scored": len(epss)}
        self._relevance(ctx, state)
        return state

    # ------------------------------------------------------------------ external intelligence
    def _relevance(self, ctx: AgentContext, state: PipelineState) -> None:
        """Keep only advisories / indicators that touch OUR assets, sector or telemetry."""
        intel = [f for f in state.findings if f.domain == Domain.THREAT_INTEL]
        if not intel:
            return
        others = [f for f in state.findings if f.domain != Domain.THREAT_INTEL]
        estate_cves: dict[str, list] = {}
        for f in others:
            if f.cve and f.status in (Status.OPEN, Status.IN_PROGRESS):
                estate_cves.setdefault(f.cve.upper(), []).append(f)
        telemetry_iocs = {k[4:] for f in others for k in f.entity_keys if k.startswith("ioc:")}
        by_tag: dict[str, list[str]] = {}
        for a in state.assets.values():
            for t in a.tags:
                by_tag.setdefault(t.lower(), []).append(a.asset_id)
        sectors = set(ctx.vertical.sectors)
        kept, dropped, sightings, fanned = [], 0, 0, 0
        for f in intel:
            ev = f.evidence
            cves = {c.upper() for c in ev.get("cves", []) or ([f.cve] if f.cve else [])}
            m_cve = sorted(cves & set(estate_cves))
            ioc_list = [str(i).lower() for i in (ev.get("iocs") or [])] + ([str(ev["ioc"]).lower()] if ev.get("ioc") else [])
            m_ioc = sorted(set(ioc_list) & telemetry_iocs)
            prods = [p for p in ev.get("products", []) if p.startswith("product:")]
            m_assets = sorted({a for p in prods for a in by_tag.get(p, [])})
            s_hit = sorted(set(ev.get("sectors", [])) & sectors)
            already = f.asset_id in state.assets
            if not (m_cve or m_ioc or m_assets or already or (s_hit and SEV_ORDER.index(f.severity) >= 3)):
                dropped += 1
                continue
            tags = list(dict.fromkeys(ev.get("tags", []) + ["relevant"] + (["sector_targeted"] if s_hit else [])))
            ev["tags"] = tags
            ev.update({"matched_cves": m_cve, "matched_iocs": m_ioc, "matched_assets": m_assets[:50], "matched_sectors": s_hit})
            f.entity_keys += [f"cve:{c}" for c in cves] + [f"ioc:{i}" for i in ioc_list[:200]]
            if m_ioc:
                sightings += 1
                tags.append("sighted")
                f.finding_type = FindingType.DETECTION
                f.title = f"IOC from {f.source} sighted in our telemetry: {f.title}"
                f.severity = _at_least(f.severity, Severity.HIGH)
            if s_hit and m_cve:
                f.severity = _at_least(f.severity, Severity.HIGH)
            if "exploited" in tags:
                for c in m_cve:
                    for ef in estate_cves[c]:
                        ef.evidence["sector_exploited"] = f"{f.source}" + (f" ({', '.join(s_hit)} sector)" if s_hit else "")
            if m_assets and not already:
                for aid in m_assets[:25]:
                    c = f.model_copy(deep=True)
                    c.finding_id, c.asset_id = f"{f.finding_id}-{aid}", aid
                    kept.append(c)
                    fanned += 1
            else:
                if not f.asset_id and m_cve:
                    f.asset_id = estate_cves[m_cve[0]][0].asset_id
                kept.append(f)
        state.findings = others + kept
        state.intel.update({"advisories_ingested": len(intel), "advisories_relevant": len(intel) - dropped,
                            "advisories_dropped_not_relevant": dropped, "ioc_sightings": sightings, "asset_matches": fanned})
        state.data_quality["intel"] = dict(state.intel)
        for c in state.controls:
            if c.domain == Domain.THREAT_INTEL:
                c.kpis.update({"advisories_relevant_7d": len(intel) - dropped, "advisories_ingested_7d": len(intel),
                               "ioc_sightings_7d": sightings})
