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

from ...models import FindingType
from ..base import AgentContext, BaseAgent, PipelineState

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
        return state
