"""ConnectorAgent - one instance per control domain (EDR, WAF, PAM, threat intel ...).

The agent is product-agnostic: it delegates collection to one or more adapters
(mock / file_drop / webhook / vendor API / SIEM query / feeds / mailbox) and then
enforces the contract:
  * per-source failure isolation (a failed source never resolves its findings)
  * per-source sync cursor and cadence (interval_minutes, or the domain default under the scheduler),
    persisted in connector_state together with the last good health and consecutive failures
  * a skipped or failed source contributes its last good health (aged) instead of a dead control
  * every finding is stamped with its source key and sync mode for the LifecycleAgent
  * one merged health record per domain
"""
from __future__ import annotations

from datetime import timedelta

from ...models import ControlHealth
from ..base import AgentContext, BaseAgent, PipelineState
from .adapters import build_adapter
from .domains import SPECS, DomainSpec, default_cadence


class ConnectorAgent(BaseAgent):
    def __init__(self, spec: DomainSpec, sources: list[tuple]):
        self.spec = spec
        self.name = spec.agent_name
        self.phase = spec.phase
        self.description = spec.purpose
        self.adapters, self.intervals, self.keys, self.expects = [], [], [], []
        seen: dict[str, int] = {}
        for src in sources:
            a, p, s = src[0], src[1], src[2]
            ad = build_adapter(a, spec.domain, p or spec.typical_products[0], s)
            key = f"{spec.domain.value}/{a}"
            seen[key] = seen.get(key, 0) + 1
            self.keys.append(key if seen[key] == 1 else f"{key}#{seen[key]}")
            self.adapters.append(ad)
            self.intervals.append(None if len(src) < 4 or src[3] is None else int(src[3]))
            self.expects.append(dict(src[4]) if len(src) > 4 and src[4] else {})
        self.adapter = self.adapters[0]   # backwards compatibility

    def interval_for(self, i: int, ctx: AgentContext) -> int:
        """Explicit interval_minutes always applies; otherwise the domain's default cadence applies to
        scheduled runs (`lodestar schedule`), and manual runs fetch every source."""
        if self.intervals[i] is not None:
            return self.intervals[i]
        if getattr(ctx, "scheduled", False) and ctx.settings.mode == "live" and \
                (ctx.settings.raw.get("ingestion") or {}).get("default_cadence", True):
            return default_cadence(self.spec.domain)
        return 0

    @staticmethod
    def is_due(interval: int, last_success, now) -> bool:
        if not interval or last_success is None:
            return True
        slack = timedelta(minutes=min(5.0, interval * 0.1))      # scheduler jitter must not skip a whole cycle
        return now >= last_success + timedelta(minutes=interval) - slack

    @staticmethod
    def _carried(st: dict, now) -> ControlHealth | None:
        """Last good health of a source that was skipped or failed this run, aged by the time since it was
        collected - a single missed fetch must not look like a dead control (the IngestionMonitorAgent
        raises failures after `failing_after` consecutive misses instead)."""
        if not st.get("health") or not st.get("last_success"):
            return None
        try:
            h = ControlHealth.model_validate(st["health"])
        except Exception:
            return None
        age = max(0.0, (now - st["last_success"]).total_seconds() / 3600)
        h.data_freshness_hours = round(h.data_freshness_hours + age, 1)
        return h

    def _merge_health(self, parts) -> ControlHealth | None:
        """parts: (adapter, health | None, error | None) per source that has something to say this run."""
        healths = [(ad, h) for ad, h, _ in parts if h is not None]
        failed = [(ad, err) for ad, h, err in parts if err and h is None]
        if not healths and not failed:
            return None
        if len(parts) == 1 and healths:
            return healths[0][1]
        if not healths:
            ad, err = failed[0]
            return ControlHealth(domain=self.spec.domain, product=ad.product, coverage_pct=0.0, data_freshness_hours=999.0,
                                 health_issues=[f"{ad.product}: source failed ({err[:120]})"])
        n = len(parts)
        ok = [h for _, h in healths]
        kpis: dict = {}
        for h in ok:
            for k, v in h.kpis.items():
                kpis[k] = kpis.get(k, 0) + v if isinstance(v, (int, float)) and isinstance(kpis.get(k, 0), (int, float)) else v
        stale = [ad.product for ad, h in healths if h.data_freshness_hours > 48]
        kpis.update({"feeds_active": len(ok) - len(stale), "feeds_stale": len(stale) + len(failed)})
        issues = [f"{ad.product}: source failed ({err[:80]})" for ad, err in failed] + \
                 [f"{p}: no new data for > 48h" for p in stale] + [i for h in ok for i in h.health_issues]
        return ControlHealth(
            domain=self.spec.domain, product=" + ".join(ad.product for ad, *_ in parts),
            coverage_pct=round(100 * (len(ok) - len(stale)) / n, 1),
            data_freshness_hours=min((h.data_freshness_hours for h in ok), default=999.0),
            policy_drift_items=sum(h.policy_drift_items for h in ok), health_issues=issues, kpis=kpis)

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        org = ctx.settings.org_name
        sources = state.data_quality.setdefault("sources", {})
        write = ctx.store is not None and not ctx.dry_run
        parts, findings, warnings, fetched = [], [], [], 0
        for i, (ad, key) in enumerate(zip(self.adapters, self.keys, strict=True)):
            st = ctx.store.connector_state(org, key) if ctx.store is not None else {}
            ad.cursor = None if getattr(ctx, "ignore_cursor", False) else st.get("cursor")
            interval = self.interval_for(i, ctx)
            cadence = self.intervals[i] if self.intervals[i] is not None else default_cadence(self.spec.domain)
            base = {"mode": ad.sync_mode, "domain": self.spec.domain.value, "adapter": ad.name, "product": ad.product,
                    "interval_minutes": interval, "cadence_minutes": cadence, "expect": self.expects[i]}
            if not ctx.force and not self.is_due(interval, st.get("last_success"), ctx.now):
                due = st["last_success"] + timedelta(minutes=interval)
                sources[key] = {**base, "status": "skipped", "reason": f"interval {interval} min not elapsed",
                                "next_due": due.isoformat()}
                carried = self._carried(st, ctx.now)
                if carried is not None:
                    parts.append((ad, carried, None))
                continue
            fetched += 1
            try:
                r = ad.fetch(ctx)
            except Exception as exc:      # one broken source must not hide the others, nor resolve its findings
                err = f"{type(exc).__name__}: {exc}"
                sources[key] = {**base, "status": "failed", "error": err[:300],
                                "consecutive_failures": int(st.get("failures") or 0) + 1}
                state.data_quality.setdefault("agent_failures", []).append({"agent": self.name, "source": key, "error": err[:300]})
                ctx.record(self.name, "source_failed", source=key, error=err[:300])
                parts.append((ad, self._carried(st, ctx.now), err))
                if write:
                    ctx.store.set_connector_state(org, key, ok=False, error=err, at=ctx.now)
                    ctx.store.record_source_run(org, key, "failed", at=ctx.now)
                continue
            no_data = r.health is None and not r.findings
            sources[key] = {**base, "status": "no_data" if no_data else "ok", "items": len(r.findings),
                            "warnings": r.warnings[:10]}
            if r.health is not None:
                sources[key]["health"] = {"coverage_pct": r.health.coverage_pct,
                                          "data_freshness_hours": r.health.data_freshness_hours}
            for f in r.findings:
                f.evidence["_src"], f.evidence["_sync"] = key, ad.sync_mode
            findings += r.findings
            warnings += r.warnings
            if r.health is not None or r.findings:
                parts.append((ad, r.health, None))
            if write:
                if not no_data:
                    ctx.store.set_connector_state(org, key, ok=True, cursor=r.cursor, items=len(r.findings), at=ctx.now,
                                                  health=r.health.model_dump_json() if r.health is not None else None)
                ctx.store.record_source_run(org, key, "no_data" if no_data else "ok", len(r.findings),
                                            len(r.warnings), at=ctx.now)
        dq = state.data_quality.setdefault("connectors", {})
        health = self._merge_health(parts)
        if not fetched:                   # everything skipped by interval - LifecycleAgent carries findings forward
            if health is not None:
                state.controls.append(health)
                dq[self.spec.domain.value] = {"adapter": ",".join(a.name for a in self.adapters), "product": health.product,
                                              "findings": 0, "warnings": [], "source_failures": [], "skipped": True}
            return state
        if health is None and not findings:
            state.data_quality.setdefault("not_integrated", []).append(self.spec.domain.value)
            ctx.record(self.name, "no_data", domain=self.spec.domain.value, warnings=warnings[:3])
            return state
        seen = {f.finding_id for f in state.findings}
        added = 0
        for f in findings:
            if f.domain != self.spec.domain:
                f.domain = self.spec.domain
            if f.finding_id in seen:
                continue
            seen.add(f.finding_id)
            state.findings.append(f)
            added += 1
        health = health or ControlHealth(domain=self.spec.domain, product=self.adapter.product, coverage_pct=0.0,
                                         data_freshness_hours=999.0, health_issues=["Adapter returned no health telemetry"])
        state.controls.append(health)
        dq[self.spec.domain.value] = {"adapter": ",".join(a.name for a in self.adapters), "product": health.product,
                                      "findings": added, "warnings": warnings[:20],
                                      "source_failures": [e for *_, e in parts if e]}
        ctx.record(self.name, "collected", domain=self.spec.domain.value, findings=added, warnings=len(warnings))
        return state


def build_connector_agents(settings, max_phase: int) -> list[ConnectorAgent]:
    agents = []
    for domain, cc in settings.connectors.items():
        sp = SPECS[domain]
        if not cc.enabled or sp.phase > max_phase:
            continue
        if settings.mode == "demo":
            sources = [("mock", cc.product, {}, None, {})]
        elif cc.sources:
            sources = [(s["adapter"], s["product"], s["settings"], s.get("interval_minutes"), s.get("expect") or {})
                       for s in cc.sources]
        else:
            sources = [(cc.adapter, cc.product, cc.settings, cc.interval_minutes, cc.expect)]
        agents.append(ConnectorAgent(sp, sources))
    return sorted(agents, key=lambda a: (a.phase, a.spec.domain.value))
