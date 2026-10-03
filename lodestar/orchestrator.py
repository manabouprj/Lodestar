"""Orchestrator - assembles the agent pipeline for the configured deployment
phase, runs it, computes KRIs/posture and persists the result.

    Phase 0  AssetContext, DataQuality, IngestionMonitor,
             Lifecycle                                      (foundation)
    Phase 1  + EDR, VMDR, Identity, SOC, Email connectors,
             ThreatIntel, ControlAssurance, Prioritization  (see & prioritise)
    Phase 2  + Firewall, WAF, Proxy, ZTNA, PAM, Cloud,
             Correlation, Action, Decision desk             (attack paths, action, human decisions)
    Phase 3  + SAST, DAST, Brand, AI, DLP, OT, Backup,
             ComplianceMapping                              (full coverage)
    Phase 4  + Narrative (LLM) & quarterly board reporting  (executive & scale)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .agents.base import AgentContext, BaseAgent, PipelineState
from .agents.connectors import build_connector_agents
from .agents.core import (
    ActionAgent,
    AssetContextAgent,
    ComplianceMappingAgent,
    ControlAssuranceAgent,
    CorrelationAgent,
    DataQualityAgent,
    DecisionAgent,
    IngestionMonitorAgent,
    LifecycleAgent,
    PrioritizationAgent,
    ThreatHuntAgent,
    ThreatIntelAgent,
)
from .config import Settings
from .metrics import build_snapshot, compute_kris, kri_coverage, lifecycle_kpis, manual_kpis, posture_score
from .models import DailySnapshot, PipelineResult
from .store import Store
from .verticals import load_vertical

log = logging.getLogger("lodestar")


def load_dataset(path: Path | None) -> dict | None:
    if not path:
        return None
    if not path.exists():
        raise FileNotFoundError(f"Demo dataset not found: {path}. Run `python -m lodestar demo-data` first.")
    return json.loads(path.read_text(encoding="utf-8"))


def build_pipeline(settings: Settings) -> list[BaseAgent]:
    p = settings.deployment_phase
    stages: list[BaseAgent] = [AssetContextAgent()]
    stages += build_connector_agents(settings, p)
    if (settings.raw.get("threat_hunt") or {}).get("enabled") and ThreatHuntAgent.phase <= p:
        stages.append(ThreatHuntAgent())      # before DataQuality so sightings get entity resolution
    stages += [DataQualityAgent(), IngestionMonitorAgent(), LifecycleAgent()]
    for agent in (ThreatIntelAgent(), ControlAssuranceAgent(), CorrelationAgent(), PrioritizationAgent(),
                  ComplianceMappingAgent(), ActionAgent(), DecisionAgent()):
        if agent.phase <= p:
            stages.append(agent)
    return stages


class Orchestrator:
    def __init__(self, settings: Settings, store: Store | None = None, dataset: dict | None = None):
        self.settings = settings
        self.store = store or Store(settings.sqlite_path, keep_runs=int((settings.raw.get("storage") or {}).get("keep_runs", 5)))
        self.dataset = dataset if dataset is not None else (
            load_dataset(settings.demo_dataset) if settings.mode == "demo" else None)
        if self.dataset:
            settings.org_name = self.dataset.get("org_name", settings.org_name)
            settings.vertical = self.dataset.get("vertical", settings.vertical)
        self.vertical = load_vertical(settings.vertical)

    def _now(self) -> datetime:
        if self.dataset and self.dataset.get("as_of"):
            return datetime.fromisoformat(self.dataset["as_of"])
        return datetime.now(timezone.utc)

    def run(self, persist: bool = True, force: bool = False, lock_wait: float = 0,
            scheduled: bool = False) -> PipelineResult:
        """One pipeline run. Persisting runs hold a per-org lease lock so the API, scheduler and CLI
        never run the same organisation concurrently. `scheduled` = run by `lodestar schedule`: each
        source is fetched on its own cadence (interval_minutes or the domain default)."""
        if not persist:
            return self._run(persist=False, force=force, scheduled=scheduled)
        with self.store.lease(f"run:{self.settings.org_name}", ttl_seconds=3 * 3600, wait_seconds=lock_wait):
            return self._run(persist=True, force=force, scheduled=scheduled)

    def _run(self, persist: bool, force: bool, scheduled: bool = False) -> PipelineResult:
        now = self._now()
        ctx = AgentContext(settings=self.settings, vertical=self.vertical, now=now, dataset=self.dataset,
                           store=self.store, dry_run=not persist, force=force, scheduled=scheduled)
        state = PipelineState()
        for agent in build_pipeline(self.settings):
            state = agent(ctx, state)

        computed = {} if self.dataset else lifecycle_kpis(
            self.store.resolution_stats(self.settings.org_name, 90), state.findings, now)
        manual, manual_src, stale = manual_kpis(self.settings.raw.get("kpis_manual"), now)
        prov: dict[str, str] = {}
        kris = compute_kris(state.findings, state.controls, state.correlations, state.assets, now,
                            computed=computed, manual=manual, manual_sources=manual_src, provenance=prov,
                            phase=self.settings.deployment_phase)
        cov, missing = kri_coverage(kris, self.vertical)
        posture = posture_score(kris, state.controls, state.findings, state.correlations, self.vertical)
        kris["posture_score"] = posture
        snap = build_snapshot(now.date().isoformat(), state.findings, state.controls, state.correlations,
                              kris, posture, now, new_since=now - timedelta(days=7))
        snap.kri_sources, snap.kri_coverage_pct, snap.kri_missing = prov, cov, missing
        snap.posture_provisional = cov < 60 or state.data_quality.get("confidence") == "low"
        state.data_quality["kpis"] = {"coverage_pct": cov, "not_measured": missing, "manual_stale": stale,
                                      "lifecycle_computed": sorted(computed)}
        state.data_quality["phase"] = self.settings.deployment_phase
        state.data_quality["agents_run"] = [e["agent"] for e in ctx.audit if e["event"] == "completed"]

        if self.dataset and self.dataset.get("history"):
            self.store.save_snapshots(self.settings.org_name,
                                      [DailySnapshot.model_validate(h) for h in self.dataset["history"]])
        history = [h for h in self.store.history(self.settings.org_name) if h.date != snap.date] + [snap]
        history = [h for h in history if h.date <= snap.date][-400:]

        result = PipelineResult(
            org_name=self.settings.org_name, vertical=self.vertical.id, generated_at=now,
            findings=state.findings, controls=state.controls, correlations=state.correlations,
            snapshot=snap, history=history, data_quality=state.data_quality, compliance=state.compliance,
            actions=state.actions, decisions=state.decisions,
            asset_names={a.asset_id: a.name for a in state.assets.values()})
        if persist:
            self.store.save_result(result, state.lifecycle)
            self.store.audit_many(ctx.audit)
        return result
