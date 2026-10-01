"""Agent catalogue - single source of truth for docs, API and CLI."""
from __future__ import annotations

from .agents.connectors.domains import SPECS
from .agents.core import (
    ActionAgent,
    AssetContextAgent,
    ComplianceMappingAgent,
    ControlAssuranceAgent,
    CorrelationAgent,
    DataQualityAgent,
    DecisionAgent,
    LifecycleAgent,
    PrioritizationAgent,
    ThreatHuntAgent,
    ThreatIntelAgent,
)

NARRATIVE = {"name": "NarrativeAgent", "phase": 4, "kind": "core",
             "description": "Business-language executive summaries; template engine by default, optional LLM with numeric grounding guardrail."}
REPORTING = {"name": "ReportingAgent", "phase": 1, "kind": "core",
             "description": "Weekly (phase 1), monthly (phase 3) and quarterly board (phase 4) reports in HTML, Markdown and JSON."}
CHATOPS = {"name": "ChatOpsAgent", "phase": 2, "kind": "core",
           "description": "Conversational interface to the prioritisation agent in Slack, Microsoft Teams, the dashboard and CLI; "
                          "pushes the daily focus brief and urgent decisions; records verdicts by mapped role."}
ORCH = {"name": "Orchestrator", "phase": 0, "kind": "core",
        "description": "Builds the phase-appropriate pipeline, runs agents with failure isolation, persists results and audit."}


def agent_catalog() -> list[dict]:
    core = [ORCH] + [{"name": a.name, "phase": a.phase, "kind": "core", "description": a.description} for a in (
        AssetContextAgent, DataQualityAgent, LifecycleAgent, ThreatHuntAgent, ThreatIntelAgent, ControlAssuranceAgent, PrioritizationAgent,
        CorrelationAgent, ActionAgent, DecisionAgent, ComplianceMappingAgent)] + [REPORTING, NARRATIVE, CHATOPS]
    conn = [{"name": s.agent_name, "phase": s.phase, "kind": "connector", "domain": s.domain.value, "title": s.title,
             "description": s.purpose, "products": list(s.typical_products), "kpis": list(s.kpis),
             "least_privilege": s.least_privilege, "live_adapters": list(s.live_adapters) + ["file_drop", "webhook"]}
            for s in SPECS.values()]
    return sorted(core, key=lambda a: a["phase"]) + sorted(conn, key=lambda a: (a["phase"], a["name"]))
