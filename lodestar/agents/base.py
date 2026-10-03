"""Agent primitives.

LODESTAR agents are small, single-purpose units with a uniform contract:
    agent.run(ctx, state) -> state
They are composed by the Orchestrator into a pipeline. Each agent declares
the deployment phase it belongs to so the platform can be rolled out
incrementally (see docs/DEPLOYMENT_PHASES.md).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..models import Asset, ControlHealth, Correlation, Finding
from ..verticals import VerticalProfile

log = logging.getLogger("lodestar")


@dataclass
class AgentContext:
    settings: Any                      # lodestar.config.Settings
    vertical: VerticalProfile
    now: datetime
    dataset: dict[str, Any] | None = None   # demo dataset (mode=demo)
    store: Any = None                        # lodestar.store.Store
    audit: list[dict[str, Any]] = field(default_factory=list)
    dry_run: bool = False                    # True = do not write cursors / connector state (tests, previews)
    force: bool = False                      # True = ignore connector intervals
    scheduled: bool = False                  # True = run by `lodestar schedule`: domain default cadences apply
    ignore_cursor: bool = False              # True = fetch the full lookback window (sanity checks)

    def record(self, agent: str, event: str, **details: Any) -> None:
        entry = {"ts": datetime.utcnow().isoformat() + "Z", "agent": agent, "event": event, **details}
        self.audit.append(entry)
        log.info("%s | %s | %s", agent, event, details)


@dataclass
class PipelineState:
    assets: dict[str, Asset] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    controls: list[ControlHealth] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    intel: dict[str, Any] = field(default_factory=dict)
    data_quality: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    actions: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    lifecycle: dict[str, Any] = field(default_factory=dict)
    identities: list[Any] = field(default_factory=list)      # lodestar.entities.Identity
    resolver: Any = None                                     # lodestar.entities.EntityResolver


class BaseAgent:
    name: str = "BaseAgent"
    phase: int = 0
    description: str = ""

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:  # pragma: no cover
        raise NotImplementedError

    def __call__(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        start = time.perf_counter()
        try:
            out = self.run(ctx, state)
            ctx.record(self.name, "completed", ms=round((time.perf_counter() - start) * 1000, 1))
            return out
        except Exception as exc:  # an agent failure must never take down the pipeline
            ctx.record(self.name, "failed", error=f"{type(exc).__name__}: {exc}")
            log.exception("Agent %s failed", self.name)
            state.data_quality.setdefault("agent_failures", []).append({"agent": self.name, "error": str(exc)})
            return state
