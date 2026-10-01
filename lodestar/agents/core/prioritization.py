"""PrioritizationAgent (Phase 1) - the heart of LODESTAR.

Applies the explainable LODESTAR Risk Score to every open finding, assigns a
focus horizon (today / this week / this month / backlog), sets SLA due dates
from the vertical profile and ranks attack paths. Output = the CISO's list.
"""
from __future__ import annotations

from datetime import timedelta, timezone

from ...models import Horizon, Status
from ...scoring import score_finding
from ..base import AgentContext, BaseAgent, PipelineState


class PrioritizationAgent(BaseAgent):
    name = "PrioritizationAgent"
    phase = 1
    description = "Scores and ranks every finding into Today / This week / This month / Backlog."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        cfg = ctx.settings.scoring
        for f in state.findings:
            if f.due_date is None:
                first = f.first_seen if f.first_seen.tzinfo else f.first_seen.replace(tzinfo=timezone.utc)
                f.due_date = first + timedelta(days=ctx.vertical.sla(f.severity.value))
            if f.status in (Status.OPEN, Status.IN_PROGRESS):
                score_finding(f, state.assets.get(f.asset_id) if f.asset_id else None, ctx.vertical, ctx.now, cfg)
        # capacity guard: a Today list nobody can finish is not a priority list
        if cfg.today_capacity:
            today = sorted((f for f in state.findings if f.horizon == Horizon.TODAY), key=lambda f: f.score, reverse=True)
            protected = [f for f in today if f.correlation_ids or f.actively_exploited_in_env or f.kev]
            pids = {f.finding_id for f in protected}
            others = [f for f in today if f.finding_id not in pids]
            room = max(0, cfg.today_capacity - len(protected))
            for f in others[room:]:
                f.horizon = Horizon.THIS_WEEK
                f.why.append(f"Scheduled for this week: Today capacity ({cfg.today_capacity}) reached by higher-risk items")
            state.data_quality["today_deferred"] = len(others[room:])
        by_id = {f.finding_id: f for f in state.findings}
        for c in state.correlations:
            scores = [by_id[i].score for i in c.finding_ids if i in by_id]
            c.score = round(min(100.0, max(scores, default=0) + 5 * (len(c.domains) - 1)), 1)
        state.correlations.sort(key=lambda c: c.score, reverse=True)
        state.findings.sort(key=lambda f: f.score, reverse=True)
        return state
