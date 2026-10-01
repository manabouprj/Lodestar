"""ActionAgent (Phase 2) - turns priorities into owned, trackable work.

Creates ticket drafts for every Today item and every attack path, grouped by
owner team. HUMAN-IN-THE-LOOP: drafts are never auto-submitted; an analyst
approves them in the dashboard/API, then they are pushed to ITSM
(ServiceNow / Jira) - or exported - by lodestar.itsm.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from ...models import Horizon, Status
from ..base import AgentContext, BaseAgent, PipelineState


class ActionAgent(BaseAgent):
    name = "ActionAgent"
    phase = 2
    description = "Drafts owner-assigned remediation tickets (human approval required before ITSM submission)."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        actions = []
        by_id = {f.finding_id: f for f in state.findings}
        for c in state.correlations:
            members = [by_id[i] for i in c.finding_ids if i in by_id]
            teams = sorted({f.owner_team or "Security Operations" for f in members})
            actions.append({
                "action_id": "ACT-" + c.correlation_id[4:],
                "kind": "attack_path", "priority": "P1", "title": c.title, "entity": c.entity,
                "teams": teams, "recommended_action": c.recommended_action, "finding_ids": c.finding_ids,
                "due_hours": 24, "approval_required": True, "status": "draft"})
        grouped = defaultdict(list)
        for f in state.findings:
            if f.status in (Status.OPEN, Status.IN_PROGRESS) and f.horizon == Horizon.TODAY:
                grouped[f.owner_team or "Security Operations"].append(f)
        for team, items in sorted(grouped.items()):
            ids = [f.finding_id for f in items]
            actions.append({
                "action_id": "ACT-" + hashlib.sha1(("|".join(sorted(ids)) + team).encode()).hexdigest()[:10],
                "kind": "team_queue", "priority": "P1", "title": f"{len(items)} priority item(s) for {team}",
                "entity": team, "teams": [team],
                "recommended_action": "; ".join(dict.fromkeys(f.remediation for f in items[:3] if f.remediation))[:500],
                "finding_ids": ids, "due_hours": 24, "approval_required": True, "status": "draft"})
        state.actions = actions
        return state
