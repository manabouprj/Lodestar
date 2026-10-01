"""Recording human verdicts on Decision Desk items - shared by the API, Slack and Teams.

Authorisation: any analyst may decide operational items; risk acceptance,
regulatory (breach / STR) and safety-critical (OT) decisions require the
`ciso` role. Every verdict is audit-logged with the channel it came from.
Only an *approved* verdict releases the linked action to ITSM.
"""
from __future__ import annotations

from typing import Any

from .itsm import submit
from .models import PipelineResult
from .store import Store

ROLE_RANK = {"exec": 1, "analyst": 2, "ciso": 3}
CISO_ONLY = {"risk_acceptance", "safety_critical", "breach_assessment", "str_filing", "regulatory_notification"}
# Note: in production map MLRO / Head of Fraud to the `ciso` (decision-authority) role or add roles in ROLE_RANK.


class DecisionError(ValueError):
    def __init__(self, msg: str, code: int = 400):
        super().__init__(msg)
        self.code = code


def status_for(choice: str) -> str:
    c = choice.lower()
    if c.startswith(("reject", "close as false")):
        return "rejected"
    if c.startswith("escalate"):
        return "escalated"
    if c.startswith(("monitor", "defer", "investigate further", "schedule")):
        return "deferred"
    return "approved"


def find(result: PipelineResult, decision_id: str) -> dict[str, Any] | None:
    return next((d for d in result.decisions if d["decision_id"].lower() == decision_id.lower()), None)


def record(store: Store, result: PipelineResult, decision_id: str, choice: str, role: str, *,
           note: str = "", channel: str = "dashboard", actor: str = "", itsm_cfg: dict | None = None) -> dict[str, Any]:
    d = find(result, decision_id)
    if not d:
        raise DecisionError(f"Decision {decision_id} not found", 404)
    if ROLE_RANK.get(role, 0) < ROLE_RANK["analyst"]:
        raise DecisionError("Your role can view decisions but not make them", 403)
    if (d["type"] in CISO_ONLY or d.get("regulatory")) and role != "ciso":
        raise DecisionError("Regulatory, risk-acceptance and safety-critical decisions need the decision-authority role "
                            "(ciso). Map the MLRO / Head of Fraud / plant manager to it in your role config.", 403)
    allowed = d["options"] + ["Escalate"]
    match = next((o for o in allowed if o.lower() == choice.lower()), None)
    if match is None:
        # accept a 1-based option number from chat ("approve DEC-x 1")
        if choice.isdigit() and 1 <= int(choice) <= len(allowed):
            match = allowed[int(choice) - 1]
        else:
            raise DecisionError(f"Choice must be one of: {allowed}")
    status = status_for(match)
    store.record_decision(result.org_name, d["decision_id"], status, match, role, note)
    out: dict[str, Any] = {"decision_id": d["decision_id"], "status": status, "choice": match, "role": role}
    if status == "approved" and d.get("action_id"):
        action = next((a for a in result.actions if a["action_id"] == d["action_id"]), None)
        if action:
            out["itsm"] = submit(action, itsm_cfg or {})
    store.audit(f"{channel}:{actor or role}", "decision_recorded",
                {"org": result.org_name, **{k: v for k, v in out.items() if k != "itsm"}, "note": note[:500]})
    d.update({"status": status, "choice": match, "decided_by": role})
    return out


def overlay(store: Store, result: PipelineResult) -> PipelineResult:
    """Apply verdicts recorded since the last pipeline run."""
    known = store.decision_state(result.org_name)
    for d in result.decisions:
        k = known.get(d["decision_id"])
        if k and k["status"] != "pending":
            d.update({"status": k["status"], "choice": k["choice"], "decided_by": k["role"],
                      "decided_at": k["decided_at"], "note": k["note"]})
    return result
