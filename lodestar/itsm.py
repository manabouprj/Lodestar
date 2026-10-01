"""ITSM hand-off for approved actions (ServiceNow / Jira).

Human-in-the-loop by design: only actions explicitly approved through the API
are submitted, and `dry_run: true` (default) returns the payload without
calling the ITSM system - useful for change-board review before go-live.
"""
from __future__ import annotations

from typing import Any

PRIORITY = {"P1": ("1", "Highest"), "P2": ("2", "High"), "P3": ("3", "Medium"), "P4": ("4", "Low")}


def servicenow_payload(action: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    urgency, _ = PRIORITY.get(action.get("priority", "P2"), ("2", "High"))
    return {
        "short_description": f"[LODESTAR] {action['title']}"[:160],
        "description": f"{action.get('recommended_action', '')}\n\nEntity: {action.get('entity')}\n"
                       f"Findings: {', '.join(action.get('finding_ids', [])[:50])}",
        "urgency": urgency, "impact": urgency, "category": "security",
        "assignment_group": (action.get("teams") or ["Security Operations"])[0],
        "correlation_id": action["action_id"],
    }


def jira_payload(action: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    _, prio = PRIORITY.get(action.get("priority", "P2"), ("2", "High"))
    text = f"{action.get('recommended_action', '')}\nEntity: {action.get('entity')}\nFindings: " \
           f"{', '.join(action.get('finding_ids', [])[:50])}\nLODESTAR action: {action['action_id']}"
    return {"fields": {
        "project": {"key": cfg.get("project_key", "SEC")}, "issuetype": {"name": "Task"},
        "summary": f"[LODESTAR] {action['title']}"[:250], "priority": {"name": prio},
        "labels": ["lodestar", action.get("kind", "action")],
        "description": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}]},
    }}


def submit(action: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    provider = cfg.get("provider", "none")
    if provider == "servicenow":
        payload, url = servicenow_payload(action, cfg), f"{cfg.get('base_url', '').rstrip('/')}/api/now/table/incident"
    elif provider == "jira":
        payload, url = jira_payload(action, cfg), f"{cfg.get('base_url', '').rstrip('/')}/rest/api/3/issue"
    else:
        return {"submitted": False, "reason": "itsm.provider is 'none' - action recorded as approved only"}
    if cfg.get("dry_run", True):
        return {"submitted": False, "dry_run": True, "url": url, "payload": payload}
    from .agents.connectors.adapters.base import http_client
    with http_client(30, verify=cfg.get("ca_bundle") or True) as c:   # no automatic retry: a create must not duplicate
        r = c.post(url, json=payload, auth=(cfg.get("username", ""), cfg.get("api_token", "")))
    r.raise_for_status()
    body = r.json()
    ref = (body.get("result") or {}).get("number") or body.get("key") or (body.get("result") or {}).get("sys_id") or ""
    base = cfg.get("base_url", "").rstrip("/")
    link = f"{base}/browse/{ref}" if provider == "jira" and ref else (
        f"{base}/nav_to.do?uri=incident.do?sys_id={(body.get('result') or {}).get('sys_id')}" if ref else "")
    return {"submitted": True, "status": r.status_code, "ticket": ref, "url": link}


def submit_once(store, org: str, action: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Submit an approved action unless a ticket already exists for it (approval twice, from the dashboard
    and from Slack, or a retry after a timeout). Returns the existing ticket in that case."""
    if store is None:
        return submit(action, cfg)
    # the lease serialises simultaneous approvals (dashboard + Slack at the same moment) for one action
    with store.lease(f"itsm:{org}:{action['action_id']}", ttl_seconds=120, wait_seconds=60):
        existing = store.ticket_for(org, action["action_id"])
        if existing:
            return {"submitted": False, "duplicate": True, "ticket": existing["ref"], "url": existing["url"]}
        out = submit(action, cfg)
        if out.get("submitted") and out.get("ticket"):
            store.save_ticket(org, action["action_id"], out["ticket"], out.get("url", ""))
        return out
