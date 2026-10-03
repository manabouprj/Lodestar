"""Push the focus brief and new urgent decisions to Slack / Teams.

Called by the scheduler after each run:
  * daily brief at chatops.daily_brief_hour (local time)
  * immediately when a run raises new decisions with urgency 'now'
  * per-team queues to chatops.slack.team_channels (optional)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import PipelineResult
from . import slack, teams
from .engine import ChatEngine, ChatReply, _decision_line


def channels(cfg: dict[str, Any]) -> list[str]:
    return [c for c in ("slack", "teams") if (cfg.get(c) or {}).get("enabled")]


def send(reply: ChatReply, cfg: dict[str, Any], only: str | None = None) -> list[dict[str, Any]]:
    results = []
    for ch in channels(cfg):
        if only and ch != only:
            continue
        try:
            results.append({"channel": ch, **(slack.post(reply, cfg["slack"]) if ch == "slack" else teams.post(reply, cfg["teams"]))})
        except Exception as exc:  # never break the pipeline because chat is down
            results.append({"channel": ch, "ok": False, "error": str(exc)})
    return results


def daily_brief(result: PipelineResult, cfg: dict[str, Any], only: str | None = None) -> list[dict[str, Any]]:
    eng = ChatEngine(result, cfg.get("dashboard_url"))
    out = send(eng.brief(), cfg, only)
    for team, channel in ((cfg.get("slack") or {}).get("team_channels") or {}).items():
        if (cfg.get("slack") or {}).get("enabled") and only in (None, "slack"):
            try:
                out.append({"team": team, **slack.post(eng.team(team), cfg["slack"], channel)})
            except Exception as exc:
                out.append({"team": team, "ok": False, "error": str(exc)})
    return out


def new_urgent(result: PipelineResult, raised: dict[str, datetime], since: datetime, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    fresh = [d for d in result.decisions if d.get("status", "pending") == "pending" and d["urgency"] == "now"
             and raised.get(d["decision_id"]) and raised[d["decision_id"]] >= since]
    if not fresh:
        return []
    reply = ChatReply(f"{len(fresh)} new decision(s) need a human now - {result.org_name}",
                      [_decision_line(d, i) for i, d in enumerate(fresh, 1)],
                      [], cfg.get("dashboard_url"), "alert")
    from .engine import Button
    reply.buttons = [Button(d["options"][0][:75], d["decision_id"], d["options"][0]) for d in fresh[:3]]
    return send(reply, cfg)


DEFAULT_ESCALATION_HOURS = {"now": 4, "today": 24, "this_week": 96}


def escalate(result: PipelineResult, store, cfg: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    """Re-post decisions still pending after chatops.escalation_hours (per urgency) - once per stage.
    Stage 1 at the threshold, stage 2 at twice the threshold (sent to chatops.escalation_channel when set,
    e.g. the CISO's channel). Nothing is decided automatically; this only makes waiting visible."""
    hours = {**DEFAULT_ESCALATION_HOURS, **(cfg.get("escalation_hours") or {})}
    state = store.decision_state(result.org_name)
    due: list[tuple[dict, int, float]] = []
    for d in result.decisions:
        st = state.get(d["decision_id"]) or {}
        if d.get("status", "pending") != "pending" or st.get("status", "pending") != "pending" or not st.get("first_raised"):
            continue
        limit = hours.get(d.get("urgency"))
        if not limit:
            continue
        raised = st["first_raised"]
        waited = (now - (raised if raised.tzinfo else raised.replace(tzinfo=now.tzinfo))).total_seconds() / 3600
        stage = 2 if waited >= 2 * limit else 1 if waited >= limit else 0
        if stage and store.escalation_pending(result.org_name, d["decision_id"], f"stage{stage}"):
            due.append((d, stage, waited))
    if not due:
        return []
    lines = [f"{_decision_line(d)}\n   waiting {w:.0f}h{' - SECOND REMINDER' if s == 2 else ''}" for d, s, w in due]
    reply = ChatReply(f"{len(due)} decision(s) still waiting for a human - {result.org_name}", lines, [],
                      cfg.get("dashboard_url"), "escalation")
    out = send(reply, cfg)
    if any(r.get("ok", True) for r in out):           # mark only what actually reached a channel; retry next run otherwise
        for d, s, _ in due:
            store.escalation_sent(result.org_name, d["decision_id"], f"stage{s}")
    ch = cfg.get("escalation_channel")
    if ch and any(s == 2 for _, s, _ in due) and (cfg.get("slack") or {}).get("enabled"):
        try:
            out.append({"escalation_channel": ch, **slack.post(reply, cfg["slack"], ch)})
        except Exception as exc:
            out.append({"escalation_channel": ch, "ok": False, "error": str(exc)})
    return out


def ingestion_alerts(result: PipelineResult, store, ingestion_cfg: dict[str, Any], cfg: dict[str, Any],
                     now: datetime) -> list[dict[str, Any]]:
    """Alert when an ingestion source enters an alerting state (failing / stale / volume_drop by default),
    again every `repeat_hours` while it stays there, and once when it recovers. Goes to Slack / Teams
    (ingestion.alerts.slack_channel overrides the Slack channel) and to an optional generic JSON webhook
    (ingestion.alerts.webhook_url, e.g. an on-call tool's events endpoint). State lives in
    connector_state.monitor, so an alert that could not be delivered is retried on the next run."""
    from ..ingestion import ALERT_STATES
    acfg = (ingestion_cfg or {}).get("alerts") or {}
    if acfg.get("enabled", True) is False:
        return []
    states = set(acfg.get("states") or ALERT_STATES)
    repeat = float(acfg.get("repeat_hours", 24))
    org = result.org_name
    recs = (result.data_quality.get("ingestion") or {}).get("sources") or {}
    cs = store.all_connector_state(org)
    fire, recovered = [], []
    for key, rec in recs.items():
        mon = (cs.get(key) or {}).get("monitor") or {}
        alerted, at = mon.get("alerted"), mon.get("alerted_at")
        if rec["state"] in states:
            age = (now - datetime.fromisoformat(at)).total_seconds() / 3600 if at else None
            if alerted != rec["state"] or (age is not None and age >= repeat):
                fire.append((key, rec))
        elif alerted in states and rec["state"] in ("healthy", "degraded", "volume_spike"):
            recovered.append((key, rec))
    if not fire and not recovered:
        return []
    lines = [f"• {k}: *{r['state'].upper()}* - {r['detail'] or 'see dashboard'}" for k, r in fire] + \
            [f"• {k}: recovered ({r['state']})" for k, r in recovered]
    title = (f"Ingestion: {len(fire)} source(s) need attention - {org}" if fire
             else f"Ingestion recovered: {len(recovered)} source(s) - {org}")
    reply = ChatReply(title, lines, [], cfg.get("dashboard_url"), "alert")
    out: list[dict[str, Any]] = []
    for ch in channels(cfg):
        try:
            if ch == "slack":
                out.append({"channel": ch, **slack.post(reply, cfg["slack"], acfg.get("slack_channel"))})
            else:
                out.append({"channel": ch, **teams.post(reply, cfg["teams"])})
        except Exception as exc:  # never break the pipeline because chat is down
            out.append({"channel": ch, "ok": False, "error": str(exc)})
    if acfg.get("webhook_url"):
        import httpx
        body = {"source": "lodestar", "org": org, "title": title,
                "events": [{"source_key": k, "state": r["state"], "detail": r["detail"], "domain": r["domain"],
                            "recovered": False} for k, r in fire] +
                          [{"source_key": k, "state": r["state"], "domain": r["domain"], "recovered": True} for k, r in recovered]}
        try:
            resp = httpx.post(acfg["webhook_url"], json=body, timeout=20, trust_env=True)
            out.append({"channel": "webhook", "ok": resp.status_code < 300, "status": resp.status_code})
        except Exception as exc:
            out.append({"channel": "webhook", "ok": False, "error": type(exc).__name__})
    if out and any(r.get("ok", True) for r in out):
        for key, rec in fire:
            store.set_monitor_state(org, key, {**((cs.get(key) or {}).get("monitor") or {}), "state": rec["state"],
                                               "alerted": rec["state"], "alerted_at": now.isoformat()})
        for key, rec in recovered:
            mon = {**((cs.get(key) or {}).get("monitor") or {}), "state": rec["state"]}
            mon.pop("alerted", None), mon.pop("alerted_at", None)
            store.set_monitor_state(org, key, mon)
    return out
