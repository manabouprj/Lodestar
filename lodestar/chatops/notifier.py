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
