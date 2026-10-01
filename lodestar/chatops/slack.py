"""Slack integration.

Inbound (Slack app):
  * Slash command  /lodestar <question>        -> POST /api/chat/slack/commands
  * Events API (app_mention, message.im)       -> POST /api/chat/slack/events
  * Interactivity (decision buttons)           -> POST /api/chat/slack/interactions
  All requests are verified with Slack's v0 signing secret (HMAC-SHA256 over
  "v0:{timestamp}:{body}", 5-minute replay window).
Outbound:
  * chat.postMessage with a bot token (scopes: chat:write, commands, app_mentions:read, im:history)
  * or an incoming-webhook URL (post-only)
Slack users map to LODESTAR roles in config (chatops.slack.user_roles); unknown users are read-only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from .engine import ChatReply


def verify(signing_secret: str, timestamp: str, body: bytes, signature: str, now: float | None = None) -> bool:
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        if abs((now or time.time()) - int(timestamp)) > 300:
            return False
    except ValueError:
        return False
    base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _mrkdwn(text: str) -> str:
    return text.replace("**", "*")


def blocks(reply: ChatReply) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"type": "header", "text": {"type": "plain_text", "text": reply.title[:150]}}]
    chunk: list[str] = []
    for line in reply.lines + [""]:
        if line == "" and chunk:
            out.append({"type": "section", "text": {"type": "mrkdwn", "text": _mrkdwn("\n".join(chunk))[:2900]}})
            chunk = []
        elif line:
            chunk.append(line)
    if reply.buttons:
        out.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": b.label[:75]}, "style": "primary" if i == 0 else None,
             "action_id": f"lodestar_decide_{i}", "value": json.dumps({"d": b.decision_id, "c": b.choice})[:2000]}
            for i, b in enumerate(reply.buttons[:5])]})
        for el in out[-1]["elements"]:
            if el["style"] is None:
                del el["style"]
    ctx = "Agents prepare and recommend; people decide. Nothing is changed in your systems from this message."
    if reply.link:
        ctx += f"  <{reply.link}|Open dashboard>"
    out.append({"type": "context", "elements": [{"type": "mrkdwn", "text": ctx}]})
    return out


def message(reply: ChatReply, response_type: str = "ephemeral") -> dict[str, Any]:
    return {"response_type": response_type, "text": reply.title, "blocks": blocks(reply)}


def post(reply: ChatReply, cfg: dict[str, Any], channel: str | None = None) -> dict[str, Any]:
    import httpx
    payload = {"text": reply.title, "blocks": blocks(reply)}
    if cfg.get("bot_token"):
        payload["channel"] = channel or cfg.get("channel")
        r = httpx.post("https://slack.com/api/chat.postMessage", json=payload, timeout=20, trust_env=True,
                       headers={"Authorization": f"Bearer {cfg['bot_token']}"})
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack error: {data.get('error')}")
        return {"ok": True, "channel": payload["channel"]}
    if cfg.get("webhook_url"):
        r = httpx.post(cfg["webhook_url"], json=payload, timeout=20, trust_env=True)
        r.raise_for_status()
        return {"ok": True, "channel": "webhook"}
    raise RuntimeError("Slack not configured: set chatops.slack.bot_token or webhook_url")


def role_for(user_id: str, cfg: dict[str, Any]) -> str:
    return (cfg.get("user_roles") or {}).get(user_id, "exec")
