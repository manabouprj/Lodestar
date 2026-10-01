"""Microsoft Teams integration.

Inbound: a Teams *Outgoing Webhook* (team-scoped, @LODESTAR mention) -> POST /api/chat/teams/messages.
  Teams signs the body with HMAC-SHA256 using the base64 security token shown when the
  webhook is created; header `Authorization: HMAC <base64 signature>`. The reply is
  returned synchronously (must answer within 5 seconds).
Outbound: a Teams *Workflows* webhook URL ("Post to a channel when a webhook request is
  received") receiving an Adaptive Card. (Office 365 connectors are being retired by
  Microsoft; use Workflows.)
Users map to roles by Entra object id (chatops.teams.user_roles); unknown users are read-only.
For button-based approvals inside Teams, register a Bot Framework / Teams app (roadmap);
until then decisions are made by replying `approve DEC-xxxx 1` or via the dashboard link.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

from .engine import ChatReply


def verify(token_b64: str, body: bytes, auth_header: str) -> bool:
    if not token_b64 or not auth_header.startswith("HMAC "):
        return False
    try:
        key = base64.b64decode(token_b64)
    except Exception:
        return False
    expected = base64.b64encode(hmac.new(key, body, hashlib.sha256).digest()).decode()
    return hmac.compare_digest(expected, auth_header[5:].strip())


def card(reply: ChatReply) -> dict[str, Any]:
    body: list[dict[str, Any]] = [{"type": "TextBlock", "text": reply.title, "weight": "Bolder", "size": "Medium", "wrap": True}]
    for line in reply.lines:
        if line:
            body.append({"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"})
    if reply.buttons:
        body.append({"type": "TextBlock", "wrap": True, "isSubtle": True, "spacing": "Medium",
                     "text": "To decide, reply: " + " · ".join(f"`approve {b.decision_id} 1`" for b in reply.buttons[:3])})
    body.append({"type": "TextBlock", "wrap": True, "isSubtle": True, "size": "Small",
                 "text": "Agents prepare and recommend; people decide. Nothing is changed in your systems from this message."})
    c: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                         "version": "1.4", "body": body}
    if reply.link:
        c["actions"] = [{"type": "Action.OpenUrl", "title": "Open LODESTAR dashboard", "url": reply.link}]
    return c


def activity(reply: ChatReply) -> dict[str, Any]:
    """Synchronous reply to an outgoing-webhook call."""
    return {"type": "message", "text": reply.markdown(),
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card(reply)}]}


def post(reply: ChatReply, cfg: dict[str, Any]) -> dict[str, Any]:
    import httpx
    url = cfg.get("workflow_url")
    if not url:
        raise RuntimeError("Teams not configured: set chatops.teams.workflow_url")
    payload = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                   "contentUrl": None, "content": card(reply)}]}
    r = httpx.post(url, json=payload, timeout=20, trust_env=True)
    r.raise_for_status()
    return {"ok": True, "channel": "teams"}


def strip_mention(text: str) -> str:
    import re
    return re.sub(r"<at>.*?</at>", "", text or "").strip()


def role_for(aad_object_id: str, cfg: dict[str, Any]) -> str:
    return (cfg.get("user_roles") or {}).get(aad_object_id, "exec")
