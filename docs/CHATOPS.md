# Slack and Microsoft Teams (ChatOps)

The dashboard stays the system of record. ChatOps brings the same prioritisation agent into the
channels where security teams already work:

* **Push:** a daily focus brief ("what needs attention now"), an alert whenever a run raises a new
  decision that needs a human *now*, and optional per-team queues to team channels.
* **Ask:** the CISO or analysts ask the agent in plain language: `brief`, `decisions`,
  `why DEC-…`, `team Identity & Access`, `paths`, `controls`, `fraud`, `kri`, `posture`.
* **Decide:** people record verdicts (`approve DEC-… 1`, `reject DEC-…`, `escalate DEC-…`, or
  the Slack buttons). LODESTAR never changes a system from chat. The verdict is audit-logged with
  the channel and user, and only an approval releases the linked ITSM ticket.

One engine (`lodestar/chatops/engine.py`) answers the dashboard chat panel, Slack, Teams and the
terminal (`python -m lodestar chat`), so everyone sees the same answer.

## Roles in chat

Chat users are mapped to LODESTAR roles in `config/lodestar.yaml`. Unmapped users can read but
not decide.

```yaml
chatops:
  slack:
    user_roles: {U0123ABCD: ciso, U0456EFGH: analyst}
  teams:
    user_roles: {"6f1c…-entra-object-id": ciso}
```

| Role | Can ask | Can decide |
|---|---|---|
| exec | yes | no |
| analyst | yes | containment, emergency change, policy enforcement, control outage, incident declaration, fraud response that is not regulatory |
| ciso (decision authority) | yes | everything, including risk acceptance, regulatory (breach notification, payment holds, STR filing) and safety-critical OT decisions |

Map your MLRO, Head of Fraud and plant/OT manager to the decision-authority role for their items.

## Slack setup (15 minutes)

1. Create an app at api.slack.com → *From an app manifest*:

```yaml
display_information: {name: LODESTAR}
features:
  bot_user: {display_name: LODESTAR, always_online: true}
  slash_commands:
    - {command: /lodestar, url: "https://lodestar.your-org.example/api/chat/slack/commands", description: "Ask the prioritisation agent", usage_hint: "brief | decisions | fraud | why DEC-…"}
oauth_config:
  scopes: {bot: [chat:write, commands, app_mentions:read, im:history]}
settings:
  event_subscriptions:
    request_url: "https://lodestar.your-org.example/api/chat/slack/events"
    bot_events: [app_mention, message.im]
  interactivity:
    is_enabled: true
    request_url: "https://lodestar.your-org.example/api/chat/slack/interactions"
```

2. Install to the workspace, then set `SLACK_BOT_TOKEN` (xoxb-…) and `SLACK_SIGNING_SECRET` in `.env`.
3. In `config/lodestar.yaml`: `chatops.slack.enabled: true`, `channel: "#security-leadership"`,
   `user_roles`, optional `team_channels`.
4. Invite the bot to the channel and test: `/lodestar brief`, then `python -m lodestar notify --channel slack`.

Every inbound request is verified with the Slack signing secret (HMAC-SHA256, 5-minute replay
window). Requests that fail verification get HTTP 401.

## Microsoft Teams setup

Teams uses two lightweight mechanisms, with no bot registration needed:

**Outbound (brief and alerts):** in the target channel, open *Workflows* and choose
"Post to a channel when a webhook request is received". Copy the URL to `TEAMS_WORKFLOW_URL`.
LODESTAR posts Adaptive Cards with an *Open LODESTAR dashboard* button. (Microsoft is retiring
Office 365 connector webhooks, so use Workflows.)

**Inbound (ask and decide):** in the team, *Manage team → Apps → Create an outgoing webhook*,
name it `LODESTAR`, callback URL `https://lodestar.your-org.example/api/chat/teams/messages`.
Copy the security token to `TEAMS_OUTGOING_WEBHOOK_TOKEN`. Users type `@LODESTAR brief` or
`@LODESTAR approve DEC-… 1`. Requests are verified with the HMAC token.

Set `chatops.teams.enabled: true` and map users by Entra object ID in `user_roles`.

Teams outgoing webhooks are team-scoped and text-based, so card buttons cannot call back. Decisions
in Teams are made by replying with the command, or from the dashboard. A full Teams bot
(Bot Framework) with card actions is on the roadmap.

## Scheduling

`python -m lodestar schedule` (the `scheduler` container) handles two kinds of message:

| When | Message |
|---|---|
| After every run, if a new decision with urgency *now* appears | Alert listing the new decisions, with buttons (Slack) |
| Once a day after `daily_brief_hour` | Focus brief, plus per-team queues to `team_channels` |

Manual: `python -m lodestar notify --channel slack|teams|all|stdout`.

## Network and security

* The API must be reachable from Slack/Microsoft cloud for inbound chat: publish only
  `/api/chat/*` through your reverse proxy / WAF and keep the dashboard behind SSO.
* Chat replies contain finding titles, hostnames and user principal names. Post to private
  channels only.
* Chat never triggers connectors, scans or changes. Rate limiting and payload size limits are
  applied at the proxy.
