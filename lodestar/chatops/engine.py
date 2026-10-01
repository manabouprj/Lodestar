"""Conversational front-end to the PrioritizationAgent (Slack, Teams, dashboard, CLI).

The same engine answers in every channel, so the CISO gets the same answer in
Teams as on the dashboard. Answers are built deterministically from the latest
pipeline result; an optional LLM only rephrases free-text questions and is
held to the same numeric-grounding guardrail as the reports.

Intents
  brief | now | focus        what needs attention now (decisions + Today + attack paths)
  decisions                  pending human decisions with IDs and options
  approve|reject|escalate <DEC-id> [option#]   record a verdict (role-mapped)
  why <id|text>              explain a finding or decision
  team <name>                one team's queue
  paths                      open attack paths
  controls                   degraded / stale controls
  fraud                      fraud & financial-crime view
  kri | risk                 KRIs outside appetite
  posture                    score and trend
  help
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..agents.connectors.domains import SPECS
from ..metrics import kri_table
from ..models import Domain, Horizon, PipelineResult, Status, safe_title
from ..verticals import load_vertical

ACTIVE = (Status.OPEN, Status.IN_PROGRESS)
URGENCY_LABEL = {"now": "NOW", "today": "Today", "this_week": "This week"}


@dataclass
class Button:
    label: str
    decision_id: str
    choice: str


@dataclass
class ChatReply:
    title: str
    lines: list[str] = field(default_factory=list)
    buttons: list[Button] = field(default_factory=list)
    link: str | None = None
    intent: str = "help"

    def markdown(self) -> str:
        body = "\n".join(self.lines)
        return f"**{self.title}**\n{body}" + (f"\n\nOpen dashboard: {self.link}" if self.link else "")


def _due(d: dict) -> str:
    h = d.get("hours_left", 0)
    if h < 0:
        return f"overdue {abs(h):.0f}h"
    return f"due in {h:.0f}h" if h >= 1 else f"due in {max(1, round(h * 60))}m"


def _decision_line(d: dict, idx: int | None = None) -> str:
    lead = f"{idx}. " if idx else "• "
    who = " / ".join(d["deciders"][:2])
    reg = " · regulatory" if d.get("regulatory") else ""
    return f"{lead}**{d['title']}** ({URGENCY_LABEL[d['urgency']]}, {_due(d)}{reg})\n   decides: {who} · `{d['decision_id']}`"


def _finding_line(f) -> str:
    tags = []
    if f.kev:
        tags.append("KEV")
    if f.correlation_ids:
        tags.append("attack path")
    t = f" [{', '.join(tags)}]" if tags else ""
    tlp = f" TLP:{f.tlp.upper()}" if f.tlp and f.tlp not in ("clear", "red") else ""
    return f"• {round(f.score)} · **{safe_title(f)}**{t}{tlp} · {SPECS[f.domain].title} · {f.owner_team}"


class ChatEngine:
    def __init__(self, result: PipelineResult, dashboard_url: str | None = None):
        self.r = result
        self.v = load_vertical(result.vertical)
        self.url = dashboard_url
        self.active = [f for f in result.findings if f.status in ACTIVE]
        self.today = [f for f in self.active if f.horizon == Horizon.TODAY]
        self.pending = [d for d in result.decisions if d.get("status", "pending") == "pending"]

    # ------------------------------------------------------------------ public
    def handle(self, text: str, role: str = "exec", recorder=None) -> ChatReply:
        t = (text or "").strip()
        low = t.lower()
        m = re.match(r"^(approve|reject|escalate|decide)\s+(dec-[0-9a-f]+)\s*(.*)$", low)
        if m:
            return self._verdict(m.group(1), m.group(2), t[m.end(2):].strip(), role, recorder)
        if not low or low in ("help", "?", "hi", "hello"):
            return self.help()
        if low.startswith("why "):
            return self.why(t[4:].strip())
        if low.startswith("team "):
            return self.team(t[5:].strip())
        for words, fn in ((("bounty", "hackerone", "researcher", "bug bounty", "vdp"), self.bounty),
                          (("intel", "advisor", "ioc", "cert", "isac", "feed", "indicator"), self.intel),
                          (("decision", "pending", "approval", "waiting"), self.decisions),
                          (("fraud", "mule", "payment", "takeover", "ato"), self.fraud),
                          (("path", "toxic", "correlat"), self.paths),
                          (("control", "health", "stale", "coverage"), self.controls),
                          (("kri", "appetite", "risk indicator"), self.kris),
                          (("posture", "score", "trend"), self.posture),
                          (("brief", "now", "focus", "today", "priorit", "attention", "first", "morning"), self.brief)):
            if any(w in low for w in words):
                return fn()
        return self.search(t)

    # ------------------------------------------------------------------ intents
    def help(self) -> ChatReply:
        return ChatReply("LODESTAR - what I can do", [
            "• `brief` - what needs attention now", "• `decisions` - approvals waiting on people",
            "• `approve DEC-xxxx 1` / `reject DEC-xxxx` / `escalate DEC-xxxx` - record your decision",
            "• `why <id or words>` - why something is prioritised", "• `team Identity & Access` - one team's queue",
            "• `paths` · `controls` · `fraud` · `intel` · `bounty` · `kri` · `posture`",
            "I never act on systems myself: containment, changes, takedowns, payment holds and risk acceptance are decided by people.",
        ], link=self.url, intent="help")

    def brief(self) -> ChatReply:
        snap = self.r.snapshot
        now = [d for d in self.pending if d["urgency"] == "now"]
        lines = [f"Posture **{snap.posture_score:.0f}/100** · {len(self.today)} items today · "
                 f"{len(self.r.correlations)} attack paths · **{len(now)} decisions needed now**", ""]
        if now:
            lines.append("**Decisions only a human can make (agents are holding):**")
            lines += [_decision_line(d, i) for i, d in enumerate(now[:5], 1)]
            lines.append("")
        lines.append("**Top of today's queue:**")
        lines += [_finding_line(f) for f in self.today[:5]]
        weak = [c for c in self.r.controls if c.status in ("stale", "failing")]
        if weak:
            lines += ["", "**Controls not working:** " + ", ".join(f"{SPECS[c.domain].title} ({c.status})" for c in weak)]
        btns = []
        for d in now[:3]:
            btns.append(Button(f"Approve: {d['options'][0]}"[:75], d["decision_id"], d["options"][0]))
        return ChatReply(f"{self.r.org_name} - focus for {self._date()}", lines, btns, self.url, "brief")

    def decisions(self) -> ChatReply:
        if not self.pending:
            return ChatReply("No decisions waiting", ["Every queued decision has a verdict."], link=self.url, intent="decisions")
        lines = []
        for i, d in enumerate(self.pending[:10], 1):
            lines.append(_decision_line(d, i))
            lines.append("   options: " + " | ".join(f"{n}) {o}" for n, o in enumerate(d["options"], 1)))
        if len(self.pending) > 10:
            lines.append(f"…and {len(self.pending) - 10} more on the dashboard.")
        lines.append("Reply `approve DEC-xxxx <option number>` to decide.")
        btns = [Button(d["options"][0][:75], d["decision_id"], d["options"][0]) for d in self.pending[:3]]
        return ChatReply(f"{len(self.pending)} decisions waiting on people", lines, btns, self.url, "decisions")

    def why(self, q: str) -> ChatReply:
        ql = q.lower()
        d = next((d for d in self.r.decisions if d["decision_id"].lower() == ql), None)
        if d:
            lines = [d["why_now"], f"Decides: {', '.join(d['deciders'])} · {_due(d)}",
                     "Agents prepared: " + "; ".join(d["prepared"]),
                     "Agents will not: " + "; ".join(d["will_not"]),
                     f"If nobody decides: {d['if_no_decision']}"]
            return ChatReply(d["title"], lines, [Button(o[:75], d["decision_id"], o) for o in d["options"][:3]], self.url, "why")
        f = next((f for f in self.active if f.finding_id.lower() == ql), None) or \
            next((f for f in sorted(self.active, key=lambda x: -x.score) if ql in f.title.lower()), None)
        if not f:
            return ChatReply("Nothing found", [f"No open finding or decision matches '{q}'."], intent="why")
        lines = [f"Score **{f.score:.0f}** → {f.horizon.value if f.horizon else 'n/a'} · {SPECS[f.domain].title} · owner {f.owner_team}"]
        lines += [f"• {w}" for w in f.why]
        if f.remediation:
            lines.append(f"Fix: {f.remediation}")
        return ChatReply(f.title, lines, link=self.url, intent="why")

    def team(self, name: str) -> ChatReply:
        teams = sorted({f.owner_team for f in self.active if f.owner_team})
        match = next((t for t in teams if t.lower() == name.lower()), None) or \
            next((t for t in teams if name.lower() in t.lower()), None)
        if not match:
            return ChatReply("Unknown team", ["Teams: " + ", ".join(teams)], intent="team")
        items = [f for f in self.active if f.owner_team == match and f.horizon in (Horizon.TODAY, Horizon.THIS_WEEK)]
        lines = [f"{sum(1 for f in items if f.horizon == Horizon.TODAY)} today · "
                 f"{sum(1 for f in items if f.horizon == Horizon.THIS_WEEK)} this week"]
        lines += [_finding_line(f) for f in items[:8]]
        return ChatReply(f"Queue: {match}", lines, link=self.url, intent="team")

    def paths(self) -> ChatReply:
        lines = [f"• **{c.title}** - {c.entity} (score {c.score:.0f}; {', '.join(x.value for x in c.domains)})\n   {c.recommended_action}"
                 for c in self.r.correlations[:6]]
        return ChatReply(f"{len(self.r.correlations)} attack paths open", lines or ["None open."], link=self.url, intent="paths")

    def controls(self) -> ChatReply:
        weak = [c for c in sorted(self.r.controls, key=lambda c: c.effectiveness) if c.status != "healthy"]
        lines = [f"• **{SPECS[c.domain].title}** ({c.product}) - {c.status}, effectiveness {c.effectiveness:.0f}, "
                 f"coverage {c.coverage_pct:.0f}%, data {c.data_freshness_hours:.0f}h old" for c in weak]
        return ChatReply(f"{len(weak)} controls need attention", lines or ["All integrated controls healthy."], link=self.url, intent="controls")

    def fraud(self) -> ChatReply:
        ctl = next((c for c in self.r.controls if c.domain == Domain.FRAUD), None)
        if not ctl:
            return ChatReply("Fraud management not integrated", ["Enable the `fraud` connector (Feedzai, Actimize, SAS, FICO, BioCatch…)."], intent="fraud")
        k = ctl.kpis
        lines = [f"Confirmed loss 30d **USD {k.get('confirmed_loss_30d', 0):,.0f}** · prevented USD {k.get('prevented_30d', 0):,.0f} · "
                 f"detected before loss {k.get('detection_rate_pct', 0):.0f}% · alert backlog {k.get('alert_backlog_hours', 0):.0f}h · "
                 f"channel coverage {k.get('channel_coverage_pct', 0):.0f}%", ""]
        fpaths = [c for c in self.r.correlations if Domain.FRAUD in c.domains]
        if fpaths:
            lines.append("**Cyber-enabled fraud paths:**")
            lines += [f"• {c.title} - {c.entity}" for c in fpaths]
        fd = [d for d in self.pending if d["type"] in ("fraud_response", "str_filing")]
        if fd:
            lines += ["", "**Fraud decisions waiting:**"] + [_decision_line(d) for d in fd]
        return ChatReply("Fraud & financial crime", lines, [Button(d["options"][0][:75], d["decision_id"], d["options"][0]) for d in fd[:3]],
                         self.url, "fraud")

    def bounty(self) -> ChatReply:
        ctl = next((c for c in self.r.controls if c.domain == Domain.BUG_BOUNTY), None)
        reps = sorted([f for f in self.active if f.domain == Domain.BUG_BOUNTY], key=lambda f: -f.score)
        if not ctl and not reps:
            return ChatReply("Bug bounty not integrated", ["Enable the `bug_bounty` connector (HackerOne API/webhooks or a VDP mailbox)."], intent="bounty")
        k = ctl.kpis if ctl else {}
        lines = [f"{len(reps)} open researcher reports · {sum(1 for f in reps if 'triaged' in f.evidence.get('tags', []))} triaged awaiting fix · "
                 f"{sum(1 for f in reps if f.evidence.get('sla_breaches'))} past response SLA · mean time to triage {k.get('mean_time_to_triage_hours', 'n/a')}h · "
                 f"scope covers {k.get('in_scope_internet_assets_pct', 'n/a')}% of internet assets", ""]
        lines += [_finding_line(f) + (" · not in CMDB" if "unknown_asset" in f.evidence.get("tags", []) else "") for f in reps[:6]]
        d = [x for x in self.pending if x["type"] == "bounty_programme" or x["source"] == "LDS-014"]
        if d:
            lines += ["", "**Waiting on people:**"] + [_decision_line(x) for x in d]
        return ChatReply("Bug bounty (HackerOne)", lines, link=self.url, intent="bounty")

    def intel(self) -> ChatReply:
        st = self.r.data_quality.get("intel") or {}
        items, seen = [], {}
        for f in sorted([f for f in self.active if f.domain == Domain.THREAT_INTEL], key=lambda f: -f.score):
            k = f.evidence.get("advisory_id") or f.title
            seen[k] = seen.get(k, 0) + 1
            if seen[k] == 1:
                items.append(f)
        lines = [f"{st.get('advisories_ingested', 0)} advisories / indicators ingested · **{st.get('advisories_relevant', 0)} relevant to us** · "
                 f"{st.get('ioc_sightings', 0)} indicator sighting(s) in our telemetry", ""]
        lines += [_finding_line(f) + (f" · {f.source}" if f.source else "") +
                  (f" · {seen[f.evidence.get('advisory_id') or f.title]} of our assets" if seen[f.evidence.get("advisory_id") or f.title] > 1 else "")
                  for f in items[:6]]
        paths = [c for c in self.r.correlations if Domain.THREAT_INTEL in c.domains]
        if paths:
            lines += ["", "**Intel-driven attack paths:**"] + [f"• {c.title} - {c.entity}" for c in paths[:4]]
        return ChatReply("Threat intelligence & advisories", lines, link=self.url, intent="intel")

    def kris(self) -> ChatReply:
        rows = [r for r in kri_table(self.r.snapshot.kris, self.v) if r["status"] in ("breach", "near")]
        lines = [f"• {r['label']}: **{r['value']}{r['unit']}** vs appetite {r['appetite']}{r['unit']} ({r['status']})" for r in rows]
        return ChatReply(f"{sum(1 for r in rows if r['status'] == 'breach')} KRIs outside appetite", lines or ["All KRIs within appetite."],
                         link=self.url, intent="kri")

    def posture(self) -> ChatReply:
        h = self.r.history
        prev = h[-31].posture_score if len(h) > 30 else None
        delta = f" ({self.r.snapshot.posture_score - prev:+.1f} vs 30 days ago)" if prev is not None else ""
        return ChatReply("Security posture", [f"**{self.r.snapshot.posture_score:.1f}/100**{delta}; appetite "
                                              f"{next((k['appetite'] for k in self.v.kris if k['metric'] == 'posture_score'), 75)}",
                                              f"Data trust {self.r.data_quality.get('trust_score')} ({self.r.data_quality.get('confidence', 'n/a')} confidence)"],
                         link=self.url, intent="posture")

    def search(self, q: str) -> ChatReply:
        words = [w for w in re.findall(r"[a-z0-9]{3,}", q.lower()) if w not in {"the", "what", "show", "about", "with", "and", "for"}]
        hits = [f for f in self.active if f.horizon in (Horizon.TODAY, Horizon.THIS_WEEK)
                and any(w in (f.title + " " + (f.owner_team or "") + " " + f.domain.value).lower() for w in words)]
        if not hits:
            return self.help()
        return ChatReply(f"{len(hits)} prioritised items match", [_finding_line(f) for f in hits[:8]], link=self.url, intent="search")

    # ------------------------------------------------------------------ verdicts
    def _verdict(self, verb: str, did: str, rest: str, role: str, recorder) -> ChatReply:
        d = next((d for d in self.r.decisions if d["decision_id"].lower() == did), None)
        if not d:
            return ChatReply("Decision not found", [f"No decision {did.upper()}."], intent="verdict")
        if verb == "reject":
            choice = next((o for o in d["options"] if o.lower().startswith(("reject", "close as false", "release"))), d["options"][-1])
        elif verb == "escalate":
            choice = "Escalate"
        else:
            choice = rest or "1"
        if recorder is None:
            return ChatReply("Read-only channel", ["This channel cannot record decisions; use the dashboard."], intent="verdict")
        try:
            out = recorder(d["decision_id"], choice, role)
        except Exception as exc:  # DecisionError carries a user-safe message
            return ChatReply("Decision not recorded", [str(exc)], intent="verdict")
        lines = [f"Recorded **{out['choice']}** ({out['status']}) by role {out['role']}.",
                 "The linked action is released to the ticketing queue." if out.get("itsm") else
                 "No system change is made by LODESTAR; the owning team executes."]
        return ChatReply(d["title"], lines, link=self.url, intent="verdict")

    def _date(self) -> str:
        g = self.r.generated_at
        return (g if isinstance(g, datetime) else datetime.fromisoformat(str(g))).strftime("%a %d %b %Y")


SUGGESTED = ["brief", "decisions", "intel", "bounty", "fraud", "paths", "controls", "kri"]


def precomputed(result: PipelineResult, dashboard_url: str | None = None) -> list[dict[str, Any]]:
    """Answers for the dashboard chat panel in static (offline) mode."""
    eng = ChatEngine(result, dashboard_url)
    out = []
    for q in SUGGESTED:
        rep = eng.handle(q)
        if rep.intent == "fraud" and rep.title.startswith("Fraud management not"):
            continue
        out.append({"q": q, "title": rep.title, "lines": rep.lines,
                    "buttons": [{"label": b.label, "decision_id": b.decision_id, "choice": b.choice} for b in rep.buttons]})
    return out
