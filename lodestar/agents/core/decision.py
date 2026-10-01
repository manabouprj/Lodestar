"""DecisionAgent (Phase 2) - the human-in-the-loop decision desk.

Agents in LODESTAR investigate, correlate, rank and PREPARE. They never
isolate a host, reset an account, change a firewall/WAF, take down a domain,
accept a risk or notify a regulator. Those are business decisions with
side-effects (outages, safety, legal clocks), so they are queued here for a
named human role with a deadline.

Each decision states:
  * what needs deciding and why now
  * who decides (role, not a person - mapped to people in your RACI)
  * the deadline (hours from detection, by playbook)
  * the options the human can choose
  * what the agents have already prepared (evidence, drafts)
  * what the agents will NOT do on their own
  * the consequence of no decision
Decisions are recorded through the API (audit-logged); only an approved
decision releases the linked action (e.g. ITSM ticket) for execution.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta, timezone

from ...models import Domain, FindingType, Horizon, Severity, Status
from ..base import AgentContext, BaseAgent, PipelineState

# rule_id -> decision playbook
PLAYBOOKS: dict[str, dict] = {
    "LDS-001": {
        "type": "emergency_change", "title": "Approve emergency patch or isolation of {entity}",
        "deciders": ["CISO", "Head of IT Operations"], "deadline_h": 4,
        "options": ["Approve emergency patch now", "Apply WAF/IPS virtual patch only", "Isolate from internet", "Reject"],
        "prepared": ["CISA KEV and EPSS evidence", "Exploit-attempt telemetry from perimeter", "Emergency change ticket draft", "Compromise-hunt query pack"],
        "will_not": ["Patch, reboot or isolate the system", "Change firewall or WAF policy"],
        "if_none": "A known-exploited, internet-facing flaw stays open while attack traffic continues.",
    },
    "LDS-002": {
        "type": "containment", "title": "Approve EDR deployment or temporary containment for {entity}",
        "deciders": ["Asset owner", "Endpoint Security lead"], "deadline_h": 24,
        "options": ["Deploy/repair EDR sensor", "Restrict network access until covered", "Accept for 7 days", "Reject"],
        "prepared": ["Vulnerability list for the host", "Sensor health history", "Deployment change draft"],
        "will_not": ["Install agents or restrict network access"],
        "if_none": "Exploitation of this host would not be detected.",
    },
    "LDS-003": {
        "type": "identity_containment", "title": "Approve credential reset and session revocation for privileged account {entity}",
        "deciders": ["Identity & Access lead", "Account owner's manager"], "deadline_h": 2,
        "options": ["Reset credentials and revoke sessions", "Force phishing-resistant MFA re-registration", "Monitor only", "Reject"],
        "prepared": ["Sign-in risk timeline", "PAM vaulting status", "Reset runbook with business-impact note"],
        "will_not": ["Disable, reset or lock any account", "Change PAM or IdP policy"],
        "if_none": "A possibly compromised admin identity keeps standing privilege.",
    },
    "LDS-004": {
        "type": "containment", "title": "Approve endpoint isolation after phishing compromise of {entity}",
        "deciders": ["SOC lead"], "deadline_h": 1,
        "options": ["Isolate endpoint and reset user", "Collect triage, keep online", "Reject (false positive)"],
        "prepared": ["Email click evidence", "EDR process tree", "Mailbox purge query for the campaign"],
        "will_not": ["Isolate the device or purge mailboxes"],
        "if_none": "Likely initial access remains active on the network.",
    },
    "LDS-005": {
        "type": "external_action", "title": "Authorise takedown and customer advisory for lookalike domain {entity}",
        "deciders": ["CISO", "Legal / Brand", "Corporate Communications"], "deadline_h": 24,
        "options": ["Submit takedown and block", "Block internally only", "Monitor"],
        "prepared": ["Domain registration and hosting evidence", "Phishing samples", "Takedown request draft", "Customer advisory draft"],
        "will_not": ["File takedown requests or publish customer communications"],
        "if_none": "Customers and staff stay exposed to an active impersonation campaign.",
    },
    "LDS-006": {
        "type": "breach_assessment", "title": "Remove public access and start breach-notification assessment for {entity}",
        "deciders": ["Data owner", "DPO / Legal", "CISO"], "deadline_h": 4,
        "options": ["Remove public access and open breach assessment", "Remove public access only", "Reject (data not sensitive)"],
        "prepared": ["DLP classification and record estimate", "Access-log query for downloads", "Regulator notification checklist"],
        "will_not": ["Change cloud permissions", "Decide whether a regulator or customer must be notified"],
        "if_none": "Sensitive records remain public; regulatory notification clocks may already be running.",
        "regulatory": True,
    },
    "LDS-007": {
        "type": "policy_enforcement", "title": "Block unsanctioned AI service and review data shared by {entity}",
        "deciders": ["CISO", "Data owner", "Line manager"], "deadline_h": 24,
        "options": ["Block app and redirect to sanctioned AI", "Coach user, allow with DLP", "Reject"],
        "prepared": ["Proxy usage log", "DLP match summary", "Sanctioned-AI guidance note"],
        "will_not": ["Block applications or contact the employee"],
        "if_none": "Customer data may continue to flow to an external AI provider.",
    },
    "LDS-008": {
        "type": "emergency_change", "title": "Approve WAF blocking mode / virtual patch for {entity}",
        "deciders": ["Application owner", "Application Security lead"], "deadline_h": 24,
        "options": ["Enable blocking with virtual patch", "Virtual patch in detect mode for 48h", "Reject"],
        "prepared": ["Confirmed DAST/SAST evidence", "Virtual-patch rule draft", "False-positive risk estimate"],
        "will_not": ["Change WAF mode or deploy code"],
        "if_none": "An exploitable customer-facing flaw remains unshielded.",
    },
    "LDS-009": {
        "type": "safety_critical", "title": "Approve removal of unmanaged vendor remote access to OT asset {entity}",
        "deciders": ["OT Operations manager", "Process safety engineer", "CISO"], "deadline_h": 8,
        "options": ["Disable and route via ZTNA/PAM jump host", "Restrict to scheduled windows", "Reject"],
        "prepared": ["Remote-access session evidence", "Asset safety classification", "Vendor access procedure draft"],
        "will_not": ["Touch any OT network, device or vendor tool (safety)"],
        "if_none": "An uncontrolled path into the control network stays open.",
    },
    "LDS-010": {
        "type": "resilience", "title": "Approve immutable backup and restore test for {entity}",
        "deciders": ["Head of IT Operations", "Business service owner"], "deadline_h": 24,
        "options": ["Enable immutable copy and test restore this week", "Schedule in next change window", "Accept risk"],
        "prepared": ["Backup coverage evidence", "Threat context on the host", "Restore-test plan"],
        "will_not": ["Change backup policies or run restores"],
        "if_none": "A ransomware event on this crown jewel may not be recoverable.",
    },
    "LDS-011": {
        "type": "fraud_response", "title": "Approve joint cyber-fraud response for campaign via {entity}",
        "deciders": ["Head of Fraud", "CISO", "Customer Operations"], "deadline_h": 2,
        "options": ["Step-up auth + payment holds + customer notice", "Step-up auth only", "Monitor"],
        "prepared": ["List of affected customer accounts and sessions", "Lookalike-domain evidence", "Takedown request draft",
                     "Customer notification draft"],
        "will_not": ["Block or restrict customer accounts", "Hold or recall payments", "Contact customers"],
        "if_none": "Fraudsters keep converting harvested credentials into losses.",
    },
    "LDS-012": {
        "type": "fraud_response", "title": "Hold payment and suspend payment rights for {entity}",
        "deciders": ["Head of Fraud", "Head of Payments Operations", "HR / Legal"], "deadline_h": 1,
        "options": ["Hold/recall payment and suspend rights", "Hold payment, verify with employee", "Release payment"],
        "prepared": ["Payment details and beneficiary history", "Credential-exposure evidence", "Recall request draft"],
        "will_not": ["Hold, recall or release payments", "Suspend the employee"],
        "if_none": "Funds may leave the institution before recall is possible.",
        "regulatory": True,
    },
    "LDS-013": {
        "type": "fraud_response", "title": "Approve bot mitigation and step-up on {entity} login",
        "deciders": ["Digital channel owner", "Head of Fraud"], "deadline_h": 4,
        "options": ["Enable bot challenge + step-up", "Rate-limit only", "Reject"],
        "prepared": ["Credential-stuffing telemetry", "ATO case list", "Customer-friction estimate"],
        "will_not": ["Change login flows or WAF/bot policy"],
        "if_none": "Automated account takeover continues on the customer channel.",
    },
}

ROLE_FOR_DOMAIN = {"fraud": "Head of Fraud", "edr": "Endpoint Security lead", "vmdr": "Infrastructure lead", "identity": "Identity & Access lead",
                   "soc": "SOC lead", "email": "Messaging Security lead", "dlp": "Data Protection lead",
                   "ai_security": "AI Governance lead", "ot": "OT Operations manager", "backup": "Head of IT Operations"}


def _id(*parts: str) -> str:
    return "DEC-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _urgency(hours: float) -> str:
    return "now" if hours <= 4 else ("today" if hours <= 24 else "this_week")


class DecisionAgent(BaseAgent):
    name = "DecisionAgent"
    phase = 2
    description = "Queues decisions only a human may take (containment, emergency change, risk acceptance, disclosure) with owner, deadline and prepared evidence."

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        now = ctx.now if ctx.now.tzinfo else ctx.now.replace(tzinfo=timezone.utc)
        by_id = {f.finding_id: f for f in state.findings}
        actions_by_entity = {a.get("entity"): a["action_id"] for a in state.actions}
        org = ctx.settings.org_name
        known = ctx.store.decision_state(org) if ctx.store else {}
        raised = {k: v["first_raised"] for k, v in known.items()}
        out: list[dict] = []

        # 1. one decision per attack path
        for c in state.correlations:
            pb = PLAYBOOKS.get(c.rule_id)
            if not pb:
                continue
            members = [by_id[i] for i in c.finding_ids if i in by_id]
            # the clock starts when LODESTAR first raised this decision (persisted across runs)
            did = _id(c.correlation_id)
            start = raised.get(did, now)
            due = start + timedelta(hours=pb["deadline_h"])
            latest = max((m.first_seen if m.first_seen.tzinfo else m.first_seen.replace(tzinfo=timezone.utc)
                          for m in members), default=now)
            hours_left = (due - now).total_seconds() / 3600
            out.append({
                "decision_id": did, "type": pb["type"], "source": c.rule_id,
                "signal_age_hours": round((now - latest).total_seconds() / 3600, 1),
                "title": pb["title"].format(entity=c.entity), "why_now": c.narrative,
                "deciders": pb["deciders"], "deadline_hours": pb["deadline_h"], "due_at": due.isoformat(),
                "hours_left": round(hours_left, 1), "urgency": _urgency(hours_left), "score": c.score,
                "options": pb["options"], "prepared": pb["prepared"], "will_not": pb["will_not"],
                "if_no_decision": pb["if_none"], "regulatory": bool(pb.get("regulatory")),
                "evidence": [{"id": m.finding_id, "title": m.title, "domain": m.domain.value} for m in members[:5]],
                "action_id": actions_by_entity.get(c.entity), "status": "pending",
            })

        # 2. controls that have stopped working on mandatory domains
        for c in state.controls:
            if c.status in ("stale", "failing") and c.domain.value in ctx.vertical.mandatory_domains:
                due = now + timedelta(hours=24)
                out.append({
                    "decision_id": _id("ctl", c.domain.value), "type": "control_outage", "source": "ControlAssurance",
                    "title": f"Confirm {c.product} outage, owner and interim cover",
                    "why_now": f"{c.domain.value.upper()} is mandatory for {ctx.vertical.name} and is {c.status} "
                               f"(data {c.data_freshness_hours:.0f}h old, coverage {c.coverage_pct:.0f}%).",
                    "deciders": ["CISO", ROLE_FOR_DOMAIN.get(c.domain.value, "Control owner")], "deadline_hours": 24,
                    "due_at": due.isoformat(), "hours_left": 24.0, "urgency": "today", "score": 70.0,
                    "options": ["Assign owner and fix date", "Approve interim compensating control", "Escalate to vendor"],
                    "prepared": ["Health telemetry and last good data point", "Affected-asset list"],
                    "will_not": ["Restart, reconfigure or re-license the control"],
                    "if_no_decision": "Risk in this domain is invisible; posture confidence stays reduced.",
                    "regulatory": False, "evidence": [], "action_id": None, "status": "pending",
                })

        # 3. fix-or-accept: critical items far beyond SLA with no attack path -> owner must fund or accept
        stale_crit = [f for f in state.findings if f.status in (Status.OPEN, Status.IN_PROGRESS)
                      and f.severity == Severity.CRITICAL and not f.correlation_ids and f.due_date
                      and (now - (f.due_date if f.due_date.tzinfo else f.due_date.replace(tzinfo=timezone.utc))).days
                      >= ctx.vertical.sla("critical")]
        if stale_crit:
            stale_crit.sort(key=lambda f: -f.score)
            due = now + timedelta(days=7)
            out.append({
                "decision_id": _id("accept", *[f.finding_id for f in stale_crit[:20]]), "type": "risk_acceptance",
                "source": "PrioritizationAgent",
                "title": f"Fix or formally accept {len(stale_crit)} critical finding(s) overdue by more than twice the SLA",
                "why_now": f"These exceed the {ctx.vertical.name} critical SLA ({ctx.vertical.sla('critical')} days) at least twice over "
                           "and are not part of an active attack path. Leaving them open without a decision is an audit finding.",
                "deciders": ["Asset owners", "CISO (risk acceptance authority)"], "deadline_hours": 168,
                "due_at": due.isoformat(), "hours_left": 168.0, "urgency": "this_week", "score": 55.0,
                "options": ["Fund remediation with date", "Accept risk for 90 days with compensating control", "Decommission asset"],
                "prepared": ["Ranked list with business service and age", "Risk-acceptance form pre-filled"],
                "will_not": ["Accept risk or close findings on anyone's behalf"],
                "if_no_decision": "Findings remain in breach of policy with no accountable owner.",
                "regulatory": False,
                "evidence": [{"id": f.finding_id, "title": f.title, "domain": f.domain.value} for f in stale_crit[:5]],
                "action_id": None, "status": "pending",
            })

        # 4. financial-crime reporting: mule networks need an MLRO decision (STR / SAR)
        for f in state.findings:
            if f.domain == Domain.FRAUD and "mule" in f.evidence.get("tags", []) and "fraud" in ctx.vertical.mandatory_domains and f.status in (Status.OPEN, Status.IN_PROGRESS):
                did = _id("str", f.finding_id)
                due = raised.get(did, now) + timedelta(hours=24)
                hours_left = (due - now).total_seconds() / 3600
                out.append({
                    "decision_id": did, "type": "str_filing", "source": "FraudSentinelAgent",
                    "title": f"Decide on suspicious transaction report: {f.title}",
                    "why_now": "Mule activity is a reportable suspicion in most jurisdictions; the MLRO decides on filing and "
                               "account freezes. Cyber evidence is attached to the case.",
                    "deciders": ["MLRO", "Head of Fraud"], "deadline_hours": 24, "due_at": due.isoformat(),
                    "hours_left": round(hours_left, 1), "urgency": _urgency(hours_left), "score": f.score,
                    "options": ["File STR and freeze accounts", "Freeze accounts, continue investigation",
                                "No filing (document rationale)"],
                    "prepared": ["Linked accounts and device fingerprints", "Transaction flow summary", "Draft STR narrative"],
                    "will_not": ["Freeze accounts", "File any regulatory report", "Contact account holders (tipping-off risk)"],
                    "if_no_decision": "Reporting obligations may be missed and funds dispersed.",
                    "regulatory": True, "evidence": [{"id": f.finding_id, "title": f.title, "domain": "fraud"}],
                    "action_id": None, "status": "pending", "signal_age_hours":
                        round((now - (f.first_seen if f.first_seen.tzinfo else f.first_seen.replace(tzinfo=timezone.utc))).total_seconds() / 3600, 1),
                })

        # 5. active high-severity detections still open today -> confirm incident
        active = [f for f in state.findings if f.horizon == Horizon.TODAY and not f.correlation_ids
                  and f.finding_type in (FindingType.DETECTION, FindingType.INCIDENT)
                  and f.severity in (Severity.CRITICAL, Severity.HIGH) and f.domain in (Domain.SOC, Domain.EDR, Domain.IDENTITY)]
        for f in active[:3]:
            due = now + timedelta(hours=2)
            out.append({
                "decision_id": _id("inc", f.finding_id), "type": "incident_declaration", "source": f.domain.value,
                "title": f"Confirm true positive and declare incident: {f.title} on "
                         f"{state.assets[f.asset_id].name if f.asset_id in state.assets else (f.asset_id or f.user_id)}",
                "why_now": "High-severity live detection on a business-relevant asset with no analyst verdict yet.",
                "deciders": ["SOC lead"], "deadline_hours": 2, "due_at": due.isoformat(), "hours_left": 2.0,
                "urgency": "now", "score": f.score,
                "options": ["Declare incident (invoke IR plan)", "Investigate further (4h)", "Close as false positive"],
                "prepared": ["Alert evidence and asset context", "Related signals across controls"],
                "will_not": ["Declare incidents or trigger the IR plan"],
                "if_no_decision": "A possible intrusion runs without an incident commander.",
                "regulatory": False, "evidence": [{"id": f.finding_id, "title": f.title, "domain": f.domain.value}],
                "action_id": None, "status": "pending",
            })

        # carry human verdicts across runs; decided items stay visible until the underlying risk clears
        for d in out:
            k = known.get(d["decision_id"])
            if k and k.get("status") != "pending":
                d.update({"status": k["status"], "choice": k.get("choice"), "decided_by": k.get("role"),
                          "decided_at": k.get("decided_at"), "note": k.get("note")})
        if ctx.store:
            ctx.store.register_decisions(org, [d["decision_id"] for d in out], now)
        order = {"now": 0, "today": 1, "this_week": 2}
        out.sort(key=lambda d: (d["status"] != "pending", order[d["urgency"]], d["hours_left"], -d["score"]))
        state.decisions = out
        return state
