# Human in the loop: the Decision desk

LODESTAR's agents **observe, correlate, rank and prepare**. They do not isolate hosts, reset
accounts, change firewall or WAF policy, take down domains, hold payments, freeze accounts,
file regulatory reports or accept risk. Those actions have side-effects: outages, safety impact,
customer harm or legal deadlines. Accountability for them belongs to a named person.

The **DecisionAgent** turns that boundary into a work queue: the *Decision desk* widget on the
dashboard, the `decisions` command in Slack/Teams, the "Waiting on people" section of each report
and `GET /api/decisions`.

## What every decision contains

| Field | Example |
|---|---|
| What needs deciding | Approve emergency patch or isolation of Internet banking gateway |
| Why now | KEV vulnerability on an internet-facing system with live exploit traffic |
| Who decides (role) | CISO, Head of IT Operations |
| Deadline | 4 hours from when LODESTAR raised it (clock persists across runs) |
| Options | Approve emergency patch now · Apply WAF/IPS virtual patch only · Isolate from internet · Reject · Escalate |
| Agents prepared | KEV/EPSS evidence, exploit telemetry, change-ticket draft, hunt queries |
| Agents will not | Patch, reboot or isolate the system · change firewall or WAF policy |
| If nobody decides | Known-exploited, internet-facing flaw stays open while attacks continue |

## Decision types

| Type | Raised by | Typical decider | Deadline |
|---|---|---|---|
| Containment (endpoint) | Phishing→EDR path, blind-spot path | SOC lead, asset owner | 1-24 h |
| Identity containment | Privileged takeover path | Identity & Access lead | 2 h |
| Emergency change | KEV under attack, unshielded app flaw | CISO + Head of IT Ops / app owner | 4-24 h |
| External action | Brand impersonation | CISO, Legal/Brand, Comms | 24 h |
| Breach assessment (regulatory) | Sensitive data in public storage | Data owner, DPO/Legal, CISO | 4 h |
| Policy enforcement | Shadow-AI data leakage | CISO, data owner | 24 h |
| Safety-critical (OT) | Unmanaged vendor access to OT | OT operations manager, process safety | 8 h |
| Resilience | Crown jewel without immutable backup | Head of IT Ops | 24 h |
| Fraud response | Cyber-enabled fraud, insider payment, bot ATO | Head of Fraud, CISO, channel owner | 1-4 h |
| STR filing (regulatory) | Mule-account network | MLRO | 24 h |
| Control outage | Mandatory control stale/failing | CISO + control owner | 24 h |
| Incident declaration | High-severity live detection with no verdict | SOC lead | 2 h |
| Risk acceptance | Critical findings overdue by more than twice the SLA | Asset owners + CISO | 7 days |

Playbooks are data in `lodestar/agents/core/decision.py` (`PLAYBOOKS`): adjust deciders,
deadlines and options to your RACI.

## Guard-rails

* Recording a verdict needs at least the `analyst` role. Regulatory, risk-acceptance and
  safety-critical decisions need the decision-authority (`ciso`) role.
* Every verdict is written to the audit log with role, channel (dashboard, Slack, Teams, CLI),
  user and note.
* Only **approved** verdicts release the linked ITSM ticket, and ITSM stays in dry-run until
  change-board sign-off.
* Decisions remain visible, marked with the verdict, until the underlying risk clears from the
  source tools. Closing the loop is evidence-based, not a click.
