# LODESTAR

**Leadership-Oriented Defence: Exposure, Signal Triage And Reporting**

LODESTAR is a set of cooperating AI agents that read from the security tools you already own.
From that data it tells your security team what to work on **today, this week and this month**.
It queues the decisions only a human may take, answers questions in **Slack and Microsoft
Teams**, and writes the **weekly, monthly and quarterly reports** that business leaders and
boards actually read.

A lodestar is the star navigators steer by. The platform does the same job for a security team.

```
1,529 signals from 18 tools ─► 927 open ─► 198 this week ─► 25 today ─► 17 attack paths ─► 20 decisions for people
                                 (Sandline Bank, fictional demo, banking profile)
```

---

## What it achieves

| Outcome | How |
|---|---|
| **One priority list instead of 18 consoles** | 19 connector agents normalise EDR, firewall, VMDR, identity, PAM, cloud, ZTNA, web proxy, SOC/SIEM, SAST, DAST, WAF, brand protection, email, AI security, DLP, OT, backup and fraud data into one model |
| **A Today list a team can finish** | Explainable risk score with Today / This week / This month horizons and a capacity cap; every item says *why* it is there |
| **Attacks that no single tool sees** | 13 correlation rules join signals into attack paths, e.g. a known-exploited bug under live attack on a crown jewel, or lookalike phishing that turns into customer account takeover |
| **Clear human accountability** | The Decision desk lists every action that needs a person: who decides, by when, what the agents prepared and what they will not do |
| **Security in the tools people already use** | Daily focus brief, urgent-decision alerts and two-way chat in Slack and Microsoft Teams |
| **Cyber and fraud in one view** | Fraud-engine signals joined with brand, identity and WAF signals for banks, fintechs, retailers, telcos and airlines |
| **Controls that are known to work** | Coverage, data freshness and policy drift measured for every control; a broken control becomes a finding |
| **Board-ready reporting** | KRIs against risk appetite, decisions requested from leadership, indicative financial exposure, framework readiness (NIST CSF 2.0, ISO 27001:2022, PCI DSS v4.0.1) |
| **One platform, any industry** | Industry profiles as YAML: banking, fintech, aviation, retail, oil & gas, power & utilities, telecom, ports & logistics |

## Who it is for

LODESTAR scales from a single container for a small team to a multi-entity deployment for a
group or government CERT. The agents are the same at every size. Only the number of connectors,
entities and channels changes.

| Team | Typical situation | How LODESTAR is used | Footprint |
|---|---|---|---|
| **Small team** (1-5 people, often with an MSP/MDR) | A handful of tools, no SOC, the IT manager doubles as security lead | Phase 1 with 3-5 connectors through vendor APIs or CSV exports; the Today list and Slack/Teams brief *are* the operating rhythm; quarterly report for the owner/board | One container (2 vCPU, 4 GB), SQLite |
| **Mid-size organisation** (in-house security team, outsourced or small SOC) | 10-15 tools, too many alerts, monthly management reporting done by hand | Phases 1-3; team queues per owner; Decision desk for change and containment approvals; monthly and quarterly reports generated automatically | One container + scheduler |
| **Enterprise** (CISO organisation, 24x7 SOC, GRC, fraud) | 18+ tools, several business units, regulators, board scrutiny | All phases; per-team Slack/Teams channels; ITSM hand-off; fraud fusion; framework readiness for audit | Container platform, PostgreSQL store (roadmap), SSO proxy |
| **Group / multi-entity / MSSP** | Several subsidiaries or clients in different industries | One config per entity with its own industry profile; comparable posture and KRIs across entities | Same image, one config per entity |
| **Government & critical infrastructure** | Mission-critical operations, OT, strict accountability | Dark operations-centre dashboard with TLP marking; OT and safety-critical decisions reserved to named roles; on-premises, no cloud dependency; LLM off by default | On-premises / air-gapped capable |

## How a team works with it

| Cadence | Who | Where | What they get |
|---|---|---|---|
| Continuously | SOC, on-call | Slack / Teams alert | New decisions that need a human **now** |
| Every morning | CISO, security leads | Dashboard + daily brief in chat | Posture, decisions due, Today list, broken controls |
| During the day | Analysts, control owners | Dashboard, `/lodestar` in Slack, `@LODESTAR` in Teams | Team queue, "why is this here?", record decisions |
| Weekly | Technical leads | Weekly report | Today/This-week lists with owners and due dates, attack paths, decisions waiting, control health |
| Monthly | CISO, CIO, risk committee | Monthly report | KRIs vs appetite, trends, framework readiness, decisions requested |
| Quarterly | Board / ExCo | Quarterly report | Posture against appetite, financial exposure range, threat landscape, investment decisions |

## Human in the loop

| Agents do | Agents never do |
|---|---|
| Collect read-only data, de-duplicate, enrich with CISA KEV / EPSS | Isolate hosts, reset or disable accounts |
| Score, rank and explain every item | Change firewall, WAF, PAM, IdP or cloud policy |
| Correlate attack paths across tools | Take down domains or contact customers |
| Draft tickets, takedown requests, customer notices, STR narratives | Hold, recall or release payments; freeze accounts |
| Queue each decision for a named role with a deadline | File regulatory reports (breach, STR/SAR) |
| Record verdicts with an audit trail | Accept risk on anyone's behalf |

Only an approved verdict releases a ticket to ITSM, and ITSM starts in dry-run mode. See
[docs/HUMAN_IN_THE_LOOP.md](docs/HUMAN_IN_THE_LOOP.md).

## The dashboard

The dashboard is dark-first, built for 24x7 operations rooms, with TLP marking and local/UTC
clocks. A light theme is available.

1. **Posture and signal funnel:** posture vs appetite, data-trust confidence, and the funnel from tool noise to today's focus.
2. **Decision desk:** decisions waiting on people, grouped Now / Today / This week, filterable by decider role.
3. **Focus queue:** Today, This week and This month, filterable by owner team and control, with "why it's here" and the recommended fix.
4. **Attack paths:** correlated multi-tool risks with MITRE ATT&CK techniques.
5. **Ask LODESTAR:** chat with the prioritisation agent. The same answers go to Slack and Teams.
6. **Fraud & financial crime:** confirmed loss, prevented loss, detection before loss, backlog, channel coverage, cyber-enabled fraud paths.
7. **KRIs, control assurance, posture trend, team workload, framework readiness, remediation actions.**

## Architecture

```mermaid
flowchart LR
  subgraph Tools[Your security controls - read-only]
    EDR & VMDR & IDP[Identity] & SOC[SIEM/SOC] & MAIL[Email] & FW[Firewall] & WAF & SWG[Web proxy]
    ZTNA & PAM & CLOUD[CNAPP] & SAST & DAST & BRAND[Brand] & AI[AI security] & DLP & OT & BKP[Backup] & FRAUD[Fraud engine]
  end
  Tools -->|API / file drop / signed webhook| CA[19 connector agents]
  CA --> AC[Asset context] --> DQ[Data quality] --> TI[Threat intel] --> CTL[Control assurance]
  CTL --> COR[Correlation] --> PRI[Prioritisation] --> CMP[Compliance] --> ACT[Action drafts] --> DEC[Decision desk]
  PRI --> ST[(Store)]
  DEC --> ST
  ST --> API[REST API + RBAC] --> DASH[Dashboard]
  ST --> REP[Reports + narrative]
  ST --> CHAT[ChatOps agent] <--> SLK[Slack] & TMS[Microsoft Teams]
  DEC -. human verdict .-> ITSM[ServiceNow / Jira]
  VP[[Industry profile YAML]] -.-> PRI & CMP & REP & DEC
```

32 agents: 19 connector agents and 13 core agents. Details are in
[docs/AGENT_CATALOG.md](docs/AGENT_CATALOG.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

**Windows 11 (PowerShell)**

```powershell
git clone https://github.com/<you>/lodestar.git
cd lodestar
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 -Serve     # venv, tests, demo, serve
# open http://127.0.0.1:8080
```

**Linux / macOS**

```bash
./scripts/setup.sh --serve
```

**Docker**

```bash
cp .env.example .env                          # set API keys first
docker compose build
docker compose run --rm api python -m lodestar demo
docker compose up -d                          # API + dashboard + scheduler
```

**Talk to the agent without Slack or Teams**

```bash
python -m lodestar chat "what needs attention now?"
python -m lodestar chat --org sandline-bank-demo fraud
python -m lodestar chat                       # interactive
```

`python -m lodestar demo` builds eight **fictional** organisations, one per industry, and runs
every agent. It writes reports to `reports/` and an offline dashboard to
`dist/lodestar-dashboard.html` for presentations. Ready-made copies are in [`samples/`](samples/).

## Integrations

| Control | Example products | Phase |
|---|---|---:|
| EDR, VMDR, Identity, SOC/SIEM, Email | CrowdStrike, Defender, SentinelOne · Qualys, Tenable, Rapid7 · Entra ID, Okta · Sentinel, Splunk, QRadar · Defender for O365, Mimecast, Proofpoint | 1 |
| Firewall, WAF, Web proxy, ZTNA, PAM, Cloud, **Fraud** | Palo Alto, Fortinet, Check Point · Cloudflare, Akamai, F5 · Zscaler, Netskope · CyberArk, BeyondTrust, Delinea · Wiz, Defender for Cloud, Prisma · Feedzai, Actimize, SAS, FICO, BioCatch | 2 |
| SAST, DAST, Brand, AI security, DLP, OT, Backup | Checkmarx, Veracode, Snyk · Invicti, Burp · Recorded Future, ZeroFox · Purview AI, Lakera, Prompt Security · Purview DLP, Forcepoint · Claroty, Nozomi, Dragos · Rubrik, Cohesity, Veeam | 3 |
| Chat & ticketing | Slack, Microsoft Teams · ServiceNow, Jira | 2 |

There are three ways to connect any product: the **native adapters** (Microsoft Graph Security,
Entra ID Protection, Tenable), a **file drop** of CSV/JSON exports with a field map (no code), or a
**signed webhook** from the product or SOAR. See [docs/CONNECTOR_GUIDE.md](docs/CONNECTOR_GUIDE.md).

## Phased rollout

| Phase | Weeks* | Adds | Value delivered |
|---:|---|---|---|
| 0 | 0-2 | Platform, CMDB / crown jewels, demo | Stakeholder buy-in |
| 1 | 3-6 | EDR, VMDR, Identity, SOC, Email; scoring; weekly report | Daily Today list |
| 2 | 7-10 | Firewall, WAF, Proxy, ZTNA, PAM, Cloud, Fraud; correlation; Decision desk; Slack/Teams | Attack paths, accountable decisions, chat |
| 3 | 11-14 | SAST, DAST, Brand, AI, DLP, OT, Backup; compliance mapping; monthly report | Full coverage, framework readiness |
| 4 | 15-18 | Board report, optional LLM narrative, more entities, live ITSM | Executive and group scale |

\* Indicative for one entity. Each phase has a go-live gate: `python -m lodestar validate --phase N`.
See [docs/DEPLOYMENT_PHASES.md](docs/DEPLOYMENT_PHASES.md).

## Commands

| Command | Purpose |
|---|---|
| `python -m lodestar demo` | Demo data for 8 industries → run → reports → dashboard |
| `python -m lodestar run [--phase N]` | Run the agents once |
| `python -m lodestar serve` | API, dashboard, Slack/Teams endpoints |
| `python -m lodestar schedule` | Runs every N hours, posts the brief and alerts, writes reports on calendar boundaries |
| `python -m lodestar chat [question]` | Ask the prioritisation agent from the terminal |
| `python -m lodestar notify --channel slack\|teams\|stdout` | Push the focus brief now |
| `python -m lodestar report --period weekly\|monthly\|quarterly\|all` | Write reports (HTML, Markdown, JSON) |
| `python -m lodestar validate [--phase N]` | Config, secrets and readiness checks |
| `python -m lodestar export-dashboard` | Offline dashboard file |
| `python -m lodestar agents` | Agent catalogue |

## Repository layout

```
lodestar/
  agents/connectors/   19 connector agents + adapters (mock, file_drop, webhook, Graph Security, Entra, Tenable)
  agents/core/         asset context, data quality, threat intel, control assurance, correlation,
                       prioritisation, compliance, action, decision desk, narrative
  chatops/             chat engine, Slack, Microsoft Teams, notifier
  scoring.py           explainable LODESTAR Risk Score
  decisions.py         recording human verdicts (role checks, audit, ITSM release)
  reporting.py         weekly / monthly / quarterly reports
  api/app.py           REST API, RBAC, webhook ingest, chat endpoints, dashboard
  demo/generator.py    fictional demo data for 8 industries
config/                platform config, industry profiles, framework mappings
docs/                  architecture, scoring, phases, human-in-the-loop, ChatOps, fraud, security, peer review, demo script
samples/               dashboard and reports generated from the demo data
tests/                 39 tests
```

## Security

The platform is built to tier-0 standards. Connectors only read. Secrets come from the
environment and the config loader rejects literal secrets. The API uses role-based keys, and
webhooks and Slack/Teams requests are HMAC-verified. The container runs non-root on a read-only
filesystem. Every agent run and verdict is audit-logged. The LLM narrative is off by default and
only sees aggregates. See [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| Document | For |
|---|---|
| [HUMAN_IN_THE_LOOP.md](docs/HUMAN_IN_THE_LOOP.md) | Decision desk, decision types, guard-rails |
| [CHATOPS.md](docs/CHATOPS.md) | Slack and Teams setup, roles in chat |
| [FRAUD_MANAGEMENT.md](docs/FRAUD_MANAGEMENT.md) | Cyber-enabled fraud for financial institutions |
| [SCORING_MODEL.md](docs/SCORING_MODEL.md) | How priorities are calculated |
| [DEPLOYMENT_PHASES.md](docs/DEPLOYMENT_PHASES.md) | Rollout plan and exit criteria |
| [CONNECTOR_GUIDE.md](docs/CONNECTOR_GUIDE.md) | Connecting products |
| [AGENT_CATALOG.md](docs/AGENT_CATALOG.md) | Every agent, rule and industry profile |
| [PEER_REVIEW.md](docs/PEER_REVIEW.md) | Review findings, fixes and open items |
| [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | 15-minute presentation walkthrough |

## Status and roadmap

Version 1.1.0. Planned next: native adapters for CrowdStrike, Qualys, Zscaler, CyberArk, Wiz,
Cloudflare and Feedzai; a PostgreSQL store for multi-entity HA; in-app OIDC; and a full Teams bot
with card actions. Open items are tracked in [docs/PEER_REVIEW.md](docs/PEER_REVIEW.md).

All demo organisations, people, hosts and `*.example` domains are fictional. CVE identifiers are
real public CVEs used for illustration.
