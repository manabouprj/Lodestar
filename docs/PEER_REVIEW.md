# Peer review - LODESTAR v1.0

**Scope:** the original brief, the agent design, the code in this repository, the demo data and
the deployment approach.
**Method:** design walk-through against the brief; adversarial run of the pipeline on eight
synthetic industries; inspection of output distributions (Today list size, posture, attack
paths, financial exposure); code review for failure modes and security; live-mode run with no
credentials; full test suite (30 tests) and lint.
**Outcome:** 14 findings fixed in this version, 10 open items carried to the roadmap with an
owner phase. None of the open items blocks a Phase 0-2 deployment.

## 1. Review of the brief

| Brief item | Assessment | Adjustment made |
|---|---|---|
| Integrate EDR, firewall, VMDR, identity, cloud, ZTNA, web proxy, SOC, SAST, "DSAT", WAF, brand, email, PAM, AI controls | Read "DSAT" as DAST. "Other critical controls" left open | Added **DLP**, **OT/ICS** and **backup / cyber-recovery** connectors (18 domains). These carry the data-leak, critical-infrastructure and ransomware-recovery risks boards ask about most |
| Prioritisation dashboard daily / weekly / monthly | A dashboard that only lists findings repeats the console problem | Explainable score + **Today / This week / This month** horizons, Today capacity cap, attack-path correlation, "why is this here" on every item |
| Weekly / monthly / quarterly business reports | Board reports need decisions and money, not counts | KRIs vs **risk appetite**, **decisions requested**, **indicative financial exposure**, framework readiness |
| Scalable across verticals | Hard-coding industries does not scale | Industry = YAML profile with inheritance; 8 profiles shipped; new industry needs no code |
| Deploy in phases with no challenges | Integration risk sits in credentials, data quality and change control | Phase gating in the orchestrator, `validate` go-live gate, failure isolation, dry-run ITSM, data-trust indicator |
| (implicit) Controls are working | Not in the brief, but a silent control failure is a top CISO risk | **ControlAssuranceAgent**: coverage, freshness, drift → effectiveness; degraded controls become findings |

**Name:** LODESTAR (Leadership-Oriented Defence: Exposure, Signal Triage And Reporting). A
lodestar is the star used to steer by, which is the job of the platform.

## 2. Findings fixed in v1.0

| # | Severity | Finding | Evidence | Fix |
|---|---|---|---|---|
| PR-01 | High | Industry weights multiplied the whole score, pushing medium hygiene items into Today | Fintech Today = 50, power utility Today = 52 (mostly medium cloud/OT hygiene) | Dampened weights (`vertical_weight_strength 0.6`), Today requires high/critical **or** KEV/attack path/active exploitation, Today capacity 25. Now 23-31 per org, with every attack-path item kept |
| PR-02 | High | Financial exposure was not credible (USD 113-391M for a mid-size bank) | First board-report render | Annualised likelihood (≤ 25 %), realistic outage durations per rule, labelled "indicative, not actuarial". Bank now USD 15.4M-73.5M |
| PR-03 | High | Posture score looked healthy when feeds were missing | Live run without credentials still showed posture 59.5 | Data-trust score and **confidence** flag (high/medium/low) next to posture; mandatory-but-missing controls listed |
| PR-04 | Medium | Framework readiness collapsed to ~5 % because any Today item marked a control at risk | Dashboard first render | Graded statuses (at risk ≥ 3 Today items, attention ≥ 1 Today or ≥ 5 this week) and weighted readiness |
| PR-05 | Medium | Critical-vuln SLA KRI computed from open items only (survivorship bias, 7 %) | KRI table | Prefer the scanner's closed+open SLA statistic; open-only calculation as fallback |
| PR-06 | Medium | "Blind spot" rule fired on low-value workstations (21 attack paths, mostly noise) | Correlation output | Require asset criticality ≥ 3 on the vulnerability leg; 14 paths remain |
| PR-07 | Medium | A control that is simply not deployed (OT in a bank) was shown as a failing control | Banking run | Connector with no data and no health is recorded as *not integrated*, not failing |
| PR-08 | Medium | One failing agent would abort the pipeline | Fault injection test | Per-agent isolation; failure recorded in data quality and audit; test `test_agent_failure_is_isolated` |
| PR-09 | Medium | Webhook inbox drained on read could lose data if a run failed afterwards | Code review | Upsert by `finding_id` with retention window; re-sends update, never duplicate |
| PR-10 | Medium | LLM narrative could invent figures in a board report | Design review | Template engine by default; LLM receives aggregates only; any number not in the facts discards the text (`test_numeric_guardrail_rejects_hallucinated_numbers`) |
| PR-11 | Medium | Secrets could be committed in YAML | Code review | Loader refuses literal secrets (`test_literal_secret_rejected`) |
| PR-12 | Medium | Automated ticket creation could flood ITSM | Design review | Human approval per action, dry-run default, audit entry per approval |
| PR-13 | Low | API and dashboard open by default | Code review | Role-based API keys, enforced automatically in live mode; security headers and CSP |
| PR-14 | Low | Correlation entity labels duplicated service names ("X (X)") | Dashboard render | Label normalisation |

## 3. Open items (roadmap)

| # | Item | Risk if ignored | Planned |
|---|---|---|---|
| O-01 | Only three native vendor adapters (Microsoft Graph Security, Entra ID Protection, Tenable); others use file drop / webhook | More integration effort per product | Phase 2-3: CrowdStrike, Qualys, Zscaler, CyberArk, Wiz, Cloudflare native adapters |
| O-02 | Native adapters written to published API docs but not yet run against a live tenant | Field mapping surprises | Phase 1 validation step in CONNECTOR_GUIDE.md |
| O-03 | SQLite store | Single node; > ~5 entities or HA needs more | PostgreSQL store behind the same interface (Phase 4) |
| O-04 | No in-app OIDC/SAML | Reliance on the reverse proxy for SSO | Phase 4 |
| O-05 | Webhook HMAC without timestamp replay window | A captured request could be replayed (idempotent upsert limits impact) | Add signed timestamp header, 5-minute window |
| O-06 | Score weights are expert-set | Ranking may not match analyst judgement in every org | Calibrate after 60 days using analyst overrides (SCORING_MODEL.md) |
| O-07 | MTTR taken from vendor KPI | Inconsistent definitions between tools | Compute MTTR from store `first_seen` → `resolved_at` once 30 days of history exist |
| O-08 | Trends start empty in a new deployment (demo history is synthetic) | First month has thin trend charts | Optional back-fill from vendor APIs |
| O-09 | Financial exposure parameters are industry defaults | Board may challenge the figures | Finance to set `financial_exposure` per entity before first board use |
| O-10 | Docker image built in CI, not in the authoring environment | Build issue found late | CI job `docker` builds and smoke-tests the image on every push |

## 4. Verification performed

* `pytest`: 47 passed (v1.2) (scoring, verticals, correlation, pipeline phases, determinism, store, API auth/RBAC, webhook HMAC, reports, guardrail, config secrets, file-drop mapping)
* `ruff check`: clean
* `python -m lodestar validate`: ready (demo); FAIL items reported correctly in live mode without keys
* Live mode with no credentials: pipeline completes, six connector failures isolated and reported, firewall CSV via file drop ingested
* Dashboard rendered at 1400 px (light and dark) and 400 px (phone): no horizontal overflow, no script errors
* Output distribution across eight industries:

| Organisation (fictional) | Industry | Signals | Today | Attack paths | Decisions for people | Posture |
|---|---|---:|---:|---:|---:|---:|
| Sandline Bank | Banking | 1,554 | 28 | 20 | 25 | 60.3 |
| Lumenpay | Fintech | 1,902 | 25 | 18 | 21 | 60.0 |
| Aerolume Airways | Aviation | 1,861 | 41 | 19 | 22 | 57.4 |
| Souqara Retail Group | Retail | 1,688 | 32 | 20 | 23 | 63.4 |
| Petrava Energy | Oil & gas | 1,796 | 25 | 17 | 20 | 63.5 |
| Helionyx Power & Water | Power & utilities | 1,663 | 30 | 17 | 20 | 58.4 |
| Corvianet Telecom | Telecom | 1,708 | 25 | 18 | 21 | 63.5 |
| Portaris Terminals | Ports & logistics | 1,601 | 26 | 20 | 23 | 60.5 |

Where a Today list exceeds 25 (aviation, retail, bank, utility, port), every extra item belong to attack paths, KEV or active
exploitation; those are never deferred by the capacity cap.

## 5. Review of v1.1 (decision desk, ChatOps, fraud)

**Trigger:** stakeholder review of the v1.0 dashboard found no single place that says what a
*person* must decide now. It also found that Slack/Teams were missing and that fraud, a core risk
for financial institutions, was absent.

| # | Severity | Finding | Fix |
|---|---|---|---|
| PR-15 | High | Approvals were buried in the action table; nothing said who must decide, by when, or what the agents would not do | New **DecisionAgent** and **Decision desk** widget: role, deadline, options, "agents prepared" vs "agents will not", consequence of no decision; role-gated verdicts with audit; only approval releases ITSM |
| PR-16 | High | No fraud coverage for banks/fintechs, and cyber and fraud signals were never joined | **FraudSentinelAgent** (19th domain), cyber-enabled fraud rules LDS-011/012/013, fraud KRIs, MLRO suspicious-transaction decisions, fraud panel and report section |
| PR-17 | High | First decision-clock design used the oldest member signal, so 12 of 19 decisions showed as hundreds of hours overdue on first sight | The clock starts when LODESTAR first raises the decision and persists across runs; signal age is shown separately |
| PR-18 | Medium | The first LDS-012 draft (employee credentials + payment) would have matched any user who happened to have an identity alert and a fraud alert | Fraud leg restricted to employee payment-approval alerts (`internal` tag) |
| PR-19 | Medium | MLRO / STR decisions appeared for airlines, retailers and telcos | Raised only where fraud is a mandatory control (banking, fintech profiles) |
| PR-20 | Medium | Chat channels are a new way in for spoofed requests and unauthorised decisions | Slack signing-secret (5-minute window) and Teams HMAC verification; chat users map to roles; unmapped users are read-only |
| PR-21 | Low | The offline (exported) dashboard cannot answer free-text chat | Pre-computed answers from the same engine for suggested questions; the panel says so; full chat via API, Slack, Teams or CLI |
| PR-22 | Low | Light-first theme unsuitable for 24x7 operations rooms | Dark-first operations-centre theme with TLP marking, local/UTC clocks; light theme on request |
| PR-23 | Low | Lint caught a missing import that would have broken `/api/agents` | Fixed before release; lint runs in CI |

**New open items**

| # | Item | Planned |
|---|---|---|
| O-11 | Teams decisions are text commands (outgoing webhooks cannot carry card actions) | Teams bot (Bot Framework) with Adaptive Card actions |
| O-12 | Chat-to-role mapping is maintained in YAML | Sync from Entra ID / Slack user groups |
| O-13 | No native fraud-engine adapter yet (webhook / file drop only) | Feedzai and Actimize adapters |
| O-14 | Decision playbook deadlines are defaults | Agree with the CISO, MLRO and OT operations during Phase 2 |

## 6. Review of v1.2 (bug bounty, threat-intel feeds, advisory e-mail)

| # | Severity | Finding | Fix |
|---|---|---|---|
| PR-24 | High | Researcher reports and CERT / ISAC / PSIRT advisories reached the team only by e-mail and were matched to assets by hand | `BugBountyAgent` (HackerOne API + signed webhooks + VDP mailbox) and `ThreatFeedAgent` (TAXII 2.1, MISP, CSAF 2.0, advisory mailbox) with alias, CVE, product and IOC matching |
| PR-25 | High | Raw feeds would flood the Today list with advisories irrelevant to the organisation | Relevance filter: keep only items matching our CVEs, product tags, telemetry IOCs, or our sector at high severity. Demo: 20 ingested → 2-4 kept |
| PR-26 | High | A spoofed "CERT advisory" e-mail could trigger an emergency | Sender allow-list, DKIM/SPF check (unverified capped at medium), no link following, deterministic parsing; prompt-injection text covered by a test |
| PR-27 | High | TLP-restricted intelligence could leak into chat channels or reports | TLP stored on every finding; TLP:RED titles never leave the dashboard |
| PR-28 | Medium | Critical-infrastructure operators have legal notification clocks that nobody tracked | `critical_infrastructure` and `incident_reporting` in industry profiles; an IOC sighting raises a regulatory notification decision with the profile deadline |
| PR-29 | Medium | Researcher proof-of-concept detail is sensitive | Not copied from HackerOne; only title, severity, CWE, asset, state and link |
| PR-30 | Medium | Mock adapter shared mutable evidence with the generator, so tags were duplicated across runs | Deep copy on load; tags rebuilt immutably |
| PR-31 | Low | Energy and utility profiles have no internet-facing crown jewel, so demo researcher reports landed on DCS/SCADA | Demo adds a customer/partner portal for those profiles |
| PR-32 | Low | One connector per domain could not hold several intel sources | Multi-source connectors with per-source failure isolation and merged health (stale feed shown by name) |

**New open items**

| # | Item | Planned |
|---|---|---|
| O-15 | HackerOne, TAXII, MISP and CSAF adapters follow published specs but need validation against your tenants and feeds | Phase 1/2 validation |
| O-16 | `incident_reporting` authorities and hours are placeholders | Confirm with Legal per jurisdiction |
| O-17 | No Bugcrowd / Intigriti native adapters (use mailbox or webhook) | Roadmap |
| O-18 | STIX patterns are parsed for common observables only (IP, domain, URL, SHA-256) | Extend parser as feeds require |

## 7. Review of v2.0: deployable by other teams, in any industry, in one to two days

The v1.3 review asked whether a team other than the authors could deploy LODESTAR on real data
and trust its numbers. It found six blockers. Each one is fixed below and covered by tests (90+ in total).

| # | Severity | Blocker in v1.3 | Fix in v2.0 |
|---|---|---|---|
| B1 | Critical | No finding history. Every run replaced the last, so a tool outage made risk "disappear", first-seen reset, and MTTR / SLA could not be measured | `LifecycleAgent` + store v2: sticky first-seen; carry-forward on failed, skipped or empty sources; snapshot resolution after N complete pulls; incremental sources (Graph `lastUpdateDateTime`, Tenable `since` + `FIXED`, SIEM `{since}`) with cursors per source; expiry for alerts and advisories; schema migrations from v1 |
| B2 | Critical | Findings matched assets only by exact name, so FQDN / short name / IP / device-id variants became "unknown assets" and users were counted several times | `EntityResolver`: FQDN, unambiguous short name, IP, MAC, EDR / scanner / cloud ids and wildcards to one CMDB asset; UPN / e-mail / `DOMAIN\sam` / object id to one identity (`identities.csv`); ambiguity reported, never guessed; dedupe after resolution |
| B3 | High | Intel indicators were only matched against IOCs already present in alerts, so an ISAC indicator seen in proxy or DNS logs was missed | `ThreatHuntAgent`: one read-only KQL / SPL hunt per run over network, DNS, file, CEF and e-mail telemetry; sightings become SOC detections and mark the advisory *sighted* |
| B4 | High | KRIs defaulted to good values when a tool was not integrated (e.g. 100% SLA with no scanner), inflating posture | KRI provenance (connector, LODESTAR lifecycle, findings, manual with expiry); not measured = not counted as within appetite; KRI coverage % and a *provisional* posture flag; `lodestar kpis` |
| B5 | High | Three native adapters; every other product needed a custom field map, which is weeks of work per organisation | SIEM-first `sentinel` and `splunk` adapters (any domain, incremental or snapshot, health queries for KPIs) + a catalogue of ready-made queries; contract tests with recorded responses for Graph, Log Analytics, Splunk, Tenable and HackerOne |
| B6 | High | One organisation per deployment; SSO only through a proxy; no readiness, metrics or backups | Tenants (`config/tenants/*.yaml`); org-scoped keys, SSO groups, chat channels and webhooks; in-app OIDC + bearer JWT; signed sessions + CSRF; `/readyz`, `/metrics`, JSON logs; nightly prune + backup; lease locks; pinned dependencies |

Onboarding: `lodestar init` (SIEM-first configuration for the chosen industry, generated secrets,
CMDB template) and `lodestar doctor` (one readiness screen with a fix for every gap).
See [QUICKSTART.md](QUICKSTART.md) and [PRODUCTION.md](PRODUCTION.md).

**Closed from earlier lists:** O-04 (in-app OIDC), O-05 (webhook replay window, opt-in), O-07
(MTTR computed from history), PR-13 follow-up (per-organisation access).

**Still open, stated plainly**

| # | Item | Why it matters | Plan |
|---|---|---|---|
| O-19 | Adapters and query templates are tested against recorded responses, not your tenant | Column names differ by connector version | Week-1 validation with `test-connector` against each console (QUICKSTART) |
| O-20 | SQLite on one node | No active-active HA | PostgreSQL `Store` implementation |
| O-21 | Lifecycle MTTR needs history | The first weeks show vendor KPIs or "not measured" | Automatic once at least 3 items have closed |
| O-22 | Threat hunt covers IP, domain and hash indicators | URL-path and JA3 indicators are not hunted | Extend the templates as feeds require |
| O-23 | Webhook timestamps are optional by default | Senders that only sign the body can be replayed within retention (upsert is idempotent) | Turn on `webhook_require_timestamp` once all senders are updated |
| O-24 | No threat-intel hunting in Sumo Logic or Google SecOps | Indicators are not searched in those SIEMs | Add hunt providers once field conventions are agreed per tenant |
| O-25 | Google SecOps adapter is a preview | Regional endpoint and API version vary by tenant | Validate on a live tenant with `test-connector`, then mark native |

**Independent second-pass review of v2.0 (findings fixed before release, each with a regression test)**

| # | Severity | Finding | Fix |
|---|---|---|---|
| PR-33 | High | A tenant file could override `mode` / `security` / `chatops` and switch off authentication for every organisation | Deployment-wide keys are rejected in tenant files (`test_tenant_file_cannot_weaken_deployment_settings`) |
| PR-34 | Medium | With exactly one tenant file, webhook items were stored without an organisation and never read | Stored under that tenant (`test_single_tenant_file_webhook_is_readable`) |
| PR-35 | Medium | An unmapped Slack channel in a multi-tenant deployment fell back to the first organisation | Refused with an explanation (`test_multi_tenant_chat_without_mapping_is_refused`) |
| PR-36 | Medium | Risk-accepted findings disappeared while a source was down, and their miss count never advanced | Every non-closed status is carried; misses always recorded |
| PR-37 | Medium | "Connector removed" and "expired" closures counted as fixes in MTTR / SLA | Excluded from lifecycle KPIs; lifecycle KPIs need the scanner integrated |
| PR-38 | Medium | Internet-facing criticals and attack paths read "0, within appetite" when nothing could measure them | Source and phase requirements per KRI |
| PR-39 | Medium | IOC hunt missed MD5 / SHA-1 hits and `host:port` values | Indicator chosen by which hash matched; ports stripped when matching |
| PR-40 | Low | Unknown JWT `kid` re-fetched JWKS on every request; webhook `?org=` not covered by a shared secret; escalation marked sent before delivery; simultaneous approvals could open two tickets; malformed JSON returned 500; `/readyz` listed organisation names | JWKS refetch at most once a minute; per-organisation webhook secret mandatory with several organisations; mark after delivery; lease lock around ticket creation; 400 on bad JSON; `/readyz` returns counts only |

## 8. Review of v2.1: SIEM coverage and repository hygiene

A review of the repository as published on GitHub (fresh clone, tests, links, workflows) with a focus on
SIEM integration, the integration teams ask about first.

| # | Severity | Finding | Fix |
|---|---|---|---|
| PR-41 | High | The README listed QRadar as a supported SOC/SIEM source, but no QRadar adapter existed; only Sentinel and Splunk could be queried | Native `qradar` adapter (AQL search and open offenses) with contract tests; `docs/SIEM_INTEGRATION.md` states the support level of every platform |
| PR-42 | High | Organisations on Elastic, OpenSearch / Wazuh, Sumo Logic or Google SecOps had no SIEM-first path, so a one-to-two-day start was not possible for them | Native `elastic` (ES\|QL and Query DSL), `sumologic` (Search Job API) and `google_secops` (UDM search, preview) adapters; `init --siem` templates for each |
| PR-43 | Medium | SIEMs without an adapter (LogRhythm, Exabeam, Securonix, FortiSIEM, InsightIDR ...) could only use file drop or webhook | Generic `http_json` adapter: bearer / header / basic / OAuth2, placeholders, pagination, dotted record paths |
| PR-44 | Medium | Threat-intel hunting only ran on Sentinel and Splunk | QRadar (AQL) and Elastic / OpenSearch (ECS Query DSL) hunt providers; results aggregated per host and user |
| PR-45 | Low | No dedicated integration page; SIEM facts were spread across four documents | `docs/SIEM_INTEGRATION.md`: supported platforms, least privilege, setup, mapping, hunting, limits, troubleshooting; README "Supported SIEM platforms" table |
| PR-46 | Low | Workflow actions referenced by moving tags; no Dependabot, code owners or changelog; the setup guide still said "47 tests" and did not cover protected branches | Actions pinned to commit SHAs with `persist-credentials: false` and timeouts; Dependabot (pip, actions grouped, Docker), CODEOWNERS, CHANGELOG; GITHUB_SETUP updated with the pull-request flow |

Open items added: hunting in Sumo Logic and Google SecOps (O-24); Google SecOps out of preview after
validation on a live tenant (O-25).
