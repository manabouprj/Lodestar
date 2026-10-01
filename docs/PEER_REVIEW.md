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

* `pytest`: 30 passed (scoring, verticals, correlation, pipeline phases, determinism, store, API auth/RBAC, webhook HMAC, reports, guardrail, config secrets, file-drop mapping)
* `ruff check`: clean
* `python -m lodestar validate`: ready (demo); FAIL items reported correctly in live mode without keys
* Live mode with no credentials: pipeline completes, six connector failures isolated and reported, firewall CSV via file drop ingested
* Dashboard rendered at 1400 px (light and dark) and 400 px (phone): no horizontal overflow, no script errors
* Output distribution across eight industries:

| Organisation (fictional) | Industry | Signals | Today | Attack paths | Posture |
|---|---|---:|---:|---:|---:|
| Sandline Bank | Banking | 1,443 | 25 | 14 | 63.7 |
| Lumenpay | Fintech | 1,768 | 25 | 12 | 61.0 |
| Aerolume Airways | Aviation | 1,712 | 31 | 13 | 58.9 |
| Souqara Retail Group | Retail | 1,573 | 25 | 14 | 61.9 |
| Petrava Energy | Oil & gas | 1,753 | 25 | 14 | 60.1 |
| Helionyx Power & Water | Power & utilities | 1,624 | 25 | 14 | 60.1 |
| Corvianet Telecom | Telecom | 1,600 | 23 | 12 | 60.7 |
| Portaris Terminals | Ports & logistics | 1,560 | 25 | 17 | 60.1 |

Aviation's Today list exceeds 25 because all 31 items belong to attack paths, KEV or active
exploitation; those are never deferred by the capacity cap.
