# Phased deployment

> How to configure and test each agent is in [AGENT_SETUP.md](AGENT_SETUP.md). This page covers sequencing and exit criteria.

Each phase is independently useful, has a go-live gate (`python -m lodestar validate --phase N`)
and measurable exit criteria. Phases are set with `deployment_phase` in `config/lodestar.yaml`;
agents above the configured phase do not run, so a half-configured later phase cannot break
an earlier one.

| Phase | Weeks* | Agents switched on | Business outcome |
|---:|---|---|---|
| 0 Foundation | 0-2 | Orchestrator, AssetContext, DataQuality | Platform running, CMDB / crown jewels loaded, demo dashboard for stakeholders |
| 1 See & prioritise | 3-6 | EDR, VMDR, Identity, SOC, Email connectors; **CERT / ISAC / PSIRT feeds and advisory mailbox**; ThreatIntel, ControlAssurance, Prioritization; weekly report | Daily Today list, external advisories matched to our estate, weekly ops report |
| 2 Attack paths, decisions & chat | 7-10 | Firewall, WAF, Web proxy, ZTNA, PAM, Cloud, **Fraud**, **Bug bounty (HackerOne)** connectors; Correlation, Action, **Decision desk**, **Slack/Teams ChatOps** (+ ITSM in dry-run) | Toxic combinations, accountable human decisions, focus brief in chat |
| 3 Full coverage | 11-14 | SAST, DAST, Brand, AI security, DLP, OT, Backup connectors; ComplianceMapping; monthly report | Framework readiness, AI and OT risk in one view |
| 4 Executive & scale | 15-18 | Narrative (optional LLM), quarterly board report, further entities / verticals, ITSM live submission | Board pack, multi-entity roll-out |

\* Indicative for one entity with an available integration engineer; adjust to your change calendar.

## Phase 0 - Foundation

1. Provision a VM or container host (2 vCPU, 4 GB RAM, 20 GB disk is enough for one entity on SQLite).
2. `git clone`, `cp .env.example .env`, generate keys: `python -c "import secrets;print(secrets.token_urlsafe(32))"`.
3. Set `org.name`, `org.vertical` and `mode: demo` and run `python -m lodestar demo` for stakeholder walk-throughs.
4. Export the CMDB / crown-jewel register to `config/assets.csv` (columns in `config/assets.example.csv`) and set `assets.path`.
5. Put the service behind your SSO-aware reverse proxy (Entra Application Proxy, Cloudflare Access, oauth2-proxy) with TLS. Keep `127.0.0.1` binding in `docker-compose.yml`.

**Exit criteria:** demo reviewed by CISO; asset register loaded; `validate --phase 0` = ready; API keys issued per role.

## Phase 1 - See & prioritise

1. Create read-only API identities (see least-privilege column in `docs/AGENT_CATALOG.md`):
   Microsoft app registration with `SecurityAlert.Read.All`, `IdentityRiskyUser.Read.All`, `AuditLog.Read.All`; Tenable API keys for a read-only user. For other products choose `file_drop` or `webhook`.
2. Fill `.env`; set `mode: live`, `deployment_phase: 1`.
3. `python -m lodestar validate --phase 1` until `RESULT: ready`.
4. `docker compose up -d` (API + scheduler every 4 hours).
5. Optional: `threat_intel.live: true` if egress to `cisa.gov` and `api.first.org` is allowed.
6. External intelligence: connect the national CERT / ISAC TAXII or MISP, CSAF advisories and the advisory mailbox; add `aliases` and `vendor:`/`product:` tags to the CMDB export so advisories and researcher reports match assets (EXTERNAL_INTEL.md). Critical-infrastructure operators: confirm `incident_reporting` in the industry profile with Legal.

**Exit criteria (2 weeks of running):**
* data freshness < 24 h on all phase-1 connectors (Control assurance tiles healthy)
* CMDB match rate ≥ 90 % (shown in the dashboard footer)
* CISO and SOC lead agree that ≥ 8 of the top 10 Today items are the right priorities
* first weekly report circulated to technical leads

## Phase 2 - Attack paths & action

1. Enable firewall, WAF, web proxy, ZTNA, PAM, cloud connectors. Set `LODESTAR_WEBHOOK_SECRET` for webhook adapters and configure the sending product / SOAR to sign payloads (HMAC-SHA256 header `X-Lodestar-Signature: sha256=<hex>`).
2. `deployment_phase: 2`; review the correlation rules with the SOC; disable any that do not fit by removing them from `RULES`.
3. Configure `itsm` with `dry_run: true`; approve a sample of actions and review payloads with the service-management owner.
4. Agree the Decision-desk RACI: map each decider role in `PLAYBOOKS` (decision.py) to real people; give decision-authority (`ciso`) keys / chat mappings to the CISO, MLRO, Head of Fraud and OT manager. See HUMAN_IN_THE_LOOP.md.
5. Financial institutions: connect the fraud engine (`fraud` connector, webhook or file drop) and review LDS-011..013 with the Head of Fraud. See FRAUD_MANAGEMENT.md.
6. ChatOps: create the Slack app and/or Teams Workflows + outgoing webhook (CHATOPS.md); start with the daily brief to one private leadership channel, then add team channels.

**Exit criteria:** attack paths reviewed weekly; ≥ 80 % of Today items have an owner team; every *now* decision gets a verdict before its deadline for two consecutive weeks; ITSM payload format signed off.

## Phase 3 - Full coverage

1. Enable SAST, DAST, brand, AI security, DLP, OT (where the profile requires it) and backup connectors.
2. `deployment_phase: 3`; agree framework mapping packs with GRC (`config/frameworks.yaml`).
3. Issue the first monthly report to the CISO / CIO / risk committee.

**Exit criteria:** all mandatory controls for the industry profile integrated (`validate` shows no WARN); data trust ≥ 85.

## Phase 4 - Executive & scale

1. Quarterly board report (`python -m lodestar report --period quarterly`). Review the indicative financial-exposure parameters in the industry profile (`financial_exposure`) with Finance before the first board use.
2. Optional LLM narrative: `llm.provider: anthropic` + `ANTHROPIC_API_KEY`. Only aggregated facts are sent; output with numbers not present in the facts is discarded automatically.
3. Additional entities: one config file per entity (`--config config/entity-x.yaml`), same store or separate store per entity. For more than ~5 entities or HA, move the store to PostgreSQL (see ARCHITECTURE.md).
4. Switch ITSM `dry_run: false` after change-board approval.

**Exit criteria:** board pack produced from LODESTAR without manual rework; quarterly KRI targets agreed.

## Rollback

Every phase is a configuration change. Lower `deployment_phase` and restart; data already
collected is kept. Container images are versioned (`lodestar:2.0.0`).
