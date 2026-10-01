# Architecture

## Design principles

1. **One data contract.** Every connector emits `Finding` and `ControlHealth` objects
   (`lodestar/models.py`). Core agents never see vendor formats, so adding a product never
   touches correlation, scoring or reporting.
2. **Configuration over code for industries.** Weights, SLAs, KRIs, frameworks, crown jewels,
   financial-exposure parameters and terminology live in `config/verticals/*.yaml`.
3. **Deterministic and explainable first, AI where it adds value.** Ranking is a transparent
   formula. Language models are used only to write narrative, behind a numeric grounding check,
   and are off by default.
4. **Read-only and human-in-the-loop.** Connectors only read. The only write path (ITSM tickets)
   requires an explicit approval and defaults to dry-run.
5. **Failure isolation.** An agent that fails is recorded and skipped; the pipeline completes and
   the dashboard shows lower data confidence instead of going dark.
6. **Phase-gated.** Agents declare a deployment phase; the orchestrator only runs what the
   configured phase allows.

## Components

```
                    ┌──────────────────────────── Orchestrator (phase-aware) ────────────────────────────┐
 Vendor APIs  ──►   │ AssetContext → 18 ConnectorAgents → DataQuality → ThreatIntel → ControlAssurance    │
 File drops   ──►   │ → Correlation → Prioritization → ComplianceMapping → Action                         │
 Webhooks     ──►   └──────────────┬───────────────────────────────────────────────────────────────────┘
 (HMAC)                            ▼
                            Store (SQLite → Postgres)  ── runs · snapshots · findings · webhook · audit
                                   │
                ┌──────────────────┼──────────────────────┐
                ▼                  ▼                      ▼
         REST API + RBAC     Reporting + Narrative     Scheduler
         Dashboard           weekly/monthly/quarterly  (every N hours, calendar reports)
```

### Data model (abridged)

| Object | Key fields |
|---|---|
| `Finding` | domain, source, type (vulnerability, detection, misconfiguration, coverage_gap, policy_violation, exposure, incident), severity, asset/user/app ids, CVE, KEV/EPSS, compensating controls, correlation ids, score, horizon, why, owner team, due date, framework tags |
| `ControlHealth` | domain, product, coverage %, data freshness, policy drift, issues, KPIs, effectiveness, status |
| `Correlation` | rule, title, narrative, severity, member findings, domains, entity, recommended action, MITRE ATT&CK |
| `DailySnapshot` | posture, counts by horizon / severity / domain, SLA breaches, KRIs, control effectiveness |
| `PipelineResult` | all of the above plus data quality, compliance, actions, history |

### Adapters

| Adapter | Use |
|---|---|
| `mock` | Demo mode; reads the synthetic dataset |
| `file_drop` | Any product that can export CSV/JSON; `field_map` translates columns |
| `webhook` | Products or SOAR push to `POST /api/ingest/{domain}` with HMAC signature; upserted by `finding_id` |
| `ms_graph_security` | Microsoft Graph `security/alerts_v2` (Defender for Endpoint, Identity, Office 365, Cloud, Cloud Apps, Sentinel) |
| `entra_identity_protection` | Risky users + MFA registration coverage |
| `tenable_vm` | Tenable Vulnerability Management export API |

## Scale

| Dimension | v1.0 | Path |
|---|---|---|
| Findings per run | tested at ~2,000 per entity in < 2 s | Linear; correlation is indexed by entity key |
| Entities | one config per entity, shared or separate SQLite | PostgreSQL store implementing the same `Store` interface; tenant column already present (`org`) |
| Throughput of ingestion | pull every 4 h + webhook | Move webhook inbox to a queue (Service Bus / Kafka) and run connector agents as separate workers |
| HA | single container + scheduler | Stateless API behind a load balancer once the store is Postgres; scheduler as a single leader job (Kubernetes CronJob) |

## Multi-industry design

Industry differences that matter to prioritisation are captured as data:

* `domain_weights` – e.g. OT ×1.45 for power utilities, PAM ×1.3 for banking, cloud ×1.3 for fintech
* `sla_days` – e.g. 7-day critical SLA for banking, 14 for energy
* `kris` – inherited baseline plus industry KRIs (OT remote access, brand takedown time…)
* `frameworks` – drives which compliance packs are applied
* `mandatory_domains` – controls whose absence lowers data trust
* `financial_exposure` – downtime cost per hour, cost per record, regulatory ceiling
* `terminology` – e.g. "SCADA / grid OT" instead of "OT"

## Technology choices

Python 3.11+, FastAPI, Pydantic v2, Jinja2, httpx, SQLite (WAL). No message broker or
external database is required for phases 0-3, which keeps the first deployment to one container.
