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

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/architecture-dark.svg">
  <img alt="LODESTAR architecture diagram" src="images/architecture-light.svg" width="100%">
</picture>

Run order inside one pipeline run (the orchestrator holds a per-organisation lease, so the API,
scheduler and CLI never run the same organisation twice at once):

```
AssetContext ─► 21 ConnectorAgents ─► ThreatHunt* ─► DataQuality ─► IngestionMonitor ─► Lifecycle ─► ThreatIntel ─► ControlAssurance
             ─► Correlation ─► Prioritization ─► ComplianceMapping ─► Action ─► Decision ─► Store
                                                                     * optional, needs a SIEM (threat_hunt.enabled)
On demand / on schedule: Reporting, Narrative, ChatOps (Slack, Teams, dashboard, CLI), escalations, ingestion alerts, backups.
Read by AI assistants: the MCP server at /mcp/ (read-only tools over the stored results, see MCP.md).
```

| Stage | What it guarantees |
|---|---|
| ConnectorAgents | One per control domain, several sources each, each source on its own cadence (`interval_minutes` or the domain default). A source that fails, is skipped by its cadence, or returns nothing is recorded as such and **never** resolves earlier findings; it contributes its last good health, aged. Incremental sources keep a cursor in `connector_state`. |
| ThreatHunt | Recent intel indicators (IP, domain, hash) are searched in SIEM telemetry with one read-only query; sightings become SOC detections. |
| DataQuality | Hostnames, FQDNs, IPs, MACs, EDR device ids, cloud ids and URLs resolve to one CMDB asset; UPN / e-mail / `DOMAIN\sam` / object id resolve to one identity. Ambiguous short names are reported, never guessed. |
| IngestionMonitor | Every source gets a state (healthy, retrying, failing, stale, volume_drop, volume_spike, degraded, awaiting_data) from this fetch and its history. Failing, stale and volume-drop sources raise a coverage-gap finding and an alert; see [INGESTION_OPERATIONS.md](INGESTION_OPERATIONS.md). |
| Lifecycle | First-seen is sticky across runs. Snapshot sources resolve an item after N consecutive complete pulls without it; incremental sources close items when the source says so, or expire alerts after N days. Carried-forward items are re-scored every run. |
| Prioritization → Decision | Score, horizon and "why", attack paths, framework impact, drafted actions and the decisions only a human may take. |
| Metrics | Each KRI carries its provenance (connector KPI, measured by LODESTAR from history, manual with an expiry, or **not measured**). Unmeasured KRIs lower the posture score and mark it provisional. |

### Data model (abridged)

| Object | Key fields |
|---|---|
| `Finding` | domain, source, type (vulnerability, detection, misconfiguration, coverage_gap, policy_violation, exposure, incident), severity, asset/user/app ids, CVE, KEV/EPSS, compensating controls, correlation ids, score, horizon, why, owner team, due date, framework tags |
| `ControlHealth` | domain, product, coverage %, data freshness, policy drift, issues, KPIs, effectiveness, status |
| `Correlation` | rule, title, narrative, severity, member findings, domains, entity, recommended action, MITRE ATT&CK |
| `DailySnapshot` | posture, counts by horizon / severity / domain, SLA breaches, KRIs, control effectiveness |
| `PipelineResult` | all of the above plus data quality, compliance, actions, history |

### Adapters

| Adapter | Sync | Use |
|---|---|---|
| `sentinel` | incremental when the KQL uses `{since}` | Any domain already in Microsoft Sentinel / Log Analytics (Log Analytics Reader) |
| `splunk` | incremental when the SPL uses `{since_epoch}` | Any domain already in Splunk (search role + token) |
| `qradar` | incremental when the AQL uses `{since_ms}`; offenses = snapshot | IBM QRadar: Ariel AQL search or the open-offense list (authorised service token) |
| `elastic` | incremental when ES\|QL / DSL uses `{since}` | Elastic Security / Elasticsearch, OpenSearch, Wazuh indexer (read on indices) |
| `sumologic` | incremental (messages) / snapshot (records) | Sumo Logic Search Job API (access ID + key) |
| `google_secops` | incremental | Google SecOps (Chronicle) UDM search, service account (preview) |
| `http_json` | incremental when a `{since}` placeholder is used | Any SIEM or tool with a REST/JSON read API; bearer, header, basic or OAuth2 |
| `mcp` | incremental when a `{since}` placeholder is used | A vendor's remote MCP server: one named read-only tool, mapped like `http_json` ([MCP.md](MCP.md)) |
| `ms_graph_security` | incremental (`lastUpdateDateTime`) | Defender XDR alerts: endpoint, identity, Office 365, cloud apps, cloud |
| `entra_identity_protection` | snapshot | Risky users + MFA registration coverage |
| `tenable_vm` | incremental (`since`, FIXED closes) | Tenable Vulnerability Management export API |
| `hackerone` | snapshot | HackerOne programme reports (plus signed webhooks) |
| `taxii`, `misp`, `csaf`, `mailbox` | incremental | CERT / ISAC TAXII 2.1, MISP, CSAF advisories, advisory e-mail |
| `file_drop` | snapshot (newest file) | Any product that can export CSV/JSON; `field_map` translates columns |
| `webhook` | incremental | Products or SOAR push to `POST /api/ingest/{domain}?org=` with an HMAC signature |
| `mock` | - | Demo mode; reads the synthetic dataset |

## Scale and tenancy

| Dimension | v2.0 | Path |
|---|---|---|
| Findings per run | tested at ~2,000 per organisation in < 2 s | Linear; correlation is indexed by entity key |
| Organisations | `config/tenants/*.yaml`, one store, every table org-scoped; API keys, SSO groups and chat channels map to organisations | Separate deployments where regulation requires physical separation |
| Ingestion | scheduled pulls with cursors + signed webhooks | Move the webhook inbox to a queue (Service Bus / Kafka) and run connector agents as workers |
| HA | one API container + one scheduler; lease locks prevent double runs | PostgreSQL implementation of the `Store` interface, then a stateless API behind a load balancer |

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
