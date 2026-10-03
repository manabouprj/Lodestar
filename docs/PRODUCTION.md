# Running LODESTAR in production

This page covers what an operations or security-engineering team needs: topology, access
(SSO and keys), several organisations, monitoring, backups, upgrades and the finding lifecycle.
Day-one setup is in [QUICKSTART.md](QUICKSTART.md).

## Topology

```
             users (browser, Slack, Teams)                      Prometheus        SIEM (logs)
                        │ HTTPS                                     │ /metrics        ▲ JSON logs
                        ▼                                           │                 │
   reverse proxy / WAF (TLS, HSTS) ──► api container :8080 ─────────┴─────────────────┘
                                          │  (FastAPI: dashboard, API, chat, webhooks)
                                          │
                     data volume ◄────────┤  SQLite WAL: findings history, cursors, decisions, audit
                     (backups inside)     │
                                          ▼
                                   scheduler container ──► read-only HTTPS to SIEM / vendor APIs / feeds
```

* `docker compose up -d` starts both containers. They run non-root on read-only root filesystems
  with every capability dropped. Only the data and report volumes are writable.
* Bind the API to localhost (the default) and publish it through your reverse proxy with TLS.
  Keep `security.secure_cookies: true`.
* Run **one** scheduler per deployment. Every run takes a per-organisation lease, so an
  on-demand run from the API or CLI never overlaps a scheduled one. The second caller gets
  `409` or "skipped".
* Sizing: 2 vCPU and 4 GB RAM handle several organisations with 10,000+ open findings each.
  SQLite is the right store up to that scale on one node. Beyond it, or for active-active HA, a
  PostgreSQL implementation of the `Store` interface is on the roadmap.

## Access

### Single sign-on

Example with Microsoft Entra ID (Okta, Google, Ping and Keycloak work the same way through OIDC):

1. Create an **app registration** named "LODESTAR" with redirect URI (Web)
   `https://lodestar.your-org.example/auth/callback`, and create a client secret.
2. Under **Token configuration**, add a **groups claim** (security groups, as group IDs). For
   large tenants, assign groups to the enterprise app and emit only the assigned groups.
3. Create or choose three groups: LODESTAR CISO, LODESTAR Analysts and LODESTAR Executives.
4. In `.env`, set `OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`,
   `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `LODESTAR_PUBLIC_URL`.
5. Map the groups in `config/lodestar.yaml`:

```yaml
security:
  oidc:
    issuer: ${OIDC_ISSUER}
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    redirect_uri: ${LODESTAR_PUBLIC_URL}/auth/callback
    role_map:
      "6f1c...-ciso-group-id": ciso
      "0a2b...-soc-group-id": analyst
      "9e8d...-exec-group-id": exec
    org_map: {}            # several organisations: {"<group id>": "acme-bank", "<group id>": "*"}
```

How sign-in works:

* The flow is authorisation code with PKCE, a `state` and `nonce` check, and the ID token
  verified against the issuer's JWKS (signature, issuer, audience, expiry).
* The highest mapped role wins.
* A user in no mapped group is refused, and the refusal is audit-logged.
* Sessions are HMAC-signed cookies (`LODESTAR_SESSION_SECRET`, 8 hours, HttpOnly, Secure,
  SameSite=Lax).
* Every cookie-authenticated POST needs the CSRF token. The dashboard sends it automatically.

Service-to-service callers can send `Authorization: Bearer <token>` from the same identity
provider. The token is verified with `security.oidc.audience`.

### API keys

`LODESTAR_API_KEYS="ciso:<key>,analyst@acme-bank:<key>,exec:<key>"`. Keys must be at least 16
characters (`lodestar init` generates 32). A key written as `role@org` sees only that organisation.
To rotate a key, add the new one, deploy, move the callers over, then remove the old one. Keys suit
automation and small teams; people should sign in with SSO.

| Role | Can |
|---|---|
| exec | Dashboard, reports, KRIs, decisions (view) |
| analyst | + priorities, findings, attack paths, controls, approve actions, decide operational items |
| ciso | + run the pipeline, audit log (when mapped to every organisation), regulatory, risk-acceptance and safety decisions |

## Several organisations

Use one file per organisation in `config/tenants/` (start from `example-tenant.yaml`, or run
`lodestar init --tenant`). Each file is deep-merged over `config/lodestar.yaml`, except
`connectors`, which each tenant declares in full. Tenants may set their own industry,
`deployment_phase`, scoring, KPIs, ITSM and identity settings.

Deployment-wide settings can only be set in `lodestar.yaml`, so that one tenant file cannot weaken
access for all of them: `mode`, `security`, `chatops`, `storage`, `ops` and `tenants`. All organisations share one store, and every
table is org-scoped. Access is separated by:

* API keys and SSO `org_map` (users only see their organisations; other organisations return `404`, not `403`);
* Slack `channel_orgs` and the Teams outgoing-webhook URL `?org=`;
* webhook ingest `?org=`, signed with that organisation's own secret `LODESTAR_WEBHOOK_SECRET_<ORG_KEY>`.
  With several organisations, the per-organisation secret is mandatory, and a request without
  `?org=` is rejected;
* chat channels with no organisation mapping, which are told so and shown no data.

If regulation requires physical separation, run separate deployments.

## Monitoring

| Endpoint | Use |
|---|---|
| `/healthz` | Liveness: the process answers |
| `/readyz` | Readiness: the store is reachable and every organisation has a run newer than `ops.max_run_age_hours` (`503` otherwise) |
| `/metrics` | Prometheus. Requires `Authorization: Bearer $LODESTAR_METRICS_TOKEN` |

Suggested alerts:

```yaml
- alert: LodestarRunsStale          # scheduler stopped or failing (it ticks every 15 min)
  expr: time() - lodestar_last_run_timestamp_seconds > 3600
- alert: LodestarSourceFailing      # IngestionMonitorAgent: failing or stale (findings are carried, not closed)
  expr: lodestar_source_state{state=~"failing|stale"} == 1
  for: 10m
- alert: LodestarDecisionsWaiting
  expr: lodestar_decisions_pending > 10
- alert: LodestarKRIsUnmeasured
  expr: lodestar_kri_coverage_pct < 60
```

Ingestion has its own validation and alerting (Slack, Teams or a webhook, without Prometheus): see
[INGESTION_OPERATIONS.md](INGESTION_OPERATIONS.md). The MCP endpoint for AI assistants (`/mcp/`) shares the
API's authentication and audit: see [MCP.md](MCP.md).

Set `LODESTAR_LOG_FORMAT=json` to write one JSON object per line and ship the logs to your SIEM.
The audit trail (sign-ins, runs, verdicts, approvals, webhook ingests) is in the store and at
`GET /api/audit` (ciso role).

## Backups, retention and restore

* The scheduler runs nightly maintenance. It prunes data by `ops.retention` (closed findings 400
  days, webhook items 60, audit 400, snapshots 800) and writes an online backup to
  `ops.backup_dir`, keeping `ops.backup_keep` copies. Copy them off the host.
* For an on-demand backup, run `python -m lodestar backup --out D:\backups\lodestar.db`. It is safe
  while LODESTAR is running.
* To restore: stop both containers, copy the backup over `data/lodestar.db`, then start them again.

## Upgrades

1. `python -m lodestar backup`
2. `git pull` (or deploy the new image)
3. `pip install -r requirements.txt`. These are pinned versions. Direct dependencies are listed in
   `requirements.in`, and `make lock` regenerates the pins.
4. Start LODESTAR. Schema migrations run automatically and are idempotent (`schema_version` table).
5. Run `python -m lodestar doctor`.

## Finding lifecycle

LODESTAR keeps a history of every finding. "Resolved" only means resolved:

| Situation | Result |
|---|---|
| Seen again | Kept open; **first seen** keeps its earliest date |
| The source failed, was skipped by its interval, or returned no data | **Carried forward** unchanged. A broken tool never makes risk disappear |
| Snapshot source (file drop, a SIEM query without `{since}`), item absent | Resolved after `lifecycle.resolve_after_missed` consecutive complete pulls (default 2) |
| Incremental source (Graph, Tenable, a SIEM query with `{since}`, webhooks, feeds) | Closed when the source reports it closed (e.g. Tenable `FIXED`, alert `resolved`). Alerts and advisories without an update expire after `detection_expiry_days` / `intel_expiry_days` |
| Connector removed from the config | Resolved as "source no longer integrated" |

MTTR and SLA attainment are then measured from this history (`lodestar:lifecycle` in `lodestar kpis`).

## Honest posture

Each KRI records its source: the control's own KPI, a measurement LODESTAR derives from history,
a manual value with an expiry date, or **not measured**. A KRI that is not measured never counts
as within appetite. The posture score is marked **provisional** when fewer than 60% of the
industry profile's KRIs are measured, or when data confidence is low.

## Hardening checklist

- [ ] TLS at the reverse proxy; the API bound to localhost or a private network
- [ ] SSO with group mapping; API keys only for automation; `LODESTAR_SESSION_SECRET` set
- [ ] Secrets injected from your vault as environment variables (`.env` only on single hosts, file mode 600)
- [ ] Every connector credential is read-only (see each product in [AGENT_SETUP.md](AGENT_SETUP.md))
- [ ] Egress allow-list limited to the hosts `lodestar doctor --online` reports
- [ ] `/metrics` token set; alerts above in place
- [ ] Nightly backups copied off-host; a restore tested once
- [ ] `itsm.dry_run` stays `true` until the change board signs off on the ticket format
- [ ] LLM narrative (`llm.provider`) stays `none` unless your data-handling policy allows aggregates to leave
