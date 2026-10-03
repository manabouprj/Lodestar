# SIEM integration

Most organisations already forward their EDR, identity, e-mail, firewall, proxy, WAF and cloud alerts to a
SIEM. LODESTAR can read those domains **from the SIEM** instead of integrating each product: one read-only
credential, one network path and one query per domain. This is what makes a one-to-two-day start realistic.

This page lists the SIEM platforms LODESTAR supports, how each one is read, the least privilege it needs,
and how to set it up, test it and hunt threat-intelligence indicators in it.

## Supported SIEM platforms

| SIEM | Adapter | How LODESTAR reads it | Least privilege | Incremental | IOC hunt | Ready-made templates | Status |
|---|---|---|---|---|---|---|---|
| **Microsoft Sentinel** | `sentinel` | KQL through the Azure Monitor Logs query API | Entra app with *Log Analytics Reader* (or *Microsoft Sentinel Reader*) on the workspace | Yes (`{since}`) | Yes | EDR, identity, SOC, e-mail, cloud, firewall, WAF, web proxy | Native |
| **Splunk Enterprise / Cloud / Enterprise Security** | `splunk` | SPL through the REST search export (port 8089) | Token for a role with search on the relevant indexes | Yes (`{since_epoch}`) | Yes | EDR, SOC (ES notables) | Native |
| **IBM QRadar** (on-premises and SaaS) | `qradar` | AQL through the Ariel search API, or the open-offense list | Authorised service token for a role that can search events and view offenses | Yes (`{since_ms}`); offenses are a snapshot | Yes (IPs; domains and hashes through your custom properties) | EDR, SOC (offenses), firewall | Native |
| **Elastic Security / Elasticsearch** | `elastic` | ES\|QL (`/_query`, Elasticsearch 8.14 or later) or Query DSL (`/<index>/_search`) | API key with read on the indices | Yes (`{since}`) | Yes (ECS fields) | EDR, SOC (Security alerts), firewall | Native |
| **OpenSearch / Wazuh indexer** | `elastic` | Query DSL (`/<index>/_search`) | User with read on the indices (basic auth) | Yes (`{since}`) | Yes (ECS fields) | SOC (Wazuh alerts, see the template note) | Native |
| **Sumo Logic** (including Cloud SIEM data) | `sumologic` | Search Job API (messages or aggregate records) | Access ID and key for a role that can run searches | Yes (messages) | Not yet | SOC (Cloud SIEM signals), firewall | Native |
| **Google Security Operations** (Chronicle) | `google_secops` | UDM search through the Chronicle API | Service account that can run UDM searches on the instance | Yes | Not yet | EDR | Preview |
| **MERIDIAN** (SIEM-less, sibling product) | `webhook` | MERIDIAN pushes its cases and SOC health to a signed webhook | Per-organisation webhook secret | Push | MERIDIAN hunts itself; cases arrive as SOC findings | SOC | Native |
| **Any other SIEM**: LogRhythm, Exabeam, Securonix, FortiSIEM, Rapid7 InsightIDR, OpenText ArcSight, CrowdStrike Falcon Next-Gen SIEM, Datadog, Graylog ... | `http_json` / `webhook` / `file_drop` | The product's REST/JSON read API, a SOAR playbook that pushes to the signed webhook, or a scheduled export | A read-only API user | Yes (`http_json` with a placeholder) | No | `_generic` | Generic |

**What "Native" means.** Every native adapter is covered by contract tests against recorded responses
in the shape the vendor documents (`tests/test_contracts.py`, `tests/test_siem_platforms.py`). That
pins the request each adapter sends and how it maps the reply. It does not replace a test on your own
tenant: run `lodestar test-connector <domain>` in the first week. **Preview** means the adapter follows
the published API, but the endpoint and API version vary by tenant, so confirm them first.

**Read-only by design.** LODESTAR only runs searches and reads lists. It never changes an offense, alert,
rule or index. The one exception is housekeeping: Sumo Logic search jobs are deleted after their results
are read, to stay below the 200 concurrent-job limit.

## What to read from the SIEM, and what not

Use the SIEM for **detections and events**, which it holds for most tools. Read **state** from the
product that owns it, because SIEMs rarely hold the complete current picture:

| Domain | Best source | Why |
|---|---|---|
| EDR detections, firewall/IPS threats, WAF, web proxy, e-mail threats | SIEM | Already forwarded and normalised there |
| SOC incidents / offenses / notables | SIEM | The SOC's own case list |
| Vulnerabilities (VMDR) | The scanner (Tenable native; Qualys / Rapid7 file drop) | SIEMs rarely hold the full, current finding set |
| Identity risk (risky users, MFA coverage) | Entra ID Protection (native) or the IdP | Risk state lives in the IdP |
| Cloud posture, PAM, DLP, OT | The product (native, file drop or webhook) | Posture and coverage are not log events |

A domain can mix sources: `sources:` lists several adapters, for example the SIEM for detections and a
file drop for coverage KPIs.

## Setting up each SIEM

`lodestar init --siem <sentinel|splunk|qradar|elastic|sumologic|google_secops>` writes these blocks for
every domain that has a template and adds the variables to `.env`. Fill the blank values, then run
`lodestar doctor` and `lodestar test-connector <domain> --show 10`.

### Microsoft Sentinel

* Register an Entra app, create a client secret, and grant it *Log Analytics Reader* on the workspace.
* `.env`: `SENTINEL_WORKSPACE_ID`, `AZ_TENANT_ID`, `AZ_CLIENT_ID`, `AZ_CLIENT_SECRET`.
* Network: `login.microsoftonline.com` and `api.loganalytics.io` (443), through the corporate proxy if needed.

### Splunk

* Create a role with `search` on the relevant indexes (for example `notable`, `edr`) and a token for a
  service user in that role.
* `.env`: `SPLUNK_URL` (`https://splunk.example:8089`), `SPLUNK_TOKEN`. For a private CA set
  `ca_bundle`; TLS verification cannot be switched off.

### IBM QRadar

* *Admin → Authorized Services*: create a token for a user role that can search events and view
  offenses, with no admin rights.
* `.env`: `QRADAR_URL` (`https://qradar.example`), `QRADAR_TOKEN`.
* Two modes per connector:
  ```yaml
  soc:
    adapter: qradar
    product: IBM QRadar offenses
    settings:
      base_url: ${QRADAR_URL}
      token: ${QRADAR_TOKEN}
      mode: offenses                    # snapshot: a closed offense drops out and is resolved
      offense_filter: status="OPEN"
      field_map: {finding_id: id, title: description, severity: magnitude, asset_id: offense_source,
                  status: status, first_seen: start_time, last_seen: last_updated_time}
      finding_type: incident
  edr:
    adapter: qradar
    product: EDR detections via QRadar
    settings:
      base_url: ${QRADAR_URL}
      token: ${QRADAR_TOKEN}
      aql: |                            # {since_ms} = cursor in epoch ms -> incremental
        SELECT starttime, QIDNAME(qid) AS detection, severity, sourceip, username
        FROM events WHERE starttime > {since_ms} AND severity >= 7 LAST {lookback_days} DAYS
      field_map: {title: detection, severity: severity, asset_id: sourceip, user_id: username, first_seen: starttime}
  ```
* The adapter polls the search until it completes (`poll_seconds`, `timeout_seconds`) and reads up to
  `max_rows` results. Keep AQL windows short: Ariel searches compete with your analysts' searches.

### Elastic Security, OpenSearch and Wazuh

* Elastic: create an API key with `read` on the alert and log indices, and use its *encoded* value.
  OpenSearch and Wazuh: a user with read on the indices (`username` / `password`).
* `.env`: `ELASTIC_URL` (`https://es.example:9200`), `ELASTIC_API_KEY` (or a password variable).
* ES|QL (Elasticsearch 8.14 or later) or Query DSL:
  ```yaml
  soc:
    adapter: elastic
    product: Elastic Security alerts
    settings:
      base_url: ${ELASTIC_URL}
      api_key: ${ELASTIC_API_KEY}
      index: ".alerts-security.alerts-*"
      dsl: {bool: {filter: [{range: {"@timestamp": {gte: "now-{lookback_days}d"}}},
                            {terms: {kibana.alert.workflow_status: [open, acknowledged]}}]}}
      field_map: {finding_id: kibana.alert.uuid, title: kibana.alert.rule.name, severity: kibana.alert.severity,
                  asset_id: host.name, user_id: user.name, status: kibana.alert.workflow_status, first_seen: "@timestamp"}
      status_map: {acknowledged: in_progress}
  ```
* Nested documents are flattened, so the field map uses dotted names (`kibana.alert.rule.name`). A list of
  values keeps its first item under the name and the whole list under `name[]`.
* Wazuh: `index: wazuh-alerts-*`, a DSL range on `rule.level` (for example 10 or higher), and the field map
  `title: rule.description`, `severity: rule.level`, `asset_id: agent.name`.

### Sumo Logic

* Create an access ID and key for a service user whose role can run searches on the relevant data.
* `.env`: `SUMO_API_URL` (`https://api.<deployment>.sumologic.com`, for example `api.eu.sumologic.com`),
  `SUMO_ACCESS_ID`, `SUMO_ACCESS_KEY`.
* `results: messages` reads raw messages incrementally (by `_messagetime`). `results: records` reads
  the rows of an aggregate query (`count by ...`) as a snapshot.
* Field names depend on your parsing (field extraction rules or auto-parsing): check them in a Sumo
  search before writing the field map.

### Google Security Operations (preview)

* Create a service account with permission to run UDM searches on the SecOps instance, and download its
  JSON key. Store the key content in `.env` as `GOOGLE_SECOPS_SA_JSON`; it is never written to YAML.
* `.env`: `SECOPS_API_URL` (your tenant's regional Chronicle API endpoint), `SECOPS_PROJECT`,
  `SECOPS_LOCATION`, `SECOPS_INSTANCE` (the SecOps customer ID).
* Queries use UDM search syntax (`metadata.event_type = "PROCESS_LAUNCH"`). The response uses camelCase
  field names, so the field map does too (`securityResult.severity`, `principal.hostname`). The API accepts
  at most 90 days per search.

### MERIDIAN

MERIDIAN pushes its cases and SOC KPIs to `POST /api/ingest/soc?org=<key>` with an HMAC signature and
timestamp. Configure `soc: {adapter: webhook, product: MERIDIAN}` and the secret
`LODESTAR_WEBHOOK_SECRET_<ORG>`. The full contract is MERIDIAN's integration document (INT-00).

### Any other SIEM

Use the lightest of three generic paths:

1. **`http_json`**: when the SIEM has a REST API that returns JSON (alerts, incidents or a saved search).
   It supports bearer, header, basic and OAuth2 client-credentials authentication, `{since}` / `{since_epoch}`
   / `{since_ms}` placeholders, link or next-field pagination and a dotted `records` path.
   ```yaml
   soc:
     adapter: http_json
     product: Exabeam alerts
     settings:
       url: https://siem.example/api/v1/alerts
       params: {status: open, since: "{since}"}
       auth: {type: bearer, token: "${SIEM_API_TOKEN}"}
       records: data
       paginate: {type: next_field, path: links.next}
       field_map: {finding_id: id, title: name, severity: risk, asset_id: entity.host, first_seen: created}
   ```
2. **Signed webhook**: a SOAR playbook or the SIEM's own action pushes findings to
   `/api/ingest/<domain>` with an HMAC signature (`docs/AGENT_SETUP.md` §3.6).
3. **File drop**: a scheduled search exported as CSV or JSON into `data/drop/<domain>`.

## Mapping, sync and health

* **Field map.** Every SIEM adapter uses the same mapping engine as file drop: `field_map`,
  `severity_map`, `status_map`, `finding_type` and `evidence_fields`. Numeric severities (QRadar
  magnitude 1-10, Wazuh level, risk 0-100) are mapped automatically.
* **Sync mode.** A query with a time placeholder is **incremental**: LODESTAR keeps a cursor per source,
  and an item closes only when the SIEM returns it closed. A query without one must return the **complete
  current set** (snapshot): an item missing from two consecutive runs is resolved. Open-offense and
  open-alert lists are snapshots.
* **Health.** An optional health query (`health_query`, `health_search`, `health_aql`, `health_esql`,
  Sumo `health_query`) returns one row. Its `coverage_pct` and numeric columns become the control's
  KPIs, which feed KRIs such as MTTD and silent log sources.

## Threat hunting in the SIEM

The ThreatHuntAgent takes recent indicators from TAXII, MISP, CSAF, ISAC e-mails and bug-bounty reports
and asks the SIEM once per run whether any host or user touched them. Every hit becomes a SOC finding,
and the advisory is marked *sighted*.

| SIEM | What is searched |
|---|---|
| Sentinel | Defender network, file and e-mail tables, DNS events and CEF |
| Splunk | CIM fields (`dest_ip`, `src_ip`, `dest`, `query`, `url`, `file_hash`) |
| QRadar | `sourceip` / `destinationip`; domains and hashes through the custom properties you name (`domain_property`, `hash_property`) |
| Elastic / OpenSearch / Wazuh | ECS: `source.ip`, `destination.ip`, `dns.question.name`, `url.domain`, `destination.domain`, `file.hash.*`, `process.hash.*` |

```yaml
threat_hunt:
  enabled: true
  provider: qradar                    # sentinel | splunk | qradar | elastic
  lookback_hours: 24
  settings: {base_url: "${QRADAR_URL}", token: "${QRADAR_TOKEN}", domain_property: URL}
```

## Limits to plan for

| SIEM | Limit | How LODESTAR handles it |
|---|---|---|
| QRadar | Ariel searches share capacity with analysts | Short windows, one search per domain per run, `timeout_seconds` |
| Elastic / OpenSearch | 10,000 hits per Query DSL page | `max_rows` (default 5,000); use ES\|QL `STATS` to aggregate |
| Sumo Logic | 200 concurrent search jobs; 10,000 results per page; 100,000 messages per search | Jobs deleted after reading; `max_rows` |
| Google SecOps | 90 days per UDM search; result limit per call | Window capped at 90 days; warning when more data is available |
| All | Query cost and API throttling | Retries with back-off on 429/5xx, honouring `Retry-After` |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `401` / `403` | Token, key or role missing a permission | Check the least-privilege column above; QRadar tokens need a user role, not only a security profile |
| Search times out (QRadar, Sumo) | Window too wide or the SIEM is busy | Shorten `lookback_days`, add filters, raise `timeout_seconds` |
| Elastic `Unknown column` (ES\|QL) | Field not mapped in any index the query covers | Narrow `FROM`, or use Query DSL, which tolerates unmapped fields |
| Every item shows medium severity | Field map does not point at the severity column, or the values are unknown words | Fix `field_map.severity`, add a `severity_map` |
| Items never close | Incremental query that does not return closed items | Return status too, or switch to a snapshot query of open items |
| TLS errors | Private CA | Set `ca_bundle` to the CA file; verification cannot be disabled |

Contract tests: `pytest tests/test_siem_platforms.py tests/test_contracts.py`.
