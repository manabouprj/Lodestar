# Ingestion operations

This page covers how often LODESTAR pulls each source, how to sanity-test a source, and how every
source is validated continuously so a broken pipe is caught and alerted. It is the operational side of
[SIEM_INTEGRATION.md](SIEM_INTEGRATION.md) and [CONNECTOR_GUIDE.md](CONNECTOR_GUIDE.md).

```
            lodestar schedule  (wakes every 15 min)
                     |
     for each source: due?  (interval_minutes, or the domain cadence)
        |                  \
       yes                  no -> skipped: last good health (aged) + findings carried forward
        |
     fetch (read-only) --> map (field_map) --> entity resolution
        |
     IngestionMonitorAgent  (every run, every source)
        |   checks: fetch, volume, schema drift, mapping, CMDB match, freshness, timestamps, telemetry
        |   history: consecutive failures, last success, volume baseline, last non-empty pull
        v
     state: healthy | retrying | failing | stale | volume_drop | volume_spike | degraded | awaiting_data
        |
        +--> data_quality.ingestion, dashboard "Ingestion health", /api/ingestion, MCP get_ingestion_health
        +--> COVERAGE_GAP finding (failing, stale, volume_drop) that resolves itself on recovery
        +--> Slack / Teams / webhook alert on entry, every 24 h while it lasts, and on recovery
        +--> Prometheus: lodestar_source_state, lodestar_source_consecutive_failures, ...
```

## 1. Frequency of ingestion

### Scheduler tick and source cadence

`lodestar schedule` (the `scheduler` container in docker-compose) wakes every **15 minutes**
(`--tick-minutes`). On each tick it runs the pipeline for every organisation, but a source is only
fetched when its own cadence is due. Other sources contribute their last good health and their findings
are carried forward unchanged, so the dashboard stays complete between pulls. Ticks are aligned to the
clock, not "15 minutes after the last run finished", and a source is due up to 10% (at most 5 minutes)
early, so scheduling jitter never skips a whole cycle.

| Cadence | Domains | Why |
|---|---|---|
| **15 min** | `soc`, `edr`, `fraud` | Alerts, detections and fraud signals: minutes matter, and the decision desk escalates on them |
| **30 min** | `identity`, `email`, `waf` | Risky sign-ins, phishing clicks and attack traffic change quickly |
| **60 min** | `threat_intel`, `bug_bounty`, `web_proxy`, `firewall`, `ztna`, `dlp`, `ai_security`, `ot` | Intel and network telemetry, hourly is enough to correlate |
| **4 h** | `cloud`, `pam` | Posture (CSPM) and vaulting coverage change with deployments |
| **6 h** | `vmdr`, `brand` | Scanners refresh results a few times a day, so pulling more often only burns API quota |
| **12 h** | `backup` | Backup jobs and restore tests run daily |
| **24 h** | `sast`, `dast` | Code and application scans run per build or nightly |

### Overriding the cadence

```yaml
connectors:
  edr:
    adapter: sentinel
    interval_minutes: 5          # every 5 minutes (the scheduler tick must be <= 5: --tick-minutes 5)
  vmdr:
    sources:
      - adapter: tenable_vm
        interval_minutes: 720    # per source
      - adapter: file_drop
        interval_minutes: 0      # 0 = every scheduler tick
```

| Setting | Where | Effect |
|---|---|---|
| `interval_minutes: N` | connector or source | Minimum minutes between fetches. It applies to **every** run, manual or scheduled. `lodestar run --force` ignores it |
| *(not set)* | | The domain cadence above applies to **scheduled** runs. A manual `lodestar run` or `POST /api/run` fetches the source |
| `ingestion.default_cadence: false` | `lodestar.yaml` | Turn the domain cadences off: every scheduled tick fetches every source without `interval_minutes` |
| `--tick-minutes N` | `lodestar schedule` | How often the scheduler wakes (minimum 5). It is a floor on the effective cadence |

Choosing a cadence comes down to three questions:

* **API quotas:** Microsoft Graph, Sentinel (Log Analytics), Splunk Cloud and most SaaS tools throttle. A
  15-minute SIEM query per domain is well inside typical limits. Avoid going lower than 5 minutes.
* **Lookback overlap:** incremental sources keep a cursor, so a missed run is caught up on the next one.
  Snapshot sources (scanners, CSPM, exports) must return the full current set every pull.
* **Cost:** for a SIEM-first deployment each pull is one saved query. Use the SIEM's own scheduled
  searches or summary indexes if a query is expensive.

`lodestar run` prints the sources it skipped ("not due yet ... use --force"). `/metrics` exports
`lodestar_source_cadence_minutes` per source.

## 2. Ingestion sanity test

```powershell
python -m lodestar check-ingestion                    # every enabled source
python -m lodestar check-ingestion --domain edr       # one domain
python -m lodestar check-ingestion --full             # ignore sync cursors, read the whole lookback window
python -m lodestar check-ingestion --json > check.json
```

It fetches every enabled source **now** (cadence ignored), maps and entity-resolves the rows exactly like
a real run, grades each source and **stores nothing** (no cursors, findings or state). The exit code is
1 when any source FAILs. Use it after onboarding a source, after a credential rotation, after a vendor
upgrade, or as a CI / change-window gate. `lodestar test-connector <domain>` remains the quick look at what
one domain collects. `check-ingestion` is the graded test across all sources.

| Check | PASS | WARN | FAIL |
|---|---|---|---|
| `fetch` | Reached and authenticated, N items | Connected but no data (empty folder, no webhook yet) | Exception: DNS, TLS, 401/403, timeout, bad query |
| `volume` | Within `min_items`..`max_items` | More than `max_items` (filter too broad) | Fewer than `min_items` |
| `schema` | Every `field_map` column present | A mapped column is absent from **every** row (the vendor renamed a field) | |
| `mapping` | Titles and severities mapped | More than `max_unmapped_pct`% rows untitled, unknown severity values, rejected payloads | |
| `entities` | At least `asset_match_pct`% of asset-bearing items match the CMDB | Below that | |
| `timestamps` | | Items dated in the future (time zone, or epoch seconds vs milliseconds) | |
| `freshness` | Source data within `max_age_hours` | Source reports older data (sensor or export job behind) | |
| `telemetry` | | No coverage / health from this source | |

Example output:

```
Ingestion sanity test - Acme Bank [mode=live]

[PASS] edr/sentinel                 Microsoft Defender for Endpoint  412 item(s), incremental, every 15 min
    ok   fetch      412 item(s), incremental sync
    ok   volume     412 item(s) within bounds
    ok   schema     every mapped column present
    ok   mapping    titles and severities mapped
    ok   entities   96.4% of 412 asset-bearing items match the CMDB (expected >= 50%)
    ok   freshness  source data 0.0h old

[WARN] firewall/splunk              Palo Alto Networks  1880 item(s), incremental, every 60 min
    WARN schema     schema drift: mapped column(s) missing from all 1880 rows: dest_host (asset_id)

[FAIL] vmdr/tenable_vm              Tenable Vulnerability Management  0 item(s), snapshot, every 360 min
   FAIL  fetch      fetch failed: HTTPStatusError: Client error '401 Unauthorized' ...

RESULT: FAIL - 1 pass, 1 warn, 1 fail
```

### Expectations (`expect`)

Defaults suit most sources. Set them deployment-wide (`ingestion.expect`), per connector or per source:

```yaml
ingestion:
  expect: {failing_after: 2, asset_match_pct: 50, max_unmapped_pct: 20}
connectors:
  soc:
    adapter: sentinel
    expect:
      min_items: 1              # an always-busy SOC source returning nothing is a failure
      max_silence_hours: 6      # fetches succeed but no alerts for 6 h -> stale (log forwarding broke)
  vmdr:
    adapter: tenable_vm
    expect: {min_items: 500, max_items: 200000, volume_drop_pct: 60}
```

| Key | Default | Meaning |
|---|---|---|
| `min_items` | 0 (off) | A successful fetch with fewer items FAILs the sanity test and marks the source `degraded` |
| `max_items` | off | More items: WARN (runaway query) |
| `max_age_hours` | max(24, 3 x cadence) | No successful fetch, or the source's own data older than this: `stale` |
| `max_silence_hours` | off | Successful fetches with no items for this long: `stale`. Set it for always-busy sources (SOC, EDR, proxy, firewall) |
| `asset_match_pct` | 50 | Minimum CMDB match for asset-bearing items |
| `max_unmapped_pct` | 20 | Maximum share of rows that fall back to "Untitled finding" |
| `failing_after` | 2 | Consecutive failed fetches before `failing` (alert and finding) |
| `volume_drop_pct` | 80 | Snapshot sources: a pull this much below the median of recent pulls is a `volume_drop` |
| `volume_spike_x` | 5 | Snapshot sources: a pull this many times the median is a `volume_spike` |
| `baseline_runs` | 14 | Recent successful pulls in the volume baseline. At least 5 pulls are needed, and a median of at least 10 items |

`lodestar validate` rejects unknown `expect` keys.

## 3. Continuous validation when ingestion fails

The **IngestionMonitorAgent** runs in every pipeline run, after the connectors and data quality and
before the lifecycle agent. It applies the same checks to the fetch that just happened, then adds each
source's history (`connector_state` and `source_runs` in the store).

| State | When | Finding | Alert |
|---|---|---|---|
| `healthy` | Fetched (or not due yet) and every check passed | | Recovery message if it had alerted |
| `retrying` | Last fetch failed, fewer than `failing_after` times in a row | | |
| `failing` | `failing_after` consecutive failed fetches | **Yes**: HIGH if the domain is mandatory for the industry profile, otherwise MEDIUM | **Yes** |
| `stale` | No successful fetch within `max_age_hours`, or no items for `max_silence_hours` | **Yes** | **Yes** |
| `stale` | The source's own data is older than `max_age_hours` | ControlAssurance raises `ctl-<domain>-health` | **Yes** |
| `volume_drop` | Snapshot pull far below its recent median (export truncated, scope or permission lost) | **Yes** (MEDIUM) | **Yes** |
| `volume_spike` | Snapshot pull far above its median (filter removed, duplication) | | |
| `degraded` | Fetched, but schema drift, unmapped rows, unknown severities or volume bounds | | |
| `awaiting_data` | Configured, nothing received yet | | |

What happens to the data while a source is broken:

* **Findings are never closed because a tool was down.** The lifecycle agent carries a failed or silent
  source's findings forward unchanged.
* **No false "control dead" on a blip.** A failed or skipped source contributes its **last good health**,
  aged by the time since it was collected. ControlAssurance therefore marks the control stale only when
  the data really is old (more than 48 h), not on the first timeout.
* **Broken pipes are prioritised like any other risk.** The `ing-<domain>-<adapter>` COVERAGE_GAP finding
  (source `lodestar.ingestion_monitor`) goes through scoring, owner routing and the work queues like any
  other finding. It resolves itself ("condition cleared") on the first run in which the source is healthy
  again.
* **The control's score reflects it.** A health issue `ingestion <source> <state>: <why>` is added to the
  domain's control, so effectiveness drops.

### Alerts

The scheduler sends ingestion alerts to the chat channels that are enabled (Slack, Teams) and optionally
to a generic JSON webhook, such as an on-call tool's events endpoint or a Teams or Power Automate flow:

```yaml
ingestion:
  alerts:
    enabled: true
    states: [failing, stale, volume_drop]     # default
    repeat_hours: 24                          # reminder while it stays broken
    slack_channel: "#sec-data-pipeline"       # optional; default = chatops.slack.channel
    webhook_url: ${LODESTAR_INGESTION_ALERT_WEBHOOK_URL}
```

Alerts are sent once when a source enters an alerting state, again every `repeat_hours`, and once when it
recovers. The alert state is stored per source, so an alert that could not be delivered is retried on
the next tick. The webhook body is
`{"source": "lodestar", "org", "title", "events": [{"source_key", "state", "detail", "domain", "recovered"}]}`.

### Where to see it

| Surface | What |
|---|---|
| Dashboard, "Ingestion health" table under Control assurance | Every source: state, cadence, items, last success, why |
| `GET /api/ingestion?org=<key>` (analyst) | Same as JSON, including the checks and transitions |
| `lodestar run`, scheduler log | Sources skipped, unhealthy sources, state transitions |
| `lodestar doctor` | FAIL for failing or stale sources (live mode), WARN for the others |
| MCP `get_ingestion_health`, `check_ingestion` | For AI assistants (see [MCP.md](MCP.md)) |
| Prometheus `/metrics` | Below |

### Prometheus alert rules

```yaml
groups:
- name: lodestar-ingestion
  rules:
  - alert: LodestarSourceFailing
    expr: lodestar_source_state{state=~"failing|stale"} == 1
    for: 10m
    labels: {severity: page}
    annotations: {summary: "LODESTAR source {{ $labels.source }} ({{ $labels.org }}) is {{ $labels.state }}"}
  - alert: LodestarSourceNoSuccess
    expr: time() - lodestar_connector_last_success_timestamp_seconds > 6 * 3600
    labels: {severity: ticket}
  - alert: LodestarSchedulerStopped
    expr: time() - lodestar_last_run_timestamp_seconds > 3600
    labels: {severity: page}
```

| Metric | Meaning |
|---|---|
| `lodestar_source_state{org,source,state}` | 1 for the current state |
| `lodestar_source_consecutive_failures{org,source}` | Failed fetches in a row |
| `lodestar_source_cadence_minutes{org,source}` | Cadence under the scheduler |
| `lodestar_connector_up{org,source}` | 1 if the last attempt succeeded |
| `lodestar_connector_last_success_timestamp_seconds{org,source}` | Time of the last successful fetch |
| `lodestar_connector_items{org,source}` | Items in the last successful fetch |
| `lodestar_last_run_timestamp_seconds{org}` | Detects a stopped scheduler (the monitor runs inside it) |

### Runbook: a source is failing

1. `lodestar check-ingestion --domain <domain>` shows which check fails and the vendor error.
2. **401/403:** the secret expired or was rotated. Update `.env` or the secret store, then restart the
   scheduler. **DNS, TLS or timeout:** check the proxy and egress (`lodestar doctor --online`). **Query
   error:** the SIEM table or index was renamed.
3. **Schema drift:** compare the row keys with `field_map` (`test-connector --show 3`). Update the map.
4. **Volume drop:** check the export job or saved search scope, and the service account's permissions
   (scope reduced).
5. Run `lodestar run --force --org <key>` once the cause is fixed. The source returns to `healthy`, the
   finding resolves and a recovery alert is sent.

## Store retention

`source_runs` (one row per fetch, used for baselines and silence detection) is pruned nightly after
`ops.retention.source_runs_days` (default 30).
