# Changelog

All notable changes to LODESTAR. Versions follow [semantic versioning](https://semver.org/); each release is a
tag on `main`.

## 2.3.0 - 2026-10-04

### Added

* **Licence: Apache License 2.0** (`LICENSE`, `NOTICE`). Until now the repository had no licence, which
  legally meant "all rights reserved": nobody else could use it, in production or otherwise. Apache-2.0
  permits use, modification and commercial or production deployment, with attribution and an explicit
  patent grant. The licence metadata is in `pyproject.toml` (SPDX `Apache-2.0`, licence files in the
  wheel) and on the container image (`org.opencontainers.image.licenses`). `LICENSE` and `NOTICE` are
  copied into the image, and the README has a License section.
* `.github/SECURITY.md`: private vulnerability reporting, response times, supported versions.
* `CONTRIBUTING.md`: contributions under Apache-2.0 with DCO sign-off, and the project's ground rules.
* `lodestar --version`.

## 2.2.3 - 2026-10-03

### Fixed

* **The CI `docker` job had failed on every run since v2.0.0** with exit code 125. The smoke test named its
  container `l`, and Docker requires container names of at least two characters, so `docker run` was
  rejected and the container was never started. The container is now `lodestar-ci`. It binds to
  127.0.0.1:18080, waits up to 60 s for `/healthz`, prints `docker ps` and the container logs when it
  fails, and always shows the last 50 log lines.

## 2.2.2 - 2026-10-03

### Fixed

* **`pip install -r requirements.txt` failed on Windows** with "uvloop does not support Windows". This
  had been the case since v2.0.0. The lock is generated on Linux, so pip-compile pinned uvloop (a Linux and
  macOS speed-up pulled in by `uvicorn[standard]`) without its platform marker. The pin now carries
  `sys_platform != "win32"`, and uvicorn uses asyncio on Windows. `make lock` now runs
  `scripts/lock.py`, which re-applies the marker on every regeneration. A regression test checks the lock,
  and a new **windows** CI job installs the lock and runs validate and the demo on `windows-latest`.

## 2.2.1 - 2026-10-03

### Fixed

* **Demo page (GitHub Pages) returned 404 while every deploy run was green.** The workflow now checks
  in its build job that Pages publishes from GitHub Actions, and fails with a clear error if Pages is off
  or set to "Deploy from a branch". A new **verify** job downloads the published URL after each deploy and
  fails unless it serves the dashboard. Re-run *demo-dashboard* after setting Settings → Pages → Source:
  GitHub Actions. Troubleshooting is in `docs/GITHUB_SETUP.md`.
* GitHub Actions moved to their Node 24 releases (checkout v7.0.1, setup-python v7.0.0, upload-artifact
  v7.0.1, configure-pages v6.0.0, upload-pages-artifact v5.0.0, deploy-pages v5.0.1), pinned by SHA. This
  removes the Node 20 deprecation warnings.
* The Pages workflow also runs when `requirements.txt` changes, and no longer cancels a deployment in
  progress.

## 2.2.0 - 2026-10-03

### Added

* **Ingestion cadence per domain.** `lodestar schedule` now wakes every 15 minutes (`--tick-minutes`), and
  each source is fetched on its own cadence. The defaults are 15 min for SOC, EDR and fraud; 30 min for
  identity, e-mail and WAF; hourly for network and intel; 4 h for cloud and PAM; 6 h for VMDR and brand;
  12 h for backup; and daily for SAST and DAST. `interval_minutes` overrides the cadence per connector or
  source.
* **Ingestion sanity test: `lodestar check-ingestion [--domain] [--json] [--full]`.** It fetches every source
  now and grades it PASS, WARN or FAIL. The checks are reachability and auth, volume bounds, schema drift,
  field mapping, CMDB match, freshness, timestamps and telemetry. Nothing is stored, and the exit code is 1
  on FAIL. Each source can carry an `expect:` block with its thresholds.
* **Continuous ingestion validation: IngestionMonitorAgent (phase 0).** It runs in every run and gives each
  source a state: healthy, retrying, failing, stale, volume_drop, volume_spike, degraded or awaiting_data.
  Failing, stale and volume-drop sources raise a COVERAGE_GAP finding that resolves itself on recovery,
  and add a health issue to the control.
* **Ingestion alerts.** Slack, Teams or a generic JSON webhook, sent on entering a state, every 24 h while it
  lasts, and on recovery (`ingestion.alerts`).
* **Ingestion visibility.** An "Ingestion health" table on the dashboard, `GET /api/ingestion`, ingestion
  state in `lodestar run`, `doctor` and the scheduler log, and Prometheus `lodestar_source_state`,
  `lodestar_source_consecutive_failures` and `lodestar_source_cadence_minutes`.
* **Schema-drift detection.** A `field_map` column missing from every row is reported (the vendor renamed
  a field).
* **LODESTAR MCP server.** A read-only Model Context Protocol endpoint at `/mcp/` on the API, plus
  `lodestar mcp` over stdio. It has twelve tools: overview, priorities, findings, attack paths, KRIs,
  decisions, controls, ingestion health and the live ingestion check. It uses the same API keys, OIDC
  bearer tokens, roles and organisation scoping as the REST API. TLP:RED items are redacted and tool calls
  are audit-logged. See `docs/MCP.md`.
* **`mcp` adapter.** It ingests from a vendor's MCP server by calling one named tool, and refuses tools
  annotated as not read-only.
* `docs/INGESTION_OPERATIONS.md` and `docs/MCP.md`.

### Changed

* A source that is skipped by its cadence or fails once contributes its last good health, aged by the
  time since collection, instead of coverage 0 and data age 999 h. A single timeout no longer raises a
  HIGH "control stale" finding, and a skipped mandatory domain no longer counts as "not integrated".
* Store schema v3: `connector_state` keeps consecutive failures, last good health and monitor state. A new
  `source_runs` table holds the fetch history and is pruned after 30 days. The migration is automatic.
* Connector state is stamped with the run's clock, so cadences line up with scheduler ticks.
* `--interval-hours` on `schedule` is still accepted, and sets the tick.
* New dependency: `mcp` (Model Context Protocol SDK).

### Fixed

* LODESTAR-generated findings raised after the lifecycle agent ran (control health `ctl-*`) were marked
  resolved by the same save that re-raised them, so they flipped between open and resolved on every
  other run.
* The `data/drop/<domain>` folders were never committed (the `.gitignore` negation could not re-include
  them), so a fresh clone reported "drop folder not found". They are now in the repository.

## 2.1.0 - 2026-10-03

### Added

* **Six SIEM platforms, SIEM-first.** New native adapters for **IBM QRadar** (AQL / Ariel search and the
  open-offense list), **Elastic Security, OpenSearch and the Wazuh indexer** (ES|QL or Query DSL),
  **Sumo Logic** (Search Job API) and **Google Security Operations** (Chronicle UDM search, preview), next to
  Microsoft Sentinel and Splunk.
* **`http_json` adapter** for any SIEM or tool with a REST/JSON read API (LogRhythm, Exabeam, Securonix,
  FortiSIEM, InsightIDR, ArcSight, Falcon Next-Gen SIEM ...): bearer, header, basic or OAuth2 authentication,
  `{since}` placeholders, link / next-field pagination.
* **Threat-intel hunting in QRadar and Elastic / OpenSearch**, as well as Sentinel and Splunk.
* `lodestar init --siem qradar | elastic | sumologic | google_secops` with ready-made templates for EDR,
  SOC and firewall (and a Splunk firewall template).
* **`docs/SIEM_INTEGRATION.md`**: supported platforms and support level, least privilege, setup per SIEM,
  mapping and sync modes, hunting, limits and troubleshooting. README "Supported SIEM platforms" table.
* Dependabot, CODEOWNERS and this changelog.

### Changed

* GitHub Actions pinned to commit SHAs, with `persist-credentials: false` and job timeouts; CI also runs on tags.
* Connector catalogue lists `http_json` and the SIEM adapters for every connector agent.
* `docs/GITHUB_SETUP.md` covers repositories whose `main` branch requires pull requests.

### Fixed

* The README claimed QRadar support that did not exist; it is now real and tested (PEER_REVIEW PR-41).

## 2.0.0 - 2026-10-01

Production-ready for other teams in any industry, live in one to two days: `init` and `doctor`, finding
lifecycle with history, asset and identity resolution, SIEM-first connectors (Sentinel, Splunk) and IOC
hunting, KRI provenance, OIDC single sign-on, org-scoped access, metrics, readiness checks and backups.
Earlier versions: see the tags and `docs/PEER_REVIEW.md`.
