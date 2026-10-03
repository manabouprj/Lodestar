# Changelog

All notable changes to LODESTAR. Versions follow [semantic versioning](https://semver.org/); each release is a
tag on `main`.

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
