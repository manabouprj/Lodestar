# External reports and intelligence

Security teams get the most consequential warnings from **outside** their own tools:

* researchers reporting flaws through the **bug bounty / VDP** programme (HackerOne),
* **national CERTs, sector ISACs and regulators** sending advisories by TAXII feed, MISP or e-mail,
* **vendor PSIRTs** and **CISA ICS advisories** (CSAF) about the OT and IT products in the estate,
* **MSSP / partner alerts** arriving in a shared mailbox.

These usually arrive as e-mails or portal notifications that someone has to read, match by hand
to the asset inventory, and then chase. LODESTAR captures them automatically and keeps only what
matters to *this* organisation. It ranks that next to the internal signals and raises the human
decisions that follow, including mandatory incident notification for critical infrastructure.

## Sources and adapters

| Source | Adapter | How it connects | Notes |
|---|---|---|---|
| HackerOne programme | `hackerone` | API v1, read-only token (pull) | Title, severity, CWE, scope asset, state, SLA. The proof-of-concept write-up is **not** copied |
| HackerOne webhooks | `/api/ingest/hackerone` + `webhook` | Push, `X-H1-Signature` HMAC-SHA256 | Real-time on report_created / triaged / severity_updated / bounty_awarded |
| VDP mailbox (security@) | `mailbox` (kind `bug_bounty`) | IMAP (TLS, read-only) or Microsoft Graph | For programmes outside HackerOne |
| National CERT / ISAC TAXII | `taxii` | TAXII 2.1, STIX 2.1 | Reports, indicators, vulnerabilities, `targets` → sectors, TLP markings |
| ISAC / community MISP | `misp` | REST `events/restSearch` | Tags `tlp:*`, sector galaxies, `to_ids` attributes |
| CISA ICS / vendor PSIRT | `csaf` | CSAF 2.0 JSON (URLs or folder) | Vendor/product tree → `vendor:` / `product:` asset tags; CVSS; remediation |
| Advisory / alert e-mail | `mailbox` (kind `advisory` / `alert`) | IMAP, Graph or `.eml` folder | CVE, CVSS, IOC (refanged), TLP, sector words, CSAF/STIX JSON attachments |

All threat-intel sources sit under one `threat_intel` connector with several `sources:`. A broken
or stale feed is reported without hiding the others (see `config/lodestar.yaml`). Air-gapped
sites can drop STIX bundles, CSAF files or `.eml` files into a folder.

## Relevance filtering: only what touches us

Every advisory or indicator is kept only if it matches at least one of:

| Match | Example | Effect |
|---|---|---|
| **CVE in our estate** | Advisory CVE also found by VMDR / OT / CNAPP / SAST | Joined into attack path LDS-015 when sector-targeted; the internal finding gains "exploitation against peers reported by …" and a higher exploitability |
| **Product in our inventory** | CSAF advisory for `product:nwa-controller-500`; 20 PLCs, HMIs and RTUs carry that tag | One finding per affected asset; feeds OT attack path LDS-009 |
| **Indicator in our telemetry** | ISAC domain `update-sync-cdn.example` seen by the proxy and EDR | Becomes a *sighting* (detection, high); attack path LDS-016; incident and notification decisions |
| **Our sector + high severity** | "Active exploitation against financial-services organisations" | Kept as sector-targeted context |

Everything else is counted and dropped. In the demo, 20 items were ingested and 2 to 4 kept per
organisation. The dashboard shows *ingested → relevant → sighted*.

Researcher reports are matched to assets through **aliases** (hostnames, FQDNs, URLs,
`*.wildcards`) held on each CMDB asset. A report on a host that isn't in the CMDB is flagged
**"not in CMDB (possible shadow IT)"**. That is often the most valuable thing a bug bounty finds.

## Attack paths and decisions

| Rule | Joins | Decision raised (deciders, deadline) |
|---|---|---|
| LDS-014 Researcher-reported flaw already being probed | Bug bounty high/critical + WAF/FW/SOC/EDR detection on the same asset | Emergency fix / virtual patch (AppSec lead, service owner, 8 h) |
| LDS-015 Sector-targeted vulnerability in our estate | CERT/ISAC advisory (sector-targeted) + VMDR/OT/cloud/app finding with the same CVE | Emergency patch window (CISO, Head of IT/OT Ops, 8 h) |
| LDS-016 Intel indicator sighted in our telemetry | TAXII/MISP/e-mail IOC + EDR/proxy/firewall/e-mail/SOC/OT detection | Confirm compromise and invoke IR (SOC lead, CISO, 2 h) |
| Critical infrastructure notification | LDS-016 in a profile marked `critical_infrastructure: true` | Mandatory incident notification to the authority in `incident_reporting` (CISO, Legal, executive sponsor; profile hours, e.g. 24 h) |
| Bug bounty programme | Triaged reports awaiting bounty / response-SLA breaches | Agree severity and bounty (programme owner, AppSec lead, 72 h) |

The agents never reply to researchers, award bounties, change report severity, contact a CERT or
regulator, or block indicators on security controls. Those are Decision-desk items.

Set `incident_reporting.authority` and `hours` in each industry profile to match your regulator.
The shipped values are placeholders to confirm with Legal.

## TLP handling

* TLP is read from STIX marking definitions, MISP `tlp:` tags, CSAF `distribution.tlp` and
  `TLP:` text in e-mail subjects or bodies, and is stored on the finding.
* **TLP:RED** titles never leave the dashboard. Chat, notifications and reports show
  "[TLP:RED item - open the dashboard]" instead.
* TLP:AMBER / AMBER+STRICT items are labelled wherever they appear. Keep chat channels private.
* The optional LLM narrative only ever receives aggregate counts, never advisory text.

## E-mail ingestion safety

* Use a dedicated mailbox. Graph access is `Mail.Read` restricted to that mailbox with an Exchange
  ApplicationAccessPolicy. IMAP opens the folder read-only.
* Only allow-listed senders are processed. DKIM/SPF failures are kept, tagged
  `unverified_sender` and capped at medium severity, so a spoofed "CERT advisory" cannot
  create an emergency.
* Links are never followed and HTML is stripped. Only small CSAF/STIX JSON attachments from
  verified senders are parsed.
* Parsing is deterministic (regular expressions, no LLM), so instructions embedded in an e-mail
  ("ignore previous instructions…") have no effect. This is covered by a test.
* Advisory publisher links (cisa.gov, nvd, mitre, .gov/.mil) are never treated as IOCs.

## KRIs added to every profile

| KRI | Appetite |
|---|---|
| Sector-targeted vulns open (CERT / ISAC advisories) | 0 |
| Researcher-reported high/critical flaws past SLA | 0 |

## Setup checklist

1. Add `aliases` (public hostnames, URLs, wildcards) and `vendor:` / `product:` tags to CMDB assets
   (`config/assets.example.csv` columns, or the CMDB export).
2. HackerOne: create an API token with read-only programme access → `H1_API_IDENTIFIER`,
   `H1_API_TOKEN`, `H1_PROGRAM`. Add a programme webhook to `https://<host>/api/ingest/hackerone`
   with secret `LODESTAR_H1_WEBHOOK_SECRET`.
3. TAXII / MISP: request read-only credentials from your CERT / ISAC.
4. CSAF: list advisory URLs or sync the provider directory into `data/drop/csaf`.
5. Mailbox: create `advisories@`, forward CERT/ISAC/PSIRT distribution lists to it, and fill in
   `senders` in config.
6. `python -m lodestar validate --phase 1` then check the "External reports & intelligence" panel.
