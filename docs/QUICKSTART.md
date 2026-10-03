# Quick start: from zero to a working Today list in one to two days

This plan is for a security team of any size, in any industry, that wants LODESTAR running on its
own data quickly. It works because of three choices:

1. **SIEM-first.** If your SIEM (Microsoft Sentinel, Splunk, IBM QRadar, Elastic / OpenSearch, Sumo Logic or
   Google SecOps) already receives your EDR, identity, e-mail, cloud and SOC alerts, one read-only query per
   domain replaces most product integrations ([SIEM_INTEGRATION.md](SIEM_INTEGRATION.md)). The queries
   are ready-made in [`config/templates/catalog.yaml`](../config/templates/catalog.yaml).
2. **Generated configuration.** `lodestar init` writes a working live config, a `.env` with
   generated secrets, the CMDB and identity templates, and the drop folders.
3. **One readiness screen.** `lodestar doctor` lists everything that is missing and how to fix
   each item. When it shows no failures, the next run produces real priorities.

What one to two days gets you: a Today / This week list across EDR, vulnerabilities, identity,
SOC and e-mail, scored with KEV and EPSS and tied to your crown jewels. You also get advisories
from your CERT, ISAC and vendors matched to your estate, the Decision desk, a weekly report, and
KRIs that say where each number comes from. The remaining domains come later, phase by phase
(see [DEPLOYMENT_PHASES.md](DEPLOYMENT_PHASES.md)).

---

## Before day 1: pre-work to send out a week ahead

Most delays come from approvals, not technology. Ask for these items in advance:

| Item | Who | Why |
|---|---|---|
| A Linux VM (2 vCPU, 4 GB RAM, 40 GB disk) with Docker, or a Windows server with Python 3.12 | Infrastructure | Runs the API and the scheduler |
| **Sentinel:** an Entra app registration with a client secret, the **Log Analytics Reader** role on the Sentinel workspace, and Graph application permissions `SecurityAlert.Read.All`, `IdentityRiskyUser.Read.All` and `AuditLog.Read.All` with admin consent | Entra / cloud admin | Read-only SIEM queries, Defender alerts and identity risk |
| **Splunk:** a role with `search` on the security indexes (and `notable` for ES), an authentication token, and the Splunk CA certificate if it is private | Splunk admin | Read-only searches on the management port (8089) |
| Vulnerability scanner API key (Tenable: a Basic user with Can View), or a scheduled CSV export (Qualys, Rapid7) | VM team | Vulnerabilities, unless they are already in the SIEM |
| CMDB / crown-jewel export: hostname or FQDN, business service, owner, criticality 1-5, internet exposure | IT asset owner | Without it, every finding scores as "unknown asset" |
| CERT / ISAC feed details (TAXII URL and token, MISP key) and an advisory mailbox or `.eml` folder | Threat intel / CISO office | External warnings matched to your estate |
| Outbound HTTPS from the VM to `login.microsoftonline.com`, `api.loganalytics.io`, `graph.microsoft.com`, your Splunk host, `cloud.tenable.com`, `www.cisa.gov`, `api.first.org`, plus your feed hosts, with the proxy and CA details | Network | Every connector is an outbound, read-only HTTPS call |
| A DNS name and TLS certificate for the dashboard; optionally an SSO app registration with redirect URI `https://<name>/auth/callback` | Network / IAM | Secure access and single sign-on |

---

## Day 1, morning: install, initialise, CMDB (about 3 hours)

```powershell
git clone https://github.com/manabouprj/Lodestar.git
cd Lodestar
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m lodestar demo                         # optional: see what "good" looks like with fictional data
```

Linux: `python3.12 -m venv .venv && . .venv/bin/activate`. Docker: see [PRODUCTION.md](PRODUCTION.md).

**Initialise for your organisation.** The command asks for the organisation, industry, SIEM,
domains and e-mail domain, or takes them as flags:

```powershell
python -m lodestar init --org "Acme Bank" --vertical banking --siem sentinel --primary-domain acme.com
```

`init` does the following:

* Writes `config/lodestar.yaml`, keeping a dated backup of the previous file, with `mode: live` and `deployment_phase: 1`.
* Picks a template for each domain in this order: your SIEM, then a native API, then file drop or webhook.
* Appends API keys and the webhook, session and metrics secrets to `.env`, plus blank lines for the credentials your connectors need. Existing values are never overwritten.
* Creates `config/assets.csv`, `config/identities.csv` and the drop folders.

Industries: `aviation`, `banking`, `fintech`, `retail`, `energy`, `power_utilities`, `telecom`,
`logistics_ports`. Each industry profile sets its own weights, SLAs, KRIs, frameworks and mandatory
controls.

**Fill in `.env`** with the credentials from the pre-work, such as `AZ_TENANT_ID`, `AZ_CLIENT_ID`,
`AZ_CLIENT_SECRET` and `SENTINEL_WORKSPACE_ID` (or `SPLUNK_URL` and `SPLUNK_TOKEN`), plus
`TENABLE_*` and the feeds. If you have no source for a domain yet, set `enabled: false` on that
connector.

**Load the CMDB** into `config/assets.csv`. The columns are in
[`config/assets.example.csv`](../config/assets.example.csv). These fields matter most:

| Column | Tip |
|---|---|
| `asset_id` | Your CMDB key |
| `criticality` | 5 = crown jewel. Mark at least the top 20 systems before anything else |
| `exposure` | `internet`, `partner` or `internal` |
| `aliases` | Every name tools use: FQDN, short name, URL, `*.wildcard`. Separate with `;` |
| `ips`, `external_ids` | Optional. They help match EDR device ids, scanner UUIDs and cloud resource ids |

Optionally, export people to `config/identities.csv` (UPN, mail, `DOMAIN\sam`, Entra object id,
`privileged`), so that "jdoe", "CORP\jdoe" and "jdoe@acme.com" count as one person.

```powershell
python -m lodestar doctor            # fix every FAIL; add --online to test network paths through the proxy
```

## Day 1, afternoon: one connector at a time, then the first run (about 4 hours)

For each domain, run `test-connector`. Nothing is stored. It shows what was collected, how many
findings matched the CMDB, and any errors.

```powershell
python -m lodestar test-connector edr --show 10
python -m lodestar test-connector identity
python -m lodestar test-connector soc
python -m lodestar test-connector email
python -m lodestar test-connector vmdr
python -m lodestar test-connector threat_intel
```

| What you see | What to do |
|---|---|
| `FAILED - 401 / 403` | Wrong secret, or the role or permission has not been granted or consented yet |
| `Log Analytics error: Failed to resolve table` | That table is not in your workspace. Use the domain's native or file-drop template, or adjust the KQL |
| Findings > 0 but many "unmatched" assets | Add the names shown to `aliases` in the CMDB |
| Severity always `medium` | Add a `severity_map` for the product's values |
| Counts differ from the console | Check the query's time window (`lookback_days`) and its filters |

When every domain collects, grade them all at once with the ingestion sanity test. It checks volume,
schema drift, field mapping, CMDB match and freshness, and stores nothing:

```powershell
python -m lodestar check-ingestion          # PASS / WARN / FAIL per source; exit code 1 on FAIL
```

Then run the full pipeline and open the dashboard:

```powershell
python -m lodestar run               # every organisation; prints posture, Today count, KRIs measured and failed sources
python -m lodestar kpis              # where each KRI comes from, and how to measure the missing ones
python -m lodestar serve             # http://127.0.0.1:8080 - sign in with the ciso key printed by init
```

**Value check at the end of day 1:** the Today list has items you agree with, each with a "why".
Crown-jewel assets are named. Data trust is medium or high. The weekly report reads correctly
(`python -m lodestar report --period weekly`).

## Day 2: switch on the rest of phase 1, then put it into service

| Task | How | Time |
|---|---|---|
| Hunt intel indicators in the SIEM | Set `threat_hunt.enabled: true`, already filled by `init` when you chose a SIEM | 15 min |
| Fill in the KRIs no tool reports | `lodestar kpis`, then add `kpis_manual` entries such as phishing click rate, with `as_of` | 30 min |
| Decision owners | Map roles to the people who decide (ciso, analyst, exec). See [HUMAN_IN_THE_LOOP.md](HUMAN_IN_THE_LOOP.md) | 30 min |
| Single sign-on | `security.oidc` with group to role mapping. See [PRODUCTION.md](PRODUCTION.md#single-sign-on) | 1 h |
| Slack or Teams | [CHATOPS.md](CHATOPS.md): daily brief, urgent alerts, decisions in chat | 1 h |
| Schedule, back up, monitor | `docker compose up -d` (API and scheduler, which pulls each source on its own cadence); `ops.backup_dir`; scrape `/metrics` | 1 h |
| Ingestion alerts | `ingestion.alerts` sends failing, stale or volume-drop sources to Slack, Teams or an on-call webhook. Set `expect.max_silence_hours` on always-busy sources. See [INGESTION_OPERATIONS.md](INGESTION_OPERATIONS.md) | 30 min |
| AI assistants (optional) | Point Claude, Copilot or Foundry at `https://<host>/mcp/` with a dedicated analyst key. See [MCP.md](MCP.md) | 15 min |
| ITSM | Leave `itsm.dry_run: true` until the change board approves the ticket format | - |
| Go-live gate | `lodestar doctor --online` shows no failures; `/readyz` returns 200 | 15 min |

After go-live, add the phase 2 domains (firewall, WAF, proxy, ZTNA, PAM, cloud, fraud, bug bounty)
with the same loop of `.env`, the catalogue template, `test-connector` and `run`. Then raise
`deployment_phase`.

## Several organisations (group companies, MSSP, sector regulator)

```powershell
python -m lodestar init --tenant --org "Acme Insurance" --vertical fintech --siem splunk
```

This writes `config/tenants/acme-insurance.yaml`. Every tenant file is merged over
`config/lodestar.yaml` and declares its own connectors. The organisations are kept apart as follows:

* API keys: `analyst@acme-insurance:<key>`.
* SSO groups: `org_map`.
* Slack channels: `chatops.slack.channel_orgs`.
* Webhooks: `?org=acme-insurance`, signed with `LODESTAR_WEBHOOK_SECRET_ACME_INSURANCE`. This
  secret is required when there are several organisations.

## What takes longer than two days

Being clear about this up front saves surprises later:

* **CMDB quality.** If crown jewels are not marked, prioritisation is generic. It is worth the effort.
* **Products that are not in the SIEM and have no API on the shortlist**, such as on-premises PAM or
  OT platforms. Use a scheduled export (file drop) and expect a few days of back-and-forth on the
  format.
* **Validating against your tenant.** Adapters and query templates follow vendor documentation and
  are tested against recorded responses, not against your environment. The first week should
  include comparing counts with each console.
* **Approvals.** App consent, firewall changes and the SSO app. This is why the pre-work list exists.
