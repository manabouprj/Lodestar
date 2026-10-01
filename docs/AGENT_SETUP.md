# Agent setup and integration

This guide takes LODESTAR from the demo to your real security tools, one agent at a time. Every
step is written for **Windows 11 + PowerShell**. Linux and Docker equivalents are given where
they differ.

```
Step 0  Install and run the demo                     (30 min)
Step 1  Point LODESTAR at your organisation           (15 min)
Step 2  Load the asset register (CMDB)                (1-2 h)
Step 3  Integrate connector agents, one at a time     (per product: 30 min - 1 day)
Step 4  Configure the core agents                     (decision RACI, scoring, ITSM, chat)
Step 5  Go live and schedule                          (Docker or Windows Task Scheduler)
Step 6  Operate and troubleshoot
```

> **The integration loop.** For each product: add credentials to `.env`, then add or adjust the
> connector block in `config/lodestar.yaml`, then run `python -m lodestar test-connector <domain>`.
> Fix anything it reports, then move on to the next product. `test-connector` runs a single agent
> and shows what it collected, how many findings matched your CMDB and any errors. Nothing is
> stored.

---

## Step 0 - Install and run the demo

```powershell
cd C:\Projects\lodestar
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
python -m lodestar demo                 # 8 fictional organisations, reports, dashboard
python -m lodestar serve                # http://127.0.0.1:8080
```

Docker: `docker compose build` then `docker compose run --rm api python -m lodestar demo`.

## Step 1 - Point LODESTAR at your organisation

1. `Copy-Item .env.example .env` and set the platform secrets:

   ```powershell
   # generate three API keys (exec, analyst, ciso) and a webhook secret - cryptographically random
   python -c "import secrets; [print(secrets.token_urlsafe(32)) for _ in range(4)]"
   ```

   ```ini
   LODESTAR_API_KEYS=ciso:<key1>,analyst:<key2>,exec:<key3>
   LODESTAR_WEBHOOK_SECRET=<key4>
   LODESTAR_PUBLIC_URL=https://lodestar.your-org.example
   ```

   `.env` is read automatically, both by `python -m lodestar ...` and by Docker. It is git-ignored,
   so never commit it.

2. Edit `config/lodestar.yaml`:

   ```yaml
   org:
     name: Your Organisation
     vertical: logistics_ports      # banking | fintech | aviation | retail | energy | power_utilities | telecom | logistics_ports
   mode: live                       # stop using demo data
   deployment_phase: 1              # agents above this phase do not run yet
   ```

3. Industry profile: review `config/verticals/<vertical>.yaml`. Check SLA days, KRI appetites,
   mandatory controls, `sectors`, `critical_infrastructure` and `incident_reporting` (authority
   and hours, to confirm with Legal). To change values without editing the shipped file, copy it,
   rename the `id`, and point `org.vertical` at the copy.

4. Check: `python -m lodestar validate --phase 1`. At this point it lists the connectors that
   still need credentials.

## Step 2 - Load the asset register (CMDB)

Prioritisation needs business context. Export your CMDB or crown-jewel register to
`config/assets.csv` (copy the columns from `config/assets.example.csv`) and set
`assets.path: config/assets.csv`.

| Column | Meaning | Example |
|---|---|---|
| `asset_id` | Unique ID; use the hostname your tools report | `dxb-tos-db-01` |
| `name`, `asset_type`, `business_service`, `owner` | Descriptive | `Terminal operating system DB`, `server`, `Terminal operating system`, `tos-team@…` |
| `criticality` | 5 crown jewel · 4 business-critical · 3 important · 2 standard · 1 lab | `5` |
| `exposure` | `internet` · `partner` · `internal` · `isolated` (air-gapped OT) | `internal` |
| `data_classification` | `public` · `internal` · `confidential` · `restricted` | `restricted` |
| `tags` | `;`-separated. Use `vendor:<name>` and `product:<name>` for OT/IT products so CSAF/ICS advisories match | `ot;vendor:northwind-automation;product:nwa-controller-500` |
| `aliases` | `;`-separated FQDNs, URLs and `*.wildcards` that researchers, advisories and tools use | `tos.your-org.example;*.tos.your-org.example` |

Check: after connecting the first tools, `test-connector` prints *matched / unmatched* assets and
the dashboard footer shows the **CMDB match rate**. Aim for ≥ 90 %. An unmatched asset is scored
with criticality 3 and listed in the data-quality section.

## Step 3 - Integrate the connector agents

### 3.1 Choose an integration method per product

| Method | Use when | Effort |
|---|---|---|
| **Native adapter** | Microsoft Defender / Sentinel / Entra, Tenable, HackerOne, TAXII, MISP, CSAF, mailbox | Credentials + config |
| **File drop** (`file_drop`) | The product can schedule a CSV/JSON export, or your SIEM can export a saved search | Field map in YAML, no code |
| **Signed webhook** (`webhook`) | The product, SOAR (Sentinel Logic Apps, Splunk SOAR, Cortex XSOAR, Tines) or a small script can POST JSON | Payload mapping in the SOAR |

All methods are read-only towards your tools. Webhooks are push-only into LODESTAR.

### 3.2 Phase and order

| Phase | Agents | Typical products |
|---|---|---|
| 1 | EndpointSentinel (EDR), VulnIntel (VMDR), IdentityGuard (Identity), SocPulse (SOC), MailShield (Email), ThreatFeed (TI feeds) | Defender / CrowdStrike, Tenable / Qualys, Entra / Okta, Sentinel / Splunk, Defender for O365 / Mimecast, CERT TAXII, ISAC MISP, CSAF, advisory mailbox |
| 2 | Perimeter (FW), AppShield (WAF), WebGateway (Proxy), ZeroTrustAccess (ZTNA), PrivilegeVault (PAM), CloudPosture (Cloud), FraudSentinel (Fraud), BugBounty | Palo Alto / Fortinet, Cloudflare / Akamai, Zscaler / Netskope, CyberArk, Wiz / Defender for Cloud, Feedzai / Actimize, HackerOne |
| 3 | CodeGuard (SAST), AppProbe (DAST), BrandWatch, AIGuardian, DataGuard (DLP), OTWatch, Resilience (Backup) | Checkmarx / Snyk, Invicti / Burp, Recorded Future, Prompt Security / Purview AI, Purview DLP, Claroty / Nozomi, Rubrik / Veeam |

### 3.3 Microsoft security stack (EDR, Identity, SOC, Email, Cloud, Cloud Apps)

One **read-only app registration** feeds six agents through the Microsoft Graph Security API
(`security/alerts_v2`) and Entra ID Protection.

1. **Entra admin centre → App registrations → New registration.** Name it `LODESTAR (read-only)`,
   single tenant, no redirect URI.
2. **API permissions → Add → Microsoft Graph → Application permissions**:
   * `SecurityAlert.Read.All` - Defender XDR / Sentinel alerts (EDR, Email, Cloud, Cloud Apps, SOC)
   * `IdentityRiskyUser.Read.All` - risky users (Identity)
   * `AuditLog.Read.All` - MFA registration coverage (Identity; Entra ID P1/P2 licence needed for this report)

   Then **Grant admin consent**.
3. **Certificates & secrets → New client secret** (expiry ≤ 12 months; set a renewal reminder).
4. `.env`:

   ```ini
   AZ_TENANT_ID=<directory (tenant) id>
   AZ_CLIENT_ID=<application (client) id>
   AZ_CLIENT_SECRET=<secret value>
   ```

5. The default `config/lodestar.yaml` already maps `edr`, `identity`, `soc`, `email` and `cloud`
   to these adapters. The alerts API does not report sensor coverage, so add `coverage_pct: 96`
   (your console figure) to the EDR `settings`. Without it, coverage is assumed to be 100 % and the
   control shows "coverage not reported".
6. Test each one:

   ```powershell
   python -m lodestar test-connector edr
   python -m lodestar test-connector identity
   python -m lodestar test-connector soc
   python -m lodestar test-connector email
   ```

| Symptom | Fix |
|---|---|
| `401` / `invalid_client` | Wrong secret value (copy the *value*, not the secret ID) or expired secret |
| `403 Forbidden` | Admin consent not granted, or the permission was added as *Delegated* instead of *Application* |
| 0 findings | No alerts in the last 14 days for that product (`lookback_days`), or the product isn't licensed / connected to Defender XDR |

### 3.4 Vulnerability management - Tenable (native) / Qualys / Rapid7 (file drop)

**Tenable Vulnerability Management:** create a dedicated user with the *Basic* role and *Can View*
on the relevant access groups. Under **Settings → My Account → API Keys → Generate**, put the keys in
`TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY`. Then run `python -m lodestar test-connector vmdr`.
Exports of large estates take a few minutes (`max_wait_seconds`, default 600).

**Qualys VMDR / Rapid7 InsightVM:** schedule a CSV report of confirmed vulnerabilities (severity ≥ 3)
to a share that LODESTAR reads, then:

```yaml
vmdr:
  enabled: true
  adapter: file_drop
  product: Qualys VMDR
  settings:
    path: data/drop/vmdr                 # or a UNC/mounted path
    finding_type: vulnerability
    field_map: {title: Title, severity: Severity, asset_id: DNS, cve: "CVE ID", first_seen: "First Detected",
                last_seen: "Last Detected", remediation: Solution}
    severity_map: {"5": critical, "4": high, "3": medium, "2": low, "1": info}
    health: {coverage_pct: 94, kpis: {scan_coverage_pct: 94, critical_sla_pct: 82, mttr_critical_days: 12}}
```

Column names differ between product versions and report templates. Open one export and copy the
exact header names into `field_map`.

### 3.5 File-drop recipes for other products

Same pattern for every product: a scheduled export lands in `data/drop/<domain>/`, and a
`field_map` translates its columns. The examples below are **starting points**. Confirm the
header names against your own export.

| Domain | Product example | Export source | `field_map` example | `finding_type` |
|---|---|---|---|---|
| `edr` | CrowdStrike Falcon | Scheduled detections report or Falcon Fusion workflow → webhook | `{title: DetectDescription, severity: Severity, asset_id: Hostname, user_id: UserName, first_seen: FirstBehavior}` | detection |
| `firewall` | Palo Alto Panorama / Expedition / Tufin | Policy-optimiser / BPA rule report | `{title: rule_issue, severity: risk, asset_id: device, first_seen: detected}` (matches `data/sample_drop`) | misconfiguration |
| `waf` | Cloudflare / Akamai | Security events via SIEM saved search | `{title: rule_message, severity: action_severity, asset_id: host, first_seen: datetime}` | detection |
| `web_proxy` | Zscaler ZIA / Netskope | SIEM search: malicious + unsanctioned AI apps | `{title: threatname, severity: severity, user_id: login, asset_id: devicehostname}` | policy_violation |
| `ztna` | Zscaler ZPA | Unmanaged-device access report | `{title: policy_name, severity: severity, user_id: username, asset_id: application}` | policy_violation |
| `pam` | CyberArk PVWA | *Privileged Accounts Inventory* / compliance report | `{title: issue, severity: risk, user_id: UserName, asset_id: Address}` | policy_violation |
| `cloud` | Wiz / Prisma / Security Hub | Issues report (CSV) | `{title: Title, severity: Severity, asset_id: "Resource Name", first_seen: "Created At", remediation: Remediation}` | misconfiguration |
| `sast` | Checkmarx One / Snyk | Scan results export or webhook | `{title: queryName, severity: severity, app_id: projectName, asset_id: projectName}` | vulnerability |
| `dast` | Invicti / Burp Enterprise | Scan report CSV | `{title: Name, severity: Severity, asset_id: Url, app_id: Url}` | vulnerability |
| `brand` | Recorded Future / ZeroFox | Alerts export | `{title: AlertTitle, severity: Risk, first_seen: Triggered}` | exposure |
| `ai_security` | Prompt Security / Lakera / Purview AI | Events export or webhook | `{title: event, severity: severity, user_id: user, asset_id: application}` | detection |
| `dlp` | Microsoft Purview DLP / Forcepoint | Alerts export | `{title: PolicyName, severity: Severity, user_id: User, first_seen: CreationTime}` | policy_violation |
| `ot` | Claroty / Nozomi / Dragos | Alerts + vulnerabilities export | `{title: alert_type, severity: severity, asset_id: asset_name, cve: cve}` | detection / vulnerability |
| `backup` | Rubrik / Veeam / Cohesity | Compliance / SLA report | `{title: issue, severity: severity, asset_id: object_name}` | coverage_gap |
| `fraud` | Feedzai / Actimize / SAS | Case or alert export (aggregated, pseudonymised) | `{title: alert_type, severity: priority, user_id: case_ref, first_seen: created}` | detection |

Add a `health:` block to each file-drop connector with the product's own coverage figure (for
example the share of servers with an agent). Coverage drives control effectiveness and posture.

Test after the first export lands: `python -m lodestar test-connector <domain>`. Rows with an
unknown severity are reported as warnings and default to *medium*. Extend `severity_map` until
there are none.

### 3.6 Signed webhook (SOAR or product push)

Endpoint: `POST https://<lodestar>/api/ingest/<domain>` with header
`X-Lodestar-Signature: sha256=<hex HMAC-SHA256 of the raw body using LODESTAR_WEBHOOK_SECRET>`.

```json
{
  "findings": [
    {"finding_id": "waf-123", "source": "Cloudflare WAF", "finding_type": "detection",
     "title": "SQL injection attempts against /api/v2/login", "severity": "high",
     "asset_id": "portal.your-org.example", "first_seen": "2026-10-01T05:00:00Z",
     "evidence": {"ioc": "203.0.113.10"}, "remediation": "Confirm blocking mode"}
  ],
  "health": {"coverage_pct": 92, "policy_drift_items": 1, "kpis": {"block_mode_pct": 85}}
}
```

* `finding_id` must be stable. Re-sending the same ID updates the finding instead of duplicating it.
* `finding_type`: `vulnerability | detection | misconfiguration | coverage_gap | policy_violation | exposure | incident`.
* `severity`: `critical | high | medium | low | info`. `status`: `open | in_progress | resolved | false_positive`.
* `health` is optional. Send it from a daily job so coverage and freshness are measured.
* Put IOC values in `evidence.ioc` so threat-intel sightings can correlate (LDS-016).

Test from Windows with the sample payload:

```powershell
python -m lodestar serve                                   # in another window
powershell -ExecutionPolicy Bypass -File scripts\send-test-webhook.ps1 -Domain waf -File samples\webhooks\waf_findings.json
python -m lodestar test-connector waf
```

In a SOAR, reproduce the same three steps: build the JSON, compute the HMAC over the exact bytes
you send, and POST with the header. Sentinel Logic Apps, Splunk SOAR, XSOAR and Tines all have an
HMAC/hash function or a code step for this.

### 3.7 Threat-intelligence feeds and advisory e-mail (ThreatFeedAgent)

Configured under `threat_intel.sources` in `config/lodestar.yaml`. Each source fails independently.

| Source | What you need | `.env` |
|---|---|---|
| National CERT / ISAC **TAXII 2.1** | API root URL, collection ID, token or username/password from the CERT/ISAC | `CERT_TAXII_API_ROOT`, `CERT_TAXII_COLLECTION`, `CERT_TAXII_TOKEN` |
| **MISP** community | Base URL and a read-only auth key from the ISAC's MISP | `ISAC_MISP_URL`, `ISAC_MISP_KEY` |
| **CSAF** (CISA ICS, vendor PSIRTs) | Advisory URLs in `urls:`, or sync the provider folder into `data/drop/csaf` | - |
| **Advisory mailbox** | A dedicated mailbox (e.g. `advisories@`) that receives CERT/ISAC/PSIRT lists | IMAP: `ADVISORY_IMAP_HOST/USER/PASSWORD`; or Graph (below) |

Mailbox through Microsoft Graph (recommended for M365):

1. Reuse or create an app registration and add the **Application** permission `Mail.Read`. Grant consent.
2. Restrict it to the advisory mailbox only (Exchange Online PowerShell):

   ```powershell
   Connect-ExchangeOnline
   New-ApplicationAccessPolicy -AppId <client-id> -PolicyScopeGroupId advisories@your-org.example `
     -AccessRight RestrictAccess -Description "LODESTAR: advisory mailbox only"
   Test-ApplicationAccessPolicy -Identity advisories@your-org.example -AppId <client-id>   # AccessCheckResult: Granted
   Test-ApplicationAccessPolicy -Identity ceo@your-org.example      -AppId <client-id>   # must be Denied
   ```

   (Microsoft also offers *RBAC for Applications* in Exchange Online as the newer way to scope
   mailbox access. Either works; the aim is that the app can read only that mailbox.)
3. Source settings: `mode: graph`, `tenant_id`, `client_id`, `client_secret`, `mailbox: advisories@your-org.example`.
4. Fill in `senders:` with the exact sender addresses or domains you trust, and keep `require_dkim: true`.

Test: `python -m lodestar test-connector threat_intel`. It lists everything ingested. Run
`python -m lodestar run` and open *External reports & intelligence* to see what passed the
relevance filter. Details: [EXTERNAL_INTEL.md](EXTERNAL_INTEL.md).

### 3.8 Bug bounty - HackerOne (BugBountyAgent)

1. HackerOne → **Organization settings → API tokens → Create**, and assign the token to a group with
   *read* access to the programme. Set `H1_API_IDENTIFIER`, `H1_API_TOKEN`, `H1_PROGRAM` (programme handle).
2. Programme → **Settings → Webhooks → New webhook**. Use `https://<lodestar>/api/ingest/hackerone`,
   set a secret, and copy it to `LODESTAR_H1_WEBHOOK_SECRET`. Select the report and bounty events.
3. Add the in-scope assets' hostnames to CMDB `aliases` so reports match assets.
4. `python -m lodestar test-connector bug_bounty`. Reports on hosts not in the CMDB are flagged
   as possible shadow IT.

### 3.9 Fraud engine (FraudSentinelAgent)

Prefer a **webhook** from the fraud case manager, or a nightly **file drop** of alerts. Send
aggregated and pseudonymised data: no card or account numbers. Push the fraud-control KPIs in
`health.kpis`, because they feed the fraud KRIs:

```json
"health": {"coverage_pct": 88, "kpis": {"channel_coverage_pct": 88, "alert_backlog_hours": 31,
           "confirmed_loss_30d": 412000, "prevented_30d": 9800000, "detection_rate_pct": 96,
           "false_positive_pct": 91, "ato_attempts_7d": 1840, "mule_accounts_detected": 23}}
```

Tag fraud findings in `evidence.tags` so the cyber-fraud rules can join them:
`ato` (account takeover; add `entity_keys: ["domain:<lookalike>"]` when sessions came from a phishing
domain), `internal` (employee-approved payment), `mule` (mule network, which triggers the MLRO
decision). See [FRAUD_MANAGEMENT.md](FRAUD_MANAGEMENT.md).

### 3.10 Health of what you connected

After each integration:

```powershell
python -m lodestar validate --phase <n>      # config and credentials
python -m lodestar run --phase <n>           # full pipeline
python -m lodestar serve                     # Control assurance tiles: healthy / degraded / failing / stale
```

A control is **stale** when it has sent no data for 48 hours, and it then appears as a finding.
Fix stale controls before trusting the posture score. The data-trust score and confidence flag
next to the posture make this visible.

## Step 4 - Configure the core agents

| Agent | Where | What to decide |
|---|---|---|
| ThreatIntelAgent | `threat_intel.live: true` | Pull CISA KEV and FIRST EPSS daily (needs egress to `cisa.gov`, `api.first.org`); otherwise the cached files in `data/intel/` are used |
| PrioritizationAgent | `scoring:` | Weights (must sum to 1.0), horizon thresholds, `today_capacity` (default 25), `vertical_weight_strength` - see [SCORING_MODEL.md](SCORING_MODEL.md) |
| CorrelationAgent | `lodestar/agents/core/correlation.py` (`RULES`) | Remove rules you don't want, or add your own (example in CONNECTOR_GUIDE.md) |
| DecisionAgent | `lodestar/agents/core/decision.py` (`PLAYBOOKS`) | Map decider roles to your RACI, adjust deadlines and options; give decision-authority (`ciso`) API keys or chat mappings to CISO, MLRO, Head of Fraud and OT manager - [HUMAN_IN_THE_LOOP.md](HUMAN_IN_THE_LOOP.md) |
| ActionAgent + ITSM | `itsm:` + `.env` | **ServiceNow**: integration user with `itil` + web-service access, `provider: servicenow`, `base_url: https://<instance>.service-now.com`. **Jira Cloud**: API token from id.atlassian.com, `username` = account e-mail, `project_key`. Keep `dry_run: true` until the change board approves |
| ChatOpsAgent | `chatops:` | Slack app / Teams Workflows + outgoing webhook, user-to-role mapping, daily brief hour - [CHATOPS.md](CHATOPS.md) |
| NarrativeAgent | `llm:` | Off by default. `provider: anthropic` + `ANTHROPIC_API_KEY` to use an LLM for executive summaries (aggregates only, numbers verified) |
| ReportingAgent | scheduler | Weekly on Mondays, monthly on the 1st, quarterly on the 1st of Jan/Apr/Jul/Oct; files in `reports/` and via `/api/reports/...` |

## Step 5 - Go live and schedule

**Docker (recommended for servers):**

```bash
docker compose up -d        # api (dashboard + API + chat endpoints) and scheduler (runs every 4 h)
```

**Windows host without Docker:** create two scheduled tasks, one for the API at start-up and one
for the scheduler:

```powershell
$repo = "C:\Projects\lodestar"; $py = "$repo\.venv\Scripts\python.exe"
$api  = New-ScheduledTaskAction -Execute $py -Argument "-m lodestar serve --host 127.0.0.1 --port 8080" -WorkingDirectory $repo
$sch  = New-ScheduledTaskAction -Execute $py -Argument "-m lodestar schedule --interval-hours 4" -WorkingDirectory $repo
$boot = New-ScheduledTaskTrigger -AtStartup
$set  = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "LODESTAR API"       -Action $api -Trigger $boot -Settings $set -User "NT AUTHORITY\NETWORK SERVICE"
Register-ScheduledTask -TaskName "LODESTAR Scheduler" -Action $sch -Trigger $boot -Settings $set -User "NT AUTHORITY\NETWORK SERVICE"
Start-ScheduledTask "LODESTAR API"; Start-ScheduledTask "LODESTAR Scheduler"
```

Give the service account read access to the repo folder and write access to `data\` and
`reports\`. Put the API behind your reverse proxy / SSO (IIS ARR, Entra Application Proxy,
Cloudflare Access) with TLS, and expose only `/api/ingest/*` and `/api/chat/*` to the internet
when webhooks or Slack/Teams need them.

**Go-live gate for each phase:**

```powershell
python -m lodestar validate --phase 2      # must end with RESULT: ready
python -m lodestar run --phase 2           # check agent failures = none
```

Then raise `deployment_phase` in `config/lodestar.yaml`. Exit criteria per phase are in
[DEPLOYMENT_PHASES.md](DEPLOYMENT_PHASES.md).

## Step 6 - Operate and troubleshoot

| Check | Command / place |
|---|---|
| Is every agent running? | `python -m lodestar run` prints agent failures; `/api/audit` (ciso key) lists each agent run |
| What did one connector return? | `python -m lodestar test-connector <domain> --show 20` |
| Are controls fresh? | Dashboard → Control assurance (stale > 48 h) |
| Is the posture trustworthy? | Data-trust score and confidence next to posture; CMDB match rate in the footer |
| What is waiting on people? | Dashboard → Decision desk, or `python -m lodestar chat decisions` |

| Problem | Likely cause | Fix |
|---|---|---|
| `Literal secret found at 'connectors.x.settings.api_token'` | A secret typed into YAML | Move it to `.env` and reference it as `${MY_VAR}` |
| `missing settings/env: [...]` in validate | Variable not in `.env` or a typo in its name | Add it; names are case-sensitive |
| `CONNECTED, NO FINDINGS YET` | Empty drop folder, no webhook received yet, or nothing in the lookback window | Drop an export / send `send-test-webhook.ps1` / widen `lookback_days` |
| Many *unmatched* assets | Tool hostnames differ from CMDB IDs (FQDN vs short name) | Add the tool's names to `aliases` in the CMDB export |
| Unknown severity warnings | Vendor uses words/numbers not in the default map | Extend `severity_map` |
| Webhook `401 Invalid or missing signature` | HMAC computed over different bytes (re-serialised JSON) or wrong secret | Sign the exact body you send; check `LODESTAR_WEBHOOK_SECRET` |
| Control shows *stale* | Source sent nothing for 48 h | Fix the export / workflow schedule; the control recovers on the next run |
| Today list too long or too short | Thresholds or capacity don't fit the team | Tune `scoring.today` and `today_capacity` |
| Graph `403` | Missing admin consent or Delegated instead of Application permission | Re-check Step 3.3 |
