# Agent catalogue

Generated from `lodestar/catalog.py` (`python -m lodestar agents`). 36 agents: 15 core (including the orchestrator), 21 connector.

## Core agents

| Phase | Agent | Responsibility |
|---:|---|---|
| 0 | **Orchestrator** | Builds the phase-appropriate pipeline, runs agents with failure isolation, persists results and audit. |
| 0 | **AssetContextAgent** | Loads CMDB / crown-jewel register and enriches findings with business context. |
| 0 | **DataQualityAgent** | Deduplicates, validates and scores the trustworthiness of incoming data; resolves hosts, IPs, MACs, device ids and user spellings to one asset / identity. |
| 0 | **LifecycleAgent** | Tracks findings across runs: sticky first-seen, carry-forward when a source fails, resolution rules per sync mode (snapshot: not seen in N full pulls; incremental: closed by the source or expired). |
| 1 | **ThreatHuntAgent** | Hunts recent threat-intel indicators across SIEM telemetry (Sentinel KQL / Splunk SPL); every sighting becomes a SOC detection and marks the advisory as sighted. |
| 1 | **ThreatIntelAgent** | Enriches vulnerabilities with CISA KEV, FIRST EPSS and in-environment exploitation evidence. |
| 1 | **ControlAssuranceAgent** | Measures coverage, freshness and drift of every integrated security control. |
| 1 | **PrioritizationAgent** | Scores and ranks every finding into Today / This week / This month / Backlog. |
| 1 | **ReportingAgent** | Weekly (phase 1), monthly (phase 3) and quarterly board (phase 4) reports in HTML, Markdown and JSON. |
| 2 | **CorrelationAgent** | Joins signals across controls into attack paths ('toxic combinations'). |
| 2 | **ActionAgent** | Drafts owner-assigned remediation tickets (human approval required before ITSM submission). |
| 2 | **DecisionAgent** | Queues decisions only a human may take (containment, emergency change, risk acceptance, disclosure) with owner, deadline and prepared evidence. |
| 2 | **ChatOpsAgent** | Conversational interface to the prioritisation agent in Slack, Microsoft Teams, the dashboard and CLI; pushes the daily focus brief and urgent decisions; records verdicts by mapped role. |
| 3 | **ComplianceMappingAgent** | Maps findings to NIST CSF 2.0, ISO 27001 and PCI DSS controls; flags at-risk controls. |
| 4 | **NarrativeAgent** | Business-language executive summaries; template engine by default, optional LLM with numeric grounding guardrail. |

Pipeline order: AssetContext → connectors → ThreatHunt (optional) → DataQuality (entity resolution, dedupe, CVE/IOC keys) → Lifecycle → ThreatIntel (KEV/EPSS + relevance filter for external intel) → ControlAssurance → Correlation → Prioritization → ComplianceMapping → Action → Decision. Reporting, Narrative and ChatOps run on demand / on schedule.

## Connector agents

Every connector agent is product-agnostic; adapters decide how data is fetched (several sources per agent are allowed). All adapters are read-only.

### EndpointSentinelAgent - Endpoint Detection & Response (phase 1)

Detections, sensor coverage and health across servers and workstations.

* **Typical products / sources:** CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Trend Vision One
* **KPIs reported:** coverage_pct, sensors_stale, detections_open, prevention_policy_pct
* **Least privilege:** Read-only API client: Alerts:read, Hosts:read
* **Adapters available:** ms_graph_security, file_drop, webhook

### IdentityGuardAgent - Identity (IdP / Directory / ITDR) (phase 1)

Risky users and sign-ins, MFA coverage, stale and over-privileged accounts.

* **Typical products / sources:** Microsoft Entra ID, Okta, Ping Identity, Microsoft Defender for Identity
* **KPIs reported:** mfa_coverage_pct, risky_users, stale_accounts, legacy_auth_signins
* **Least privilege:** IdentityRiskyUser.Read.All, AuditLog.Read.All, Directory.Read.All (application, read-only)
* **Adapters available:** ms_graph_security, entra_identity_protection, file_drop, webhook

### MailShieldAgent - Email Security (phase 1)

Phishing/BEC detections, user clicks, DMARC posture and simulation results.

* **Typical products / sources:** Microsoft Defender for Office 365, Mimecast, Proofpoint, Cisco Secure Email
* **KPIs reported:** phish_blocked, user_clicks, dmarc_enforced_pct, phishing_click_rate_pct
* **Least privilege:** Read-only reporting API role
* **Adapters available:** ms_graph_security, file_drop, webhook

### SocPulseAgent - SOC / SIEM / SOAR (phase 1)

Open incidents, MTTD/MTTR, log-source health and detection coverage (MITRE ATT&CK).

* **Typical products / sources:** Microsoft Sentinel, Splunk ES, Google SecOps, IBM QRadar, Elastic
* **KPIs reported:** incidents_open, mttd_hours, mttr_hours, log_sources_silent, attack_coverage_pct
* **Least privilege:** Read-only incident and saved-search role
* **Adapters available:** ms_graph_security, file_drop, webhook

### ThreatFeedAgent - Threat Intelligence Feeds & Advisories (phase 1)

Ingests STIX/TAXII and MISP feeds, CSAF / ICS advisories and advisory e-mails from national CERTs, ISACs and vendor PSIRTs; keeps only what matches our assets, sector or telemetry (CVE, product, IOC).

* **Typical products / sources:** National CERT / NCSC TAXII, Sector ISAC (FS-ISAC, E-ISAC), MISP communities, CISA ICS advisories (CSAF), Vendor PSIRT advisories, Commercial TI (Recorded Future, Mandiant, Group-IB)
* **KPIs reported:** feeds_active, feeds_stale, advisories_relevant_7d, iocs_ingested_7d, ioc_sightings_7d, sector_targeted_cves_open, intel_to_action_hours
* **Least privilege:** Read-only TAXII/MISP API keys; read-only mailbox (Mail.Read scoped to one mailbox or IMAP over TLS)
* **Adapters available:** taxii, misp, csaf, mailbox, file_drop, webhook

### VulnIntelAgent - Vulnerability Management (VMDR) (phase 1)

Vulnerabilities with CVE/KEV/EPSS context, scan coverage and remediation SLAs.

* **Typical products / sources:** Qualys VMDR, Tenable Vulnerability Management, Rapid7 InsightVM, Microsoft Defender VM
* **KPIs reported:** scan_coverage_pct, critical_open, kev_open, mttr_critical_days
* **Least privilege:** Read-only scanner account / API key with reporting scope only
* **Adapters available:** tenable_vm, file_drop, webhook

### AppShieldAgent - Web Application Firewall / WAAP (phase 2)

Attack traffic, apps in detect-only mode, unprotected public apps, virtual patches.

* **Typical products / sources:** Cloudflare, Akamai, F5 Advanced WAF, Imperva, Azure Front Door WAF
* **KPIs reported:** apps_protected_pct, block_mode_pct, attacks_blocked, virtual_patches
* **Least privilege:** Read-only API token (zone/analytics read)
* **Adapters available:** file_drop, webhook

### BugBountyAgent - Bug Bounty & Vulnerability Disclosure (phase 2)

Researcher reports from HackerOne (API + signed webhooks) or a VDP mailbox: severity, scope asset, weakness (CWE), triage state and response-SLA breaches, matched to our assets.

* **Typical products / sources:** HackerOne, Bugcrowd, Intigriti, YesWeHack, security@ / VDP mailbox
* **KPIs reported:** reports_open, triaged_awaiting_fix, critical_open, mean_time_to_triage_hours, sla_breaches, bounties_pending_decision, in_scope_internet_assets_pct
* **Least privilege:** HackerOne API token with read-only program access (Report: read); webhook secret
* **Adapters available:** hackerone, mailbox, file_drop, webhook

### CloudPostureAgent - Cloud Security (CSPM / CNAPP) (phase 2)

Misconfigurations, toxic cloud combinations, workload vulns, identity sprawl.

* **Typical products / sources:** Wiz, Microsoft Defender for Cloud, Prisma Cloud, AWS Security Hub, Orca
* **KPIs reported:** critical_misconfigs, public_buckets, accounts_covered_pct, secure_score
* **Least privilege:** Read-only security reader role per cloud account
* **Adapters available:** ms_graph_security, file_drop, webhook

### FraudSentinelAgent - Fraud Management & Transaction Monitoring (phase 2)

Account takeover, mule networks, authorised-push-payment scams, card fraud and fraud-control health (channel coverage, disabled rules, model drift, alert backlog) - joined with cyber signals.

* **Typical products / sources:** Feedzai, NICE Actimize, SAS Fraud Management, FICO Falcon, BioCatch, LexisNexis ThreatMetrix, Featurespace
* **KPIs reported:** channel_coverage_pct, alert_backlog_hours, confirmed_loss_30d, prevented_30d, detection_rate_pct, false_positive_pct, ato_attempts_7d, mule_accounts_detected
* **Least privilege:** Read-only case/alert reporting API or analytics export (no case-management write access)
* **Adapters available:** file_drop, webhook

### PerimeterAgent - Next-Gen Firewall (phase 2)

Policy hygiene (any-any, shadowed, unused rules), threat events, firmware currency.

* **Typical products / sources:** Palo Alto Networks, Fortinet FortiGate, Check Point, Cisco Secure Firewall
* **KPIs reported:** risky_rules, unused_rules, threat_events_blocked, firmware_outdated
* **Least privilege:** Read-only admin profile / API key
* **Adapters available:** file_drop, webhook

### PrivilegeVaultAgent - Privileged Access Management (phase 2)

Vaulted vs unvaulted privileged accounts, session recording, standing privileges.

* **Typical products / sources:** CyberArk, BeyondTrust, Delinea, Microsoft Entra PIM
* **KPIs reported:** vaulted_pct, standing_admins, sessions_unrecorded, rotation_failures
* **Least privilege:** Read-only auditor role
* **Adapters available:** file_drop, webhook

### WebGatewayAgent - Secure Web Gateway / Proxy (phase 2)

Malicious and uncategorised site access, shadow IT / shadow AI, TLS inspection coverage.

* **Typical products / sources:** Zscaler Internet Access, Netskope, Palo Alto Prisma Access, Cisco Umbrella
* **KPIs reported:** tls_inspection_pct, malicious_blocked, shadow_ai_users, policy_bypass
* **Least privilege:** Read-only admin / log streaming
* **Adapters available:** file_drop, webhook

### ZeroTrustAccessAgent - Zero Trust Network Access (phase 2)

Private-app access posture, unmanaged device access, legacy VPN residue.

* **Typical products / sources:** Zscaler Private Access, Cloudflare Access, Netskope Private Access, Palo Alto Prisma Access
* **KPIs reported:** apps_behind_ztna_pct, unmanaged_device_sessions, legacy_vpn_users
* **Least privilege:** Read-only admin / log streaming
* **Adapters available:** file_drop, webhook

### AIGuardianAgent - AI Security & Governance (phase 3)

AI model/app inventory (AI-SPM), LLM guardrail events (prompt injection, data leakage), shadow AI.

* **Typical products / sources:** Microsoft Purview AI Hub, Prompt Security, Lakera Guard, Protect AI, Netskope AI, Zscaler AI
* **KPIs reported:** ai_apps_inventoried, guardrail_blocks, prompt_injection_attempts, unsanctioned_ai_apps
* **Least privilege:** Read-only API key
* **Adapters available:** file_drop, webhook

### AppProbeAgent - Dynamic Application Security Testing (phase 3)

Runtime-confirmed web/API vulnerabilities on deployed applications.

* **Typical products / sources:** Invicti, Burp Suite Enterprise, Rapid7 InsightAppSec, OWASP ZAP
* **KPIs reported:** apps_tested_pct, confirmed_critical, api_coverage_pct
* **Least privilege:** Read-only reporting token
* **Adapters available:** file_drop, webhook

### BrandWatchAgent - Brand Protection / Digital Risk (phase 3)

Lookalike domains, phishing kits, fake apps/social profiles, leaked credentials.

* **Typical products / sources:** Recorded Future, ZeroFox, Group-IB, CybelAngel, Netcraft
* **KPIs reported:** lookalikes_active, takedowns_pending, brand_takedown_hours, leaked_credentials
* **Least privilege:** Read-only API key
* **Adapters available:** file_drop, webhook

### CodeGuardAgent - Static Application Security Testing (phase 3)

Code flaws, secrets in repos and vulnerable dependencies per application.

* **Typical products / sources:** Checkmarx, Veracode, Snyk, SonarQube, GitHub Advanced Security
* **KPIs reported:** repos_scanned_pct, critical_flaws, secrets_exposed, fix_rate_pct
* **Least privilege:** Read-only reporting token
* **Adapters available:** file_drop, webhook

### DataGuardAgent - Data Loss Prevention (phase 3)

Sensitive data movement to email, web, cloud and GenAI; policy coverage.

* **Typical products / sources:** Microsoft Purview DLP, Forcepoint, Symantec DLP, Netskope DLP
* **KPIs reported:** incidents_high, policy_coverage_pct, genai_uploads_blocked
* **Least privilege:** Read-only DLP reporting role
* **Adapters available:** file_drop, webhook

### OTWatchAgent - OT / ICS Security (phase 3)

OT asset visibility, unsafe protocols, vendor remote access, ICS-specific threats.

* **Typical products / sources:** Claroty, Nozomi Networks, Dragos, Microsoft Defender for IoT, TXOne
* **KPIs reported:** ot_assets_visible_pct, unmanaged_remote_access, critical_ot_vulns, ics_alerts
* **Least privilege:** Read-only API user on OT sensor/CMC (no write to OT networks)
* **Adapters available:** file_drop, webhook

### ResilienceAgent - Backup & Cyber Recovery (phase 3)

Immutable/air-gapped backup coverage for crown jewels, restore test results.

* **Typical products / sources:** Rubrik, Cohesity, Veeam, Commvault
* **KPIs reported:** immutable_pct, failed_jobs, restore_tests_passed_pct
* **Least privilege:** Read-only reporting role
* **Adapters available:** file_drop, webhook

## Correlation rules (attack paths)

| Rule | Attack path | Joined on | Legs | Human decision it raises |
|---|---|---|---|---|
| LDS-001 | Known-exploited vulnerability under active attack on internet-facing asset | asset | VMDR KEV on internet asset + WAF/FW/SOC/EDR detection | Approve emergency patch or isolation of … (CISO, Head of IT Operations, 4h) |
| LDS-002 | Blind spot: vulnerable asset without EDR | asset | EDR coverage gap + VMDR high/critical (asset criticality ≥3) | Approve EDR deployment or temporary containment for … (Asset owner, Endpoint Security lead, 24h) |
| LDS-003 | Privileged account takeover risk | user | Identity risky sign-in + PAM unvaulted/standing privilege | Approve credential reset and session revocation for privileged account … (Identity & Access lead, Account owner's manager, 2h) |
| LDS-004 | Phishing click followed by endpoint detection | user | Email user click + EDR detection | Approve endpoint isolation after phishing compromise of … (SOC lead, 1h) |
| LDS-005 | Active brand impersonation campaign | key | Brand lookalike + email/proxy detection on same domain | Authorise takedown and customer advisory for lookalike domain … (CISO, Legal / Brand, Corporate Communications, 24h) |
| LDS-006 | Sensitive data exposed in public cloud storage | asset | Cloud public storage + DLP sensitive data | Remove public access and start breach-notification assessment for … (Data owner, DPO / Legal, CISO, 4h) |
| LDS-007 | Sensitive data flowing to unsanctioned GenAI | user | Proxy/AI shadow-AI use + DLP violation | Block unsanctioned AI service and review data shared by … (CISO, Data owner, Line manager, 24h) |
| LDS-008 | Exploitable application flaw not shielded by WAF | app | SAST/DAST high + WAF gap / detect-only | Approve WAF blocking mode / virtual patch for … (Application owner, Application Security lead, 24h) |
| LDS-009 | Unmanaged remote access into OT | asset | OT unmanaged remote access + high-risk OT/VMDR/ZTNA/FW/ICS-advisory weakness | Approve removal of unmanaged vendor remote access to OT asset … (OT Operations manager, Process safety engineer, CISO, 8h) |
| LDS-010 | Ransomware blast radius: crown jewel without immutable backup | asset | Backup gap + EDR/VMDR high on same asset | Approve immutable backup and restore test for … (Head of IT Operations, Business service owner, 24h) |
| LDS-011 | Cyber-enabled fraud: lookalike phishing driving customer account takeover | key | Brand lookalike domain + fraud account takeover referred from that domain | Approve joint cyber-fraud response for campaign via … (Head of Fraud, CISO, Customer Operations, 2h) |
| LDS-012 | Compromised employee credentials linked to anomalous payment | user | Brand/identity credential exposure + fraud anomalous payment by the same employee | Hold payment and suspend payment rights for … (Head of Fraud, Head of Payments Operations, HR / Legal, 1h) |
| LDS-013 | Bot-driven account takeover on a customer channel | app | WAF credential-stuffing on a customer app + fraud account takeover on the same app | Approve bot mitigation and step-up on … login (Digital channel owner, Head of Fraud, 4h) |
| LDS-014 | Researcher-reported flaw already being probed by attackers | asset | Bug bounty high/critical report + WAF/FW/SOC/EDR detection on the same asset | Approve emergency fix / virtual patch for researcher-reported flaw on … (Application Security lead, Product / service owner, 8h) |
| LDS-015 | Sector-targeted vulnerability present in our estate | key | CERT/ISAC sector-targeted advisory + VMDR/OT/cloud/app finding with the same CVE | Approve emergency patch window for sector-targeted vulnerability on … (CISO, Head of IT / OT Operations, 8h) |
| LDS-016 | Threat-intelligence indicator sighted in our telemetry | key | Threat-intel indicator (TAXII/MISP/e-mail) + EDR/proxy/FW/e-mail/SOC/OT detection with the same IOC | Confirm compromise and invoke incident response: indicator sighted on … (SOC lead, CISO, 2h) |

## Industry profiles

| Profile | Heavier-weighted controls | Critical SLA | Critical infrastructure | Incident reporting (placeholder) | Frameworks |
|---|---|---:|---|---|---|
| Aviation | ot x1.3, ztna x1.15, brand x1.15, pam x1.15, fraud x1.1, email x1.1 | 10 days | yes | Civil aviation authority and national CERT (24 h) | NIST CSF 2.0, ISO/IEC 27001:2022, ICAO Annex 17 (cyber), EASA Part-IS, GCAA aviation cyber requirements, PCI DSS v4.0.1, IEC 62443 |
| Banking | fraud x1.35, pam x1.3, identity x1.2, brand x1.2, waf x1.15, dlp x1.15, email x1.1 | 7 days | yes | Central bank and national CERT (4 h) | NIST CSF 2.0, ISO/IEC 27001:2022, PCI DSS v4.0.1, SWIFT CSCF v2026, CBUAE Information Security Regulation, SAMA CSF, EU DORA |
| Energy (Oil & Gas) | ot x1.4, pam x1.25, backup x1.2, firewall x1.15, ztna x1.15 | 14 days | yes | National critical-infrastructure authority / CERT (24 h) | NIST CSF 2.0, ISO/IEC 27001:2022, IEC 62443, NIST SP 800-82r3, API Std 1164, UAE IA Standards |
| Fintech | fraud x1.3, cloud x1.3, sast x1.2, dast x1.2, waf x1.2, identity x1.15, ai_security x1.1 | 7 days | no | Financial services regulator (24 h) | NIST CSF 2.0, ISO/IEC 27001:2022, PCI DSS v4.0.1, SOC 2 Type II, DFSA / ADGM FSRA cyber rules, EU DORA |
| Ports, Terminals & Logistics | ot x1.3, ztna x1.2, pam x1.2, backup x1.2, email x1.1 | 10 days | yes | Maritime authority and national CERT (24 h) | NIST CSF 2.0, ISO/IEC 27001:2022, IMO MSC-FAL.1/Circ.3 (maritime cyber risk), IEC 62443, UAE IA Standards |
| Power & Utilities | ot x1.45, pam x1.25, firewall x1.2, backup x1.2, ztna x1.15 | 14 days | yes | National critical-infrastructure authority / CERT (24 h) | NIST CSF 2.0, NERC CIP, IEC 62443, IEC 62351, ISO/IEC 27019, UAE IA Standards |
| Retail | waf x1.25, brand x1.25, fraud x1.15, email x1.1, dlp x1.1 | 14 days | no | Data protection authority (if personal data) (72 h) | NIST CSF 2.0, ISO/IEC 27001:2022, PCI DSS v4.0.1, UAE PDPL, GDPR |
| Telecommunications | pam x1.25, fraud x1.2, firewall x1.2, identity x1.15, cloud x1.15, brand x1.1 | 10 days | yes | Telecoms regulator and national CERT (24 h) | NIST CSF 2.0, ISO/IEC 27001:2022, GSMA FS.31 Baseline Security Controls, 3GPP SCAS / GSMA NESAS, TDRA regulatory framework |
