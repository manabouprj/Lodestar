"""Catalogue of control domains: what each connector agent covers, which
phase it is deployed in, typical products, the KPIs it must report and the
least-privilege permission it needs. Drives docs, validation and the UI."""
from __future__ import annotations

from dataclasses import dataclass, field

from ...models import Domain


@dataclass(frozen=True)
class DomainSpec:
    domain: Domain
    agent_name: str
    title: str
    phase: int
    purpose: str
    typical_products: tuple[str, ...]
    kpis: tuple[str, ...]
    least_privilege: str
    live_adapters: tuple[str, ...] = field(default_factory=tuple)


SPECS: dict[Domain, DomainSpec] = {s.domain: s for s in [
    DomainSpec(Domain.EDR, "EndpointSentinelAgent", "Endpoint Detection & Response", 1,
               "Detections, sensor coverage and health across servers and workstations.",
               ("CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne", "Trend Vision One"),
               ("coverage_pct", "sensors_stale", "detections_open", "prevention_policy_pct"),
               "Read-only API client: Alerts:read, Hosts:read", ("ms_graph_security",)),
    DomainSpec(Domain.VMDR, "VulnIntelAgent", "Vulnerability Management (VMDR)", 1,
               "Vulnerabilities with CVE/KEV/EPSS context, scan coverage and remediation SLAs.",
               ("Qualys VMDR", "Tenable Vulnerability Management", "Rapid7 InsightVM", "Microsoft Defender VM"),
               ("scan_coverage_pct", "critical_open", "kev_open", "mttr_critical_days"),
               "Read-only scanner account / API key with reporting scope only", ("tenable_vm",)),
    DomainSpec(Domain.IDENTITY, "IdentityGuardAgent", "Identity (IdP / Directory / ITDR)", 1,
               "Risky users and sign-ins, MFA coverage, stale and over-privileged accounts.",
               ("Microsoft Entra ID", "Okta", "Ping Identity", "Microsoft Defender for Identity"),
               ("mfa_coverage_pct", "risky_users", "stale_accounts", "legacy_auth_signins"),
               "IdentityRiskyUser.Read.All, AuditLog.Read.All, Directory.Read.All (application, read-only)",
               ("ms_graph_security", "entra_identity_protection")),
    DomainSpec(Domain.SOC, "SocPulseAgent", "SOC / SIEM / SOAR", 1,
               "Open incidents, MTTD/MTTR, log-source health and detection coverage (MITRE ATT&CK).",
               ("Microsoft Sentinel", "Splunk ES", "Google SecOps", "IBM QRadar", "Elastic"),
               ("incidents_open", "mttd_hours", "mttr_hours", "log_sources_silent", "attack_coverage_pct"),
               "Read-only incident and saved-search role", ("ms_graph_security",)),
    DomainSpec(Domain.EMAIL, "MailShieldAgent", "Email Security", 1,
               "Phishing/BEC detections, user clicks, DMARC posture and simulation results.",
               ("Microsoft Defender for Office 365", "Mimecast", "Proofpoint", "Cisco Secure Email"),
               ("phish_blocked", "user_clicks", "dmarc_enforced_pct", "phishing_click_rate_pct"),
               "Read-only reporting API role", ("ms_graph_security",)),
    DomainSpec(Domain.FIREWALL, "PerimeterAgent", "Next-Gen Firewall", 2,
               "Policy hygiene (any-any, shadowed, unused rules), threat events, firmware currency.",
               ("Palo Alto Networks", "Fortinet FortiGate", "Check Point", "Cisco Secure Firewall"),
               ("risky_rules", "unused_rules", "threat_events_blocked", "firmware_outdated"),
               "Read-only admin profile / API key", ()),
    DomainSpec(Domain.WAF, "AppShieldAgent", "Web Application Firewall / WAAP", 2,
               "Attack traffic, apps in detect-only mode, unprotected public apps, virtual patches.",
               ("Cloudflare", "Akamai", "F5 Advanced WAF", "Imperva", "Azure Front Door WAF"),
               ("apps_protected_pct", "block_mode_pct", "attacks_blocked", "virtual_patches"),
               "Read-only API token (zone/analytics read)", ()),
    DomainSpec(Domain.WEB_PROXY, "WebGatewayAgent", "Secure Web Gateway / Proxy", 2,
               "Malicious and uncategorised site access, shadow IT / shadow AI, TLS inspection coverage.",
               ("Zscaler Internet Access", "Netskope", "Palo Alto Prisma Access", "Cisco Umbrella"),
               ("tls_inspection_pct", "malicious_blocked", "shadow_ai_users", "policy_bypass"),
               "Read-only admin / log streaming", ()),
    DomainSpec(Domain.ZTNA, "ZeroTrustAccessAgent", "Zero Trust Network Access", 2,
               "Private-app access posture, unmanaged device access, legacy VPN residue.",
               ("Zscaler Private Access", "Cloudflare Access", "Netskope Private Access", "Palo Alto Prisma Access"),
               ("apps_behind_ztna_pct", "unmanaged_device_sessions", "legacy_vpn_users"),
               "Read-only admin / log streaming", ()),
    DomainSpec(Domain.PAM, "PrivilegeVaultAgent", "Privileged Access Management", 2,
               "Vaulted vs unvaulted privileged accounts, session recording, standing privileges.",
               ("CyberArk", "BeyondTrust", "Delinea", "Microsoft Entra PIM"),
               ("vaulted_pct", "standing_admins", "sessions_unrecorded", "rotation_failures"),
               "Read-only auditor role", ()),
    DomainSpec(Domain.CLOUD, "CloudPostureAgent", "Cloud Security (CSPM / CNAPP)", 2,
               "Misconfigurations, toxic cloud combinations, workload vulns, identity sprawl.",
               ("Wiz", "Microsoft Defender for Cloud", "Prisma Cloud", "AWS Security Hub", "Orca"),
               ("critical_misconfigs", "public_buckets", "accounts_covered_pct", "secure_score"),
               "Read-only security reader role per cloud account", ("ms_graph_security",)),
    DomainSpec(Domain.THREAT_INTEL, "ThreatFeedAgent", "Threat Intelligence Feeds & Advisories", 1,
               "Ingests STIX/TAXII and MISP feeds, CSAF / ICS advisories and advisory e-mails from national CERTs, ISACs and "
               "vendor PSIRTs; keeps only what matches our assets, sector or telemetry (CVE, product, IOC).",
               ("National CERT / NCSC TAXII", "Sector ISAC (FS-ISAC, E-ISAC)", "MISP communities", "CISA ICS advisories (CSAF)",
                "Vendor PSIRT advisories", "Commercial TI (Recorded Future, Mandiant, Group-IB)"),
               ("feeds_active", "feeds_stale", "advisories_relevant_7d", "iocs_ingested_7d", "ioc_sightings_7d",
                "sector_targeted_cves_open", "intel_to_action_hours"),
               "Read-only TAXII/MISP API keys; read-only mailbox (Mail.Read scoped to one mailbox or IMAP over TLS)",
               ("taxii", "misp", "csaf", "mailbox")),
    DomainSpec(Domain.BUG_BOUNTY, "BugBountyAgent", "Bug Bounty & Vulnerability Disclosure", 2,
               "Researcher reports from HackerOne (API + signed webhooks) or a VDP mailbox: severity, scope asset, "
               "weakness (CWE), triage state and response-SLA breaches, matched to our assets.",
               ("HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "security@ / VDP mailbox"),
               ("reports_open", "triaged_awaiting_fix", "critical_open", "mean_time_to_triage_hours", "sla_breaches",
                "bounties_pending_decision", "in_scope_internet_assets_pct"),
               "HackerOne API token with read-only program access (Report: read); webhook secret", ("hackerone", "mailbox")),
    DomainSpec(Domain.FRAUD, "FraudSentinelAgent", "Fraud Management & Transaction Monitoring", 2,
               "Account takeover, mule networks, authorised-push-payment scams, card fraud and fraud-control health "
               "(channel coverage, disabled rules, model drift, alert backlog) - joined with cyber signals.",
               ("Feedzai", "NICE Actimize", "SAS Fraud Management", "FICO Falcon", "BioCatch", "LexisNexis ThreatMetrix", "Featurespace"),
               ("channel_coverage_pct", "alert_backlog_hours", "confirmed_loss_30d", "prevented_30d", "detection_rate_pct",
                "false_positive_pct", "ato_attempts_7d", "mule_accounts_detected"),
               "Read-only case/alert reporting API or analytics export (no case-management write access)", ()),
    DomainSpec(Domain.SAST, "CodeGuardAgent", "Static Application Security Testing", 3,
               "Code flaws, secrets in repos and vulnerable dependencies per application.",
               ("Checkmarx", "Veracode", "Snyk", "SonarQube", "GitHub Advanced Security"),
               ("repos_scanned_pct", "critical_flaws", "secrets_exposed", "fix_rate_pct"),
               "Read-only reporting token", ()),
    DomainSpec(Domain.DAST, "AppProbeAgent", "Dynamic Application Security Testing", 3,
               "Runtime-confirmed web/API vulnerabilities on deployed applications.",
               ("Invicti", "Burp Suite Enterprise", "Rapid7 InsightAppSec", "OWASP ZAP"),
               ("apps_tested_pct", "confirmed_critical", "api_coverage_pct"),
               "Read-only reporting token", ()),
    DomainSpec(Domain.BRAND, "BrandWatchAgent", "Brand Protection / Digital Risk", 3,
               "Lookalike domains, phishing kits, fake apps/social profiles, leaked credentials.",
               ("Recorded Future", "ZeroFox", "Group-IB", "CybelAngel", "Netcraft"),
               ("lookalikes_active", "takedowns_pending", "brand_takedown_hours", "leaked_credentials"),
               "Read-only API key", ()),
    DomainSpec(Domain.AI_SECURITY, "AIGuardianAgent", "AI Security & Governance", 3,
               "AI model/app inventory (AI-SPM), LLM guardrail events (prompt injection, data leakage), shadow AI.",
               ("Microsoft Purview AI Hub", "Prompt Security", "Lakera Guard", "Protect AI", "Netskope AI", "Zscaler AI"),
               ("ai_apps_inventoried", "guardrail_blocks", "prompt_injection_attempts", "unsanctioned_ai_apps"),
               "Read-only API key", ()),
    DomainSpec(Domain.DLP, "DataGuardAgent", "Data Loss Prevention", 3,
               "Sensitive data movement to email, web, cloud and GenAI; policy coverage.",
               ("Microsoft Purview DLP", "Forcepoint", "Symantec DLP", "Netskope DLP"),
               ("incidents_high", "policy_coverage_pct", "genai_uploads_blocked"),
               "Read-only DLP reporting role", ()),
    DomainSpec(Domain.OT, "OTWatchAgent", "OT / ICS Security", 3,
               "OT asset visibility, unsafe protocols, vendor remote access, ICS-specific threats.",
               ("Claroty", "Nozomi Networks", "Dragos", "Microsoft Defender for IoT", "TXOne"),
               ("ot_assets_visible_pct", "unmanaged_remote_access", "critical_ot_vulns", "ics_alerts"),
               "Read-only API user on OT sensor/CMC (no write to OT networks)", ()),
    DomainSpec(Domain.BACKUP, "ResilienceAgent", "Backup & Cyber Recovery", 3,
               "Immutable/air-gapped backup coverage for crown jewels, restore test results.",
               ("Rubrik", "Cohesity", "Veeam", "Commvault"),
               ("immutable_pct", "failed_jobs", "restore_tests_passed_pct"),
               "Read-only reporting role", ()),
]}


def spec(domain: Domain | str) -> DomainSpec:
    d = Domain(domain) if isinstance(domain, str) else domain
    return SPECS[d]
