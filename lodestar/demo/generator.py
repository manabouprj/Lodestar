"""Synthetic demo data generator.

Creates a realistic, fully FICTIONAL enterprise per industry vertical:
assets, users, ~1,500-2,500 raw signals across 18 security controls, control
health telemetry, threat-intel context and 180 days of trend history.

Each dataset contains scripted "CISO pain-point" scenarios (attack paths)
hidden among realistic noise, so a presentation can show LODESTAR turning
thousands of tool alerts into a short, explainable Today list.

All organisation names, people, domains (*.example) and hosts are invented.
CVE identifiers are real public CVEs used for illustration only.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..models import Domain

ORGS: dict[str, dict[str, Any]] = {
    "banking": {"name": "Sandline Bank", "code": "sdb", "domain": "sandlinebank.example", "seed": 101,
                "kev_asset": ("Internet banking gateway (Citrix ADC)", "CVE-2023-4966", "Citrix NetScaler ADC session token leak ('Citrix Bleed')")},
    "fintech": {"name": "Lumenpay", "code": "lmp", "domain": "lumenpay.example", "seed": 202,
                "kev_asset": ("Partner file-transfer gateway (MOVEit)", "CVE-2023-34362", "MOVEit Transfer SQL injection")},
    "aviation": {"name": "Aerolume Airways", "code": "alw", "domain": "aerolume.example", "seed": 303,
                 "kev_asset": ("Crew remote-access gateway (Ivanti)", "CVE-2023-46805", "Ivanti Connect Secure authentication bypass")},
    "retail": {"name": "Souqara Retail Group", "code": "sqr", "domain": "souqara.example", "seed": 404,
               "kev_asset": ("E-commerce search service (Java)", "CVE-2021-44228", "Apache Log4j2 remote code execution (Log4Shell)")},
    "energy": {"name": "Petrava Energy", "code": "pve", "domain": "petrava.example", "seed": 505,
               "kev_asset": ("Remote-access firewall (PAN-OS GlobalProtect)", "CVE-2024-3400", "PAN-OS GlobalProtect command injection")},
    "power_utilities": {"name": "Helionyx Power & Water", "code": "hpw", "domain": "helionyx.example", "seed": 606,
                        "kev_asset": ("SSL-VPN gateway (FortiOS)", "CVE-2024-21762", "FortiOS SSL-VPN out-of-bounds write")},
    "telecom": {"name": "Corvianet Telecom", "code": "cvn", "domain": "corvianet.example", "seed": 707,
                "kev_asset": ("Edge router management (Cisco IOS XE)", "CVE-2023-20198", "Cisco IOS XE web UI privilege escalation")},
    "logistics_ports": {"name": "Portaris Terminals", "code": "ptr", "domain": "portaris.example", "seed": 808,
                        "kev_asset": ("Vendor remote-support server (ScreenConnect)", "CVE-2024-1709", "ConnectWise ScreenConnect authentication bypass")},
}

OT_VERTICALS = {"aviation", "energy", "power_utilities", "logistics_ports"}
FRAUD_VERTICALS = {"banking", "fintech", "retail", "telecom", "aviation"}
FRAUD_FLAVOUR = {
    "banking": ("Account-takeover surge on mobile banking", "customers", "Authorised-push-payment scam cluster"),
    "fintech": ("Wallet account-takeover surge", "wallet users", "Authorised-push-payment scam cluster"),
    "retail": ("Loyalty and stored-card account takeover surge", "shoppers", "Refund and gift-card abuse ring"),
    "telecom": ("SIM-swap enabled account takeover surge", "subscribers", "Subscription / device-financing fraud ring"),
    "aviation": ("Loyalty miles account takeover surge", "members", "Miles-to-voucher cash-out ring"),
}

KEV_SAMPLE = ["CVE-2023-4966", "CVE-2024-3400", "CVE-2023-46805", "CVE-2021-44228", "CVE-2023-34362",
              "CVE-2024-21762", "CVE-2023-20198", "CVE-2024-1709", "CVE-2023-22515", "CVE-2022-41040",
              "CVE-2023-3519", "CVE-2023-27997"]
NON_KEV = [("CVE-2024-6387", "OpenSSH regreSSHion race condition", "critical", 0.12),
           ("CVE-2023-48795", "SSH Terrapin prefix truncation", "medium", 0.6),
           ("CVE-2023-38545", "curl SOCKS5 heap overflow", "high", 0.22),
           ("CVE-2024-0727", "OpenSSL PKCS12 NULL dereference", "medium", 0.01),
           ("CVE-2023-5678", "OpenSSL DH excessive time", "medium", 0.01),
           ("CVE-2024-2961", "glibc iconv buffer overflow", "high", 0.07)]
NOISE_VULNS = [("Windows cumulative security update missing", "high"), ("Microsoft Office security update missing", "medium"),
               ("TLS 1.0/1.1 protocol enabled", "medium"), ("SMB signing not required", "medium"),
               ("Outdated Java runtime", "high"), ("Self-signed TLS certificate", "low"),
               ("Apache HTTP Server outdated version", "medium"), ("Weak SSH ciphers enabled", "low"),
               ("Google Chrome security update missing", "high"), ("VMware Tools outdated", "medium"),
               ("Unsupported OS version (end of life)", "critical"), ("Default SNMP community string", "high"),
               ("Oracle Database CPU missing", "high"), (".NET Framework security update missing", "medium")]

FIRST = ["Aisha", "Omar", "Priya", "James", "Fatima", "Rahul", "Sara", "Yousef", "Maria", "Khalid", "Leila", "David",
         "Noor", "Arjun", "Hana", "Tariq", "Elena", "Samir", "Grace", "Imran", "Mona", "Vikram", "Layla", "Peter",
         "Reem", "Anil", "Zainab", "Lucas", "Huda", "Rohan"]
LAST = ["Haddad", "Khan", "Nair", "Mensah", "Saleh", "Iyer", "Rahman", "Costa", "Farouk", "Okafor", "Aziz", "Menon",
        "Silva", "Hassan", "Pillai", "Qureshi", "Rossi", "Darwish", "Mbeki", "Shah"]


class Gen:
    def __init__(self, vertical: str, as_of: datetime):
        meta = ORGS[vertical]
        self.v, self.meta = vertical, meta
        self.r = random.Random(meta["seed"])
        self.as_of = as_of
        self.code, self.dom = meta["code"], meta["domain"]
        self.assets: list[dict] = []
        self.users: list[dict] = []
        self.f: dict[str, list[dict]] = {d.value: [] for d in Domain}
        self.n = 0
        self.kev_set = set(KEV_SAMPLE)
        self.epss: dict[str, float] = {}

    # ------------------------------------------------------------------ helpers
    def ago(self, lo: float, hi: float) -> str:
        return (self.as_of - timedelta(days=self.r.uniform(lo, hi))).isoformat()

    def fid(self, d: str) -> str:
        self.n += 1
        return f"{d}-{self.code}-{self.n:05d}"

    def add(self, d: str, **kw) -> dict:
        kw.setdefault("source", PRODUCTS[d])
        kw.setdefault("status", "open")
        kw.setdefault("first_seen", self.ago(1, 60))
        kw.setdefault("last_seen", self.ago(0, 0.5))
        kw.setdefault("description", "")
        item = {"finding_id": self.fid(d), "domain": d, **kw}
        self.f[d].append(item)
        return item

    def asset(self, aid: str, name: str, atype: str, svc: str | None, crit: int, exp: str, **kw) -> dict:
        a = {"asset_id": aid, "name": name, "asset_type": atype, "business_service": svc, "criticality": crit,
             "exposure": exp, "owner": kw.get("owner"), "tags": kw.get("tags", []),
             "data_classification": kw.get("data", "internal")}
        self.assets.append(a)
        return a

    def pick(self, seq):
        return self.r.choice(seq)

    # ------------------------------------------------------------------ estate
    def build_estate(self, crown: list[str]):
        c = self.code
        self.crown_apps = []
        for i, svc in enumerate(crown):
            exp = "internet" if any(k in svc.lower() for k in ("internet", "mobile", "portal", "e-commerce", "payments api",
                                                                "self-care", "reservations", "customer")) else "internal"
            app = self.asset(f"{c}-app-{i+1:02d}", svc, "app", svc, 5, exp, data="restricted")
            self.crown_apps.append(app)
            for n in range(1, 4):
                self.asset(f"{c}-cj{i+1}-srv-{n:02d}", f"{svc} server {n}", "server", svc, 5,
                           "internet" if exp == "internet" and n == 1 else "internal", data="restricted")
        kev_name = self.meta["kev_asset"][0]
        self.kev_asset = self.asset(f"{c}-edge-gw-01", kev_name, "server", self.crown_apps[0]["business_service"], 5,
                                    "internet", tags=["edge", "remote_access"])
        for n in range(1, 61):
            tier = self.r.choices([4, 3, 2], [0.2, 0.5, 0.3])[0]
            exp = self.r.choices(["internal", "partner", "internet"], [0.82, 0.08, 0.10])[0]
            self.asset(f"{c}-srv-{n:03d}", f"Server {n:03d}", "server", self.pick(["HR", "Finance ERP", "Intranet",
                       "File services", "Analytics", "CRM", "Build/CI", "Directory services", "Collaboration"]), tier, exp)
        for n in range(1, 7):
            self.asset(f"{c}-fw-{n:02d}", f"Firewall cluster {n:02d}", "network_device", "Network perimeter", 4,
                       "internet" if n <= 2 else "internal")
        for n in range(1, 121):
            self.asset(f"{c}-wks-{n:04d}", f"Workstation {n:04d}", "workstation", "End-user computing", 2, "internal")
        for n, name in enumerate(["Production", "Data platform", "Dev/Test", "Shared services"], 1):
            self.asset(f"{c}-cloud-{n}", f"Cloud account - {name}", "cloud_account", name, 4 if n < 3 else 2, "internet")
        self.asset(f"{c}-s3-kyc-archive", "Object storage: customer-docs-archive", "cloud_storage",
                   self.crown_apps[0]["business_service"], 5, "internet", data="restricted")
        for n, name in enumerate(["Customer assistant (LLM)", "Internal knowledge copilot", "Fraud model"], 1):
            self.asset(f"{c}-ai-{n}", name, "model", "AI services", 4 if n == 1 else 3, "internet" if n == 1 else "internal")
        if self.v in OT_VERTICALS:
            for n in range(1, 41):
                kind = self.pick(["HMI", "PLC", "Engineering workstation", "Historian", "RTU", "Safety controller"])
                self.asset(f"{c}-ot-{n:03d}", f"{kind} {n:03d}", "ot_device",
                           self.pick([s for s in crown if any(k in s for k in ("SCADA", "OT", "DCS", "Baggage", "crane", "Gate", "Substation", "Pipeline", "Safety", "EMS"))] or crown),
                           5 if kind in ("PLC", "Safety controller", "HMI") else 4, "isolated", tags=["ot"])
        for i in range(80):
            fn, ln = FIRST[i % len(FIRST)], LAST[(i * 7) % len(LAST)]
            priv = i < 10
            self.users.append({"user_id": f"{fn[0].lower()}.{ln.lower()}{i}@{self.dom}", "name": f"{fn} {ln}",
                               "privileged": priv, "device": f"{c}-wks-{i+1:04d}"})

    # ------------------------------------------------------------------ scenarios (attack paths)
    def scenarios(self):
        c, kev_asset = self.code, self.kev_asset
        name, cve, vuln_title = self.meta["kev_asset"]
        admin, clicker, ai_user = self.users[1], self.users[23], self.users[37]
        app_internet = next((a for a in self.crown_apps if a["exposure"] == "internet"), self.crown_apps[0])
        self.epss[cve] = 0.94

        # S1 KEV on internet-facing gateway + exploit attempts
        self.add("vmdr", finding_type="vulnerability", title=vuln_title, severity="critical", asset_id=kev_asset["asset_id"],
                 cve=cve, first_seen=self.ago(9, 11), remediation="Apply vendor fixed release; rotate sessions/credentials; hunt for IOCs.")
        self.add("waf" if self.v in ("banking", "retail", "fintech") else "firewall", finding_type="detection",
                 title=f"Exploit attempts matching {cve} signature", severity="high", asset_id=kev_asset["asset_id"],
                 evidence={"cve": cve, "attempts_24h": 412, "source_countries": 9}, first_seen=self.ago(0.5, 1.5),
                 remediation="Enable virtual-patch signature in blocking mode; geo/IP reputation block.")
        # S2 privileged account takeover
        self.add("identity", finding_type="detection", title="Impossible travel + MFA fatigue on privileged account",
                 severity="high", user_id=admin["user_id"], first_seen=self.ago(0.2, 0.8),
                 evidence={"mfa_prompts": 23, "countries": ["AE", "RO"]},
                 remediation="Revoke sessions, reset credentials, require phishing-resistant MFA.")
        self.add("pam", finding_type="coverage_gap", title="Domain admin account not vaulted (standing privilege)",
                 severity="high", user_id=admin["user_id"], first_seen=self.ago(40, 90),
                 remediation="Onboard to PAM vault, enforce JIT elevation and session recording.")
        # S3 phishing click -> endpoint detection
        self.add("email", finding_type="detection", title="User clicked credential-phishing link (payroll lure)",
                 severity="medium", user_id=clicker["user_id"], evidence={"tags": ["user_clicked"], "campaign": "payroll-update"},
                 first_seen=self.ago(0.5, 1))
        self.add("edr", finding_type="detection", title="Suspicious PowerShell download cradle after browser launch",
                 severity="high", asset_id=clicker["device"], user_id=clicker["user_id"], first_seen=self.ago(0.3, 0.9),
                 remediation="Isolate host, collect triage package, reset user credentials.")
        # S4 brand impersonation
        look = f"{self.dom.split('.')[0]}-verify-login.example"
        self.add("brand", finding_type="exposure", title=f"Lookalike phishing domain live: {look}", severity="high",
                 entity_keys=[f"domain:{look}"], first_seen=self.ago(2, 4), evidence={"hosting": "bulletproof", "ssl": True},
                 remediation="Submit takedown, add to email/proxy/DNS blocklists, warn customers.")
        self.add("email", finding_type="detection", title=f"Inbound phishing using lookalike domain {look}", severity="medium",
                 entity_keys=[f"domain:{look}"], first_seen=self.ago(1, 2), evidence={"messages": 187, "blocked": 171})
        # S5 public cloud storage with sensitive data
        b = f"{c}-s3-kyc-archive"
        self.add("cloud", finding_type="misconfiguration", title="Object storage bucket publicly readable", severity="critical",
                 asset_id=b, first_seen=self.ago(3, 6), remediation="Block public access; enable access logging; review data access.")
        self.add("dlp", finding_type="exposure", title="Restricted customer identity documents discovered in storage",
                 severity="high", asset_id=b, evidence={"records_estimate": 48200, "classifier": "National ID / Passport"},
                 first_seen=self.ago(2, 4))
        # S6 shadow AI + DLP
        self.add("web_proxy", finding_type="policy_violation", title="Unsanctioned GenAI service in use (free consumer tier)",
                 severity="medium", user_id=ai_user["user_id"], evidence={"tags": ["shadow_ai"], "app": "consumer chatbot"},
                 first_seen=self.ago(1, 5))
        self.add("dlp", finding_type="policy_violation", title="Customer data pasted into external GenAI prompt",
                 severity="high", user_id=ai_user["user_id"], evidence={"records": 312, "data_types": ["customer_name", "account_no"]},
                 first_seen=self.ago(0.5, 2))
        # S7 exploitable app flaw not shielded by WAF
        self.add("dast", finding_type="vulnerability", title="Broken object-level authorisation on /api/v2/accounts/{id}",
                 severity="critical", app_id=app_internet["asset_id"], asset_id=app_internet["asset_id"], first_seen=self.ago(6, 12),
                 remediation="Enforce object-level authorisation checks server side; add regression test.")
        self.add("waf", finding_type="misconfiguration", title=f"WAF policy in detect-only mode for {app_internet['name']}",
                 severity="medium", app_id=app_internet["asset_id"], asset_id=app_internet["asset_id"], first_seen=self.ago(30, 80),
                 remediation="Move policy to blocking after 7-day tuning window.")
        # S8 crown jewel without immutable backup + threat
        cj_srv = next(a for a in self.assets if a["asset_type"] == "server" and a["criticality"] == 5 and a["exposure"] == "internal")
        self.add("backup", finding_type="coverage_gap", title=f"No immutable backup copy for {cj_srv['business_service']}",
                 severity="high", asset_id=cj_srv["asset_id"], first_seen=self.ago(20, 60),
                 remediation="Enable immutable / air-gapped copy and run a restore test.")
        self.add("edr", finding_type="detection", title="Ransomware precursor: shadow copy deletion attempt blocked",
                 severity="critical", asset_id=cj_srv["asset_id"], first_seen=self.ago(0.2, 0.6),
                 remediation="Hunt for lateral movement, confirm containment, review privileged logons to host.")
        # S9 EDR blind spots on vulnerable servers
        for a in self.r.sample([x for x in self.assets if x["asset_type"] == "server" and x["criticality"] >= 4
                                and x["asset_id"] != kev_asset["asset_id"]], 3):
            self.add("edr", finding_type="coverage_gap", title="EDR sensor missing or offline > 7 days", severity="medium",
                     asset_id=a["asset_id"], first_seen=self.ago(8, 30))
            self.add("vmdr", finding_type="vulnerability", title=NON_KEV[0][1], cve=NON_KEV[0][0], severity="critical",
                     asset_id=a["asset_id"], first_seen=self.ago(20, 45))
        # S10 OT unmanaged remote access
        if self.v in OT_VERTICALS:
            ots = [a for a in self.assets if a["asset_type"] == "ot_device"]
            for a in self.r.sample(ots, 2):
                self.add("ot", finding_type="exposure", title="Unmanaged vendor remote-access tool (TeamViewer) on OT asset",
                         severity="high", asset_id=a["asset_id"], evidence={"tags": ["remote_access"]}, first_seen=self.ago(5, 25),
                         remediation="Remove tool; route vendor access via ZTNA + PAM jump host with approval and recording.")
                self.add("ot", finding_type="vulnerability", title="Unsupported Windows XP on engineering workstation",
                         severity="high", asset_id=a["asset_id"], first_seen=self.ago(100, 170))
        # AI-specific
        self.add("ai_security", finding_type="detection", title="Prompt-injection attempts against customer assistant",
                 severity="high", asset_id=f"{c}-ai-1", evidence={"attempts_24h": 64, "blocked": 61}, first_seen=self.ago(0.5, 2),
                 remediation="Confirm guardrail coverage, review 3 un-blocked prompts, restrict tool permissions of the assistant.")

    # ------------------------------------------------------------------ realistic noise
    def noise(self):
        r, A = self.r, self.assets
        servers = [a for a in A if a["asset_type"] == "server"]
        wks = [a for a in A if a["asset_type"] == "workstation"]
        users = self.users
        for cve, _title, _sev, ep in NON_KEV:
            self.epss[cve] = ep
        # VMDR bulk
        for _ in range(int(r.uniform(900, 1300))):
            a = r.choice(servers + wks)
            if r.random() < 0.18:
                cve, title, sev, _ = r.choice(NON_KEV)
            else:
                (title, sev), cve = r.choice(NOISE_VULNS), None
            if a["asset_type"] == "workstation" and sev == "critical":
                sev = "high"
            st = "open" if r.random() < 0.78 else "resolved"
            age = min(170.0, 0.5 + r.expovariate(1 / 28))
            self.add("vmdr", finding_type="vulnerability", title=title, severity=sev, asset_id=a["asset_id"], cve=cve,
                     status=st, first_seen=(self.as_of - timedelta(days=age)).isoformat())
        # one more KEV deep inside (internal, patched-ish)
        self.add("vmdr", finding_type="vulnerability", title="Atlassian Confluence broken access control", cve="CVE-2023-22515",
                 severity="critical", asset_id=r.choice([s for s in servers if s["exposure"] == "internal"])["asset_id"],
                 first_seen=self.ago(25, 35), compensating_controls=["Network segmentation (internal only)"])
        # EDR
        edr_titles = [("Potentially unwanted application detected", "low"), ("Malicious macro blocked", "medium"),
                      ("LOLBin abuse (rundll32) detected", "medium"), ("Credential dumping attempt blocked (LSASS)", "high"),
                      ("Commodity malware quarantined", "low"), ("Suspicious scheduled task created", "medium")]
        for _ in range(int(r.uniform(120, 180))):
            t, s = r.choice(edr_titles)
            self.add("edr", finding_type="detection", title=t, severity=s, asset_id=r.choice(wks + servers)["asset_id"],
                     status="resolved" if r.random() < 0.85 else "open", first_seen=self.ago(0, 90))
        for a in r.sample(wks, 9):
            self.add("edr", finding_type="coverage_gap", title="EDR sensor missing or offline > 7 days", severity="low",
                     asset_id=a["asset_id"], first_seen=self.ago(8, 40))
        # Identity
        for u in r.sample(users[10:], 14):
            self.add("identity", finding_type="coverage_gap", title="User not registered for MFA", severity="medium",
                     user_id=u["user_id"], first_seen=self.ago(10, 120))
        for u in r.sample(users, 25):
            t, s = r.choice([("Risky sign-in: unfamiliar location", "medium"), ("Legacy authentication sign-in", "medium"),
                             ("Password spray detected", "high"), ("Leaked credentials detected", "high")])
            self.add("identity", finding_type="detection", title=t, severity=s, user_id=u["user_id"],
                     status="resolved" if r.random() < 0.75 else "open", first_seen=self.ago(0, 45))
        for n in range(6):
            self.add("identity", finding_type="misconfiguration", title="Dormant account with group admin rights (> 90 days inactive)",
                     severity="medium", user_id=f"svc-legacy-{n}@{self.dom}", first_seen=self.ago(30, 150))
        # SOC
        for _ in range(int(r.uniform(40, 70))):
            t, s = r.choice([("Brute force against VPN portal", "medium"), ("Anomalous data egress volume", "high"),
                             ("Suspicious OAuth consent grant", "high"), ("Multiple failed privileged logons", "medium"),
                             ("Beaconing to newly registered domain", "high")])
            self.add("soc", finding_type="incident", title=t, severity=s, asset_id=r.choice(servers + wks)["asset_id"],
                     status="resolved" if r.random() < 0.88 else "in_progress", first_seen=self.ago(0, 60))
        self.add("soc", finding_type="coverage_gap", title="Log source silent > 24h: core database audit logs", severity="high",
                 asset_id=self.crown_apps[0]["asset_id"], first_seen=self.ago(1, 3))
        # Email
        for _ in range(int(r.uniform(60, 90))):
            t, s = r.choice([("Credential phishing blocked", "low"), ("BEC impersonation of CFO blocked", "medium"),
                             ("Malicious attachment quarantined", "low"), ("QR-code phishing delivered then removed (ZAP)", "medium")])
            self.add("email", finding_type="detection", title=t, severity=s, user_id=r.choice(users)["user_id"],
                     status="resolved" if r.random() < 0.9 else "open", first_seen=self.ago(0, 30))
        self.add("email", finding_type="misconfiguration", title="DMARC policy not at p=reject for marketing subdomain",
                 severity="medium", entity_keys=[f"domain:mkt.{self.dom}"], first_seen=self.ago(60, 120))
        # Firewall
        for t, s, n in [("Any-any allow rule on DMZ policy", "high", 2), ("Shadowed / unused rules (> 180 days)", "low", 6),
                        ("Firmware below vendor-recommended release", "medium", 3), ("Admin interface reachable from user VLAN", "high", 1)]:
            for _ in range(n):
                self.add("firewall", finding_type="misconfiguration", title=t, severity=s,
                         asset_id=f"{self.code}-fw-{r.randint(1, 6):02d}", first_seen=self.ago(20, 160))
        for _ in range(int(r.uniform(15, 30))):
            a = r.choice([x for x in servers if x["exposure"] == "internet"] or servers)
            self.add("firewall", finding_type="detection", title="IPS: exploit attempt blocked", severity="low",
                     asset_id=a["asset_id"], status="resolved", first_seen=self.ago(0, 20))
        # WAF
        for app in self.crown_apps:
            if app["exposure"] == "internet":
                for _ in range(r.randint(3, 7)):
                    self.add("waf", finding_type="detection", title=r.choice(["SQL injection attempts blocked", "XSS attempts blocked",
                             "Credential stuffing burst mitigated", "Bot scraping mitigated"]), severity="low",
                             asset_id=app["asset_id"], app_id=app["asset_id"], status="resolved", first_seen=self.ago(0, 14))
        self.add("waf", finding_type="coverage_gap", title="Public marketing microsite not behind WAF", severity="medium",
                 asset_id=f"{self.code}-srv-001", first_seen=self.ago(30, 90))
        # Web proxy
        for u in r.sample(users, 12):
            self.add("web_proxy", finding_type="policy_violation", title="Unsanctioned GenAI service in use",
                     severity="low", user_id=u["user_id"], evidence={"tags": ["shadow_ai"]}, first_seen=self.ago(1, 30))
        for _ in range(20):
            self.add("web_proxy", finding_type="detection", title="Malware download blocked", severity="low",
                     user_id=r.choice(users)["user_id"], status="resolved", first_seen=self.ago(0, 30))
        self.add("web_proxy", finding_type="misconfiguration", title="TLS inspection bypass list contains 140 broad categories",
                 severity="medium", first_seen=self.ago(60, 120))
        # ZTNA
        for _ in range(6):
            self.add("ztna", finding_type="policy_violation", title="Unmanaged device accessed private application",
                     severity="medium", user_id=r.choice(users)["user_id"], asset_id=r.choice(self.crown_apps)["asset_id"],
                     first_seen=self.ago(0, 10))
        self.add("ztna", finding_type="coverage_gap", title="Legacy IPsec VPN still used by 212 users", severity="medium",
                 first_seen=self.ago(60, 150))
        # PAM
        for u in users[2:8]:
            self.add("pam", finding_type="policy_violation", title=r.choice(["Privileged session not recorded",
                     "Password rotation failed for privileged account", "Shared admin credential used outside vault"]),
                     severity="medium", user_id=u["user_id"], first_seen=self.ago(3, 40))
        # Cloud
        for t, s, n in [("Security group allows RDP (3389) from 0.0.0.0/0", "high", 2), ("Unencrypted database snapshot", "medium", 4),
                        ("IAM role with wildcard admin permissions", "high", 3), ("Root/break-glass account without MFA", "critical", 1),
                        ("Storage account with public network access", "medium", 5), ("Kubernetes cluster API publicly exposed", "high", 1)]:
            for _ in range(n):
                self.add("cloud", finding_type="misconfiguration", title=t, severity=s,
                         asset_id=f"{self.code}-cloud-{r.randint(1, 4)}", first_seen=self.ago(2, 90))
        # SAST
        for app in self.crown_apps:
            for _ in range(r.randint(4, 12)):
                t, s = r.choice([("SQL injection (tainted input to query)", "high"), ("Hard-coded secret in repository", "high"),
                                 ("Vulnerable open-source dependency", "medium"), ("Insecure deserialization", "high"),
                                 ("Missing output encoding (XSS)", "medium"), ("Weak cryptographic algorithm", "low")])
                self.add("sast", finding_type="vulnerability", title=t, severity=s, app_id=app["asset_id"],
                         asset_id=app["asset_id"], first_seen=self.ago(5, 160))
        # DAST
        for app in self.crown_apps:
            if app["exposure"] == "internet":
                for t, s in [("Missing security headers (CSP, HSTS)", "low"), ("Reflected XSS confirmed", "medium")]:
                    self.add("dast", finding_type="vulnerability", title=t, severity=s, app_id=app["asset_id"],
                             asset_id=app["asset_id"], first_seen=self.ago(10, 90))
        # Brand
        for n in range(r.randint(3, 6)):
            d = f"{self.dom.split('.')[0]}{r.choice(['-support', '-rewards', '-app', 'online', '-offers'])}{n}.example"
            self.add("brand", finding_type="exposure", title=f"Lookalike domain registered: {d}", severity="medium",
                     entity_keys=[f"domain:{d}"], status=r.choice(["open", "resolved", "resolved"]), first_seen=self.ago(2, 40))
        self.add("brand", finding_type="exposure", title="Fake mobile app impersonating brand on third-party store",
                 severity="high", first_seen=self.ago(1, 6))
        self.add("brand", finding_type="exposure", title="Employee credentials found in infostealer logs", severity="high",
                 user_id=users[44]["user_id"], first_seen=self.ago(1, 4),
                 remediation="Reset credentials, revoke tokens, check device for infostealer infection.")
        # AI security
        self.add("ai_security", finding_type="misconfiguration", title="Internal copilot indexes HR folder without access trimming",
                 severity="high", asset_id=f"{self.code}-ai-2", first_seen=self.ago(5, 20))
        self.add("ai_security", finding_type="coverage_gap", title="AI model in production without registered owner or risk assessment",
                 severity="medium", asset_id=f"{self.code}-ai-3", first_seen=self.ago(30, 90))
        # DLP
        for _ in range(r.randint(15, 25)):
            self.add("dlp", finding_type="policy_violation", title=r.choice(["Sensitive file uploaded to personal cloud storage",
                     "Bulk customer export emailed externally", "Card numbers in unencrypted email"]), severity=r.choice(["medium", "low", "high"]),
                     user_id=r.choice(users)["user_id"], status="resolved" if r.random() < 0.6 else "open", first_seen=self.ago(0, 30))
        # OT
        if self.v in OT_VERTICALS:
            ots = [a for a in A if a["asset_type"] == "ot_device"]
            ot_types = {"PLC firmware with public ICS advisory": ("vulnerability", "high"),
                        "Unpatched historian server": ("vulnerability", "medium"),
                        "Default credentials on HMI": ("misconfiguration", "high"),
                        "Flat network: IT-to-OT route without conduit": ("misconfiguration", "medium"),
                        "New device appeared on control network": ("detection", "low"),
                        "Cleartext industrial protocol write from IT subnet": ("detection", "high")}
            weights = [6, 5, 2, 3, 6, 1]
            for _ in range(r.randint(25, 40)):
                t = r.choices(list(ot_types), weights)[0]
                ft, s = ot_types[t]
                self.add("ot", finding_type=ft,
                         title=t, severity=s, asset_id=r.choice(ots)["asset_id"], first_seen=self.ago(2, 150))
        # Backup
        self.add("backup", finding_type="misconfiguration", title="Backup job failures > 3 consecutive days (file services)",
                 severity="medium", asset_id=f"{self.code}-srv-010", first_seen=self.ago(3, 5))
        self.add("backup", finding_type="coverage_gap", title="Quarterly restore test overdue for 4 critical systems",
                 severity="medium", first_seen=self.ago(30, 45))

    # ------------------------------------------------------------------ fraud (financial crime)
    def fraud(self):
        """Cyber-enabled fraud scenarios + fraud-operations noise. Separate RNG so other domains stay stable."""
        if self.v not in FRAUD_VERTICALS:
            return
        r = random.Random(self.meta["seed"] + 7)
        ato_title, who, scam = FRAUD_FLAVOUR[self.v]
        app = next((a for a in self.crown_apps if a["exposure"] == "internet"), self.crown_apps[0])
        look = f"{self.dom.split('.')[0]}-verify-login.example"
        insider = self.users[44]
        # S11 lookalike phishing -> customer account takeover (cyber-enabled fraud)
        self.add("fraud", finding_type="detection", title=f"{ato_title}: 214 {who}, sessions referred from {look}",
                 severity="critical", app_id=app["asset_id"], asset_id=app["asset_id"], entity_keys=[f"domain:{look}"],
                 evidence={"tags": ["ato"], "accounts": 214, "exposed_value": 1_900_000, "currency": "USD"},
                 first_seen=self.ago(0.3, 1.0),
                 remediation="Step-up authentication for affected accounts, hold new-payee transfers, notify customers.")
        # S13 bot-driven credential stuffing against the same app
        self.add("waf", finding_type="detection", title="Credential-stuffing campaign against login API (2.1M attempts / 24h)",
                 severity="high", app_id=app["asset_id"], asset_id=app["asset_id"], first_seen=self.ago(0.5, 1.5),
                 evidence={"attempts_24h": 2_100_000, "success_rate_pct": 0.4},
                 remediation="Enable bot management challenge on login, rate-limit by device fingerprint.")
        # S12 compromised employee credentials -> anomalous payment approval
        self.add("fraud", finding_type="detection", title="Anomalous high-value payment approval by employee (new beneficiary, off-hours)",
                 severity="critical", user_id=insider["user_id"], first_seen=self.ago(0.1, 0.5),
                 evidence={"tags": ["internal"], "exposed_value": 640_000, "currency": "USD", "beneficiary_age_days": 1},
                 remediation="Hold/recall the payment, suspend payment-approval rights, verify with employee out of band.")
        # Mule network -> regulator reporting decision (MLRO) - regulated financial institutions only
        if self.v in ("banking", "fintech"):
            self.add("fraud", finding_type="detection", title="Mule-account network detected: 23 accounts sharing device fingerprints",
                     severity="high", first_seen=self.ago(0.5, 2),
                     evidence={"tags": ["mule"], "accounts": 23, "exposed_value": 1_200_000, "currency": "USD"},
                     remediation="Freeze accounts pending review; MLRO to decide on suspicious transaction report.")
        self.add("fraud", finding_type="detection", title=f"{scam}: 61 victims in 7 days", severity="high",
                 first_seen=self.ago(1, 4), evidence={"tags": ["app_scam"], "exposed_value": 380_000, "currency": "USD"},
                 remediation="Add confirmation-of-payee warning and cooling-off for first-time high-value payees.")
        # fraud-control health issues
        self.add("fraud", finding_type="coverage_gap", title="Instant-payments channel not covered by real-time fraud scoring",
                 severity="high", first_seen=self.ago(20, 45),
                 remediation="Route instant-payment API through the fraud engine before go-live of new limits.")
        self.add("fraud", finding_type="misconfiguration", title="3 high-yield fraud rules disabled after false-positive complaints",
                 severity="medium", first_seen=self.ago(10, 30))
        self.add("fraud", finding_type="misconfiguration", title="Fraud model drift: precision down 18% in 30 days",
                 severity="medium", first_seen=self.ago(3, 10))
        # fraud-ops noise (mostly worked by analysts already)
        titles = [("Card-not-present velocity alert", "low"), ("New payee + high-value transfer", "medium"),
                  ("Device change followed by password reset", "medium"), ("SIM-swap indicator before login", "high"),
                  ("Gift-card bulk purchase pattern", "low"), ("Geo-velocity anomaly on card", "low")]
        for _ in range(r.randint(70, 110)):
            t, sv = r.choice(titles)
            self.add("fraud", finding_type="detection", title=t, severity=sv, user_id=r.choice(self.users)["user_id"],
                     status="resolved" if r.random() < 0.82 else "open", first_seen=(self.as_of - timedelta(days=r.uniform(0, 30))).isoformat())

    # ------------------------------------------------------------------ control health
    def health(self) -> dict[str, dict]:
        r, v = self.r, self.v
        ot = v in OT_VERTICALS
        h = {
            "edr": (93.8, 2, 3, ["14 servers without sensor (mainly legacy Windows 2012)"],
                    {"coverage_pct": 93.8, "sensors_stale": 21, "detections_open": 19, "prevention_policy_pct": 88}),
            "vmdr": (91.0, 6, 1, [], {"scan_coverage_pct": 91.0, "critical_sla_pct": 87.0, "mttr_critical_days": 11.8}),
            "identity": (96.5, 1, 4, ["Legacy authentication still allowed for 3 service accounts"],
                         {"mfa_coverage_pct": 96.5, "risky_users": 7, "stale_accounts": 37, "legacy_auth_signins": 112}),
            "soc": (88.0, 1, 2, ["1 crown-jewel log source silent"],
                    {"incidents_open": 6, "mttd_hours": 3.6, "mttr_hours": 31.0, "log_sources_silent": 3, "attack_coverage_pct": 61}),
            "email": (100.0, 1, 1, [], {"phish_blocked": 18450, "user_clicks": 37, "dmarc_enforced_pct": 83, "phishing_click_rate_pct": 6.2}),
            "firewall": (100.0, 4, 14, ["2 any-any rules in DMZ"], {"risky_rules": 3, "unused_rules": 412, "firmware_outdated": 3}),
            "waf": (86.0, 1, 3, ["2 internet apps in detect-only mode"], {"apps_protected_pct": 86.0, "block_mode_pct": 72.0,
                    "attacks_blocked": 128400, "virtual_patches": 4}),
            "web_proxy": (94.0, 1, 6, [], {"tls_inspection_pct": 71, "malicious_blocked": 9200, "shadow_ai_users": 41, "policy_bypass": 140}),
            "ztna": (78.0, 2, 2, ["Legacy VPN still active"], {"apps_behind_ztna_pct": 78.0, "unmanaged_device_sessions": 34, "legacy_vpn_users": 212}),
            "pam": (88.0, 3, 5, ["Domain admin accounts outside vault"], {"vaulted_pct": 88.0, "standing_admins": 9,
                    "sessions_unrecorded": 27, "rotation_failures": 6}),
            "cloud": (92.0, 1, 9, [], {"critical_misconfigs": 2, "public_buckets": 1, "accounts_covered_pct": 92.0, "secure_score": 64}),
            "sast": (74.0, 20, 2, ["11 repositories not onboarded to scanning"], {"repos_scanned_pct": 74.0, "critical_flaws": 0,
                     "secrets_exposed": 9, "fix_rate_pct": 52}),
            "dast": (63.0, 30, 1, ["APIs not covered by authenticated scans"], {"apps_tested_pct": 63.0, "confirmed_critical": 1, "api_coverage_pct": 40}),
            "brand": (100.0, 2, 0, [], {"lookalikes_active": 5, "takedowns_pending": 3, "brand_takedown_hours": 29.0, "leaked_credentials": 14}),
            "ai_security": (58.0, 4, 2, ["AI inventory incomplete - discovery not enabled for 2 business units"],
                            {"ai_apps_inventoried": 23, "guardrail_blocks": 640, "prompt_injection_attempts": 64, "unsanctioned_ai_apps": 17}),
            "dlp": (84.0, 61, 3, ["Endpoint DLP policy sync failing on 9% of devices"],
                    {"incidents_high": 7, "policy_coverage_pct": 84.0, "genai_uploads_blocked": 211}),
            "backup": (89.0, 3, 1, [], {"immutable_pct": 82.0, "failed_jobs": 4, "restore_tests_passed_pct": 75}),
        }
        if ot:
            h["ot"] = (71.0, 2, 4, ["2 sites without passive OT sensor"], {"ot_assets_visible_pct": 71.0, "unmanaged_remote_access": 2,
                       "critical_ot_vulns": 9, "ics_alerts": 14})
        if v in FRAUD_VERTICALS:
            h["fraud"] = (88.0, 1, 3, ["Instant-payments channel not scored in real time", "3 rules disabled"],
                          {"channel_coverage_pct": 88.0, "alert_backlog_hours": 31.0, "confirmed_loss_30d": 412_000,
                           "prevented_30d": 9_800_000, "detection_rate_pct": 96.0, "false_positive_pct": 91.0,
                           "ato_attempts_7d": 1840, "mule_accounts_detected": 23, "fraud_alerts_open": 340})
        # vertical flavour: jitter so every org looks different
        out = {}
        for d, (cov, fresh, drift, issues, kpis) in h.items():
            j = r.uniform(-2.5, 2.5)
            cov2 = round(max(40.0, min(100.0, cov + j)), 1)
            k2 = dict(kpis)
            for key in list(k2):
                if key.endswith("_pct") and isinstance(k2[key], (int, float)) and key not in ("phishing_click_rate_pct",):
                    k2[key] = round(max(0.0, min(100.0, k2[key] + j)), 1)
            if "coverage_pct" in k2:
                k2["coverage_pct"] = cov2
            out[d] = {"domain": d, "product": PRODUCTS[d], "coverage_pct": cov2, "data_freshness_hours": float(fresh),
                      "policy_drift_items": drift, "health_issues": issues, "kpis": k2}
        return out

    def build(self, crown: list[str]) -> dict:
        self.build_estate(crown)
        self.scenarios()
        self.noise()
        self.fraud()
        health = self.health()
        domains = {}
        for d, items in self.f.items():
            if d not in health:
                continue
            domains[d] = {"findings": items, "health": health[d]}
        return {
            "schema": "lodestar.demo/1",
            "disclaimer": "FICTIONAL demo organisation. All names, hosts, users and domains are invented.",
            "org_name": f"{self.meta['name']} (Demo)", "vertical": self.v, "as_of": self.as_of.isoformat(),
            "assets": self.assets, "users": self.users, "domains": domains,
            "intel": {"kev": sorted(self.kev_set), "epss": self.epss},
        }


PRODUCTS = {
    "edr": "CrowdStrike Falcon", "vmdr": "Qualys VMDR", "identity": "Microsoft Entra ID", "soc": "Microsoft Sentinel",
    "email": "Microsoft Defender for Office 365", "firewall": "Palo Alto Networks NGFW", "waf": "Cloudflare WAF",
    "web_proxy": "Zscaler Internet Access", "ztna": "Zscaler Private Access", "pam": "CyberArk PAM",
    "cloud": "Wiz CNAPP", "sast": "Checkmarx One", "dast": "Invicti", "brand": "Recorded Future Brand Intelligence",
    "ai_security": "Prompt Security", "dlp": "Microsoft Purview DLP", "ot": "Claroty xDome", "backup": "Rubrik Security Cloud",
    "fraud": "Feedzai",
}


# ---------------------------------------------------------------------- history
def synth_history(current: dict, days: int, seed: int, as_of: datetime) -> list[dict]:
    """Back-fill daily snapshots that trend realistically into today's values.

    Story arc: posture ~14 points lower 6 months ago, a dip ~55 days ago
    (incident / big vuln disclosure), steady improvement since.
    """
    r = random.Random(seed)
    out = []
    p_now = current["posture_score"]
    for i in range(days, 0, -1):
        date = (as_of - timedelta(days=i)).date().isoformat()
        prog = 1 - i / days                         # 0 -> 1 over the window
        dip = 7.0 if 48 <= i <= 62 else (3.5 if 40 <= i < 48 else 0.0)
        posture = round(p_now - 14 * (1 - prog) - dip + r.uniform(-1.2, 1.2), 1)
        f = 1 + 0.9 * (1 - prog) + (0.5 if dip else 0)      # factor for "bad" counts
        hz = {k: max(0, int(round(v * f * r.uniform(0.9, 1.1)))) for k, v in current["open_by_horizon"].items()}
        sev = {k: max(0, int(round(v * (1 + 0.45 * (1 - prog)) * r.uniform(0.95, 1.05)))) for k, v in current["open_by_severity"].items()}
        dom = {k: max(0, int(round(v * (1 + 0.4 * (1 - prog)) * r.uniform(0.93, 1.07)))) for k, v in current["open_by_domain"].items()}
        kris = {}
        for k, v in current["kris"].items():
            if k.endswith("_pct") and k != "phishing_click_rate_pct":
                kris[k] = round(max(0.0, min(100.0, v - 9 * (1 - prog) - dip * 0.4 + r.uniform(-0.6, 0.6))), 1)
            elif k == "posture_score":
                kris[k] = posture
            else:
                val = max(0.0, v * (1 + 0.8 * (1 - prog)) * r.uniform(0.92, 1.08) + (1 if dip else 0))
                is_count = k.endswith("_count") or k in ("toxic_combinations_open", "shadow_ai_users")
                kris[k] = float(round(val)) if is_count else round(val, 1)
        ctl = {k: round(max(0.0, min(100.0, v - 10 * (1 - prog) + r.uniform(-1, 1))), 1)
               for k, v in current["control_effectiveness"].items()}
        out.append({
            "date": date, "posture_score": posture, "open_by_horizon": hz, "open_by_severity": sev, "open_by_domain": dom,
            "sla_breaches": int(round(current["sla_breaches"] * f * r.uniform(0.9, 1.1))),
            "new_findings": int(r.uniform(25, 60) * (1.6 if dip else 1)),
            "closed_findings": int(r.uniform(25, 65) * (0.8 + 0.4 * prog)),
            "mttr_days": {"critical": kris.get("mttr_critical_days", 0)}, "mttd_hours": kris.get("mttd_hours", 0),
            "control_effectiveness": ctl, "kris": kris,
            "incidents": int(max(0, current["incidents"] * f * r.uniform(0.7, 1.3) + (4 if dip else 0))),
        })
    return out


def generate(vertical: str, out_dir: Path, as_of: datetime | None = None, history_days: int = 180) -> Path:
    from ..config import load_settings
    from ..orchestrator import Orchestrator
    from ..store import Store
    from ..verticals import load_vertical

    as_of = as_of or datetime.now(timezone.utc).replace(hour=2, minute=0, second=0, microsecond=0)
    prof = load_vertical(vertical)
    ds = Gen(vertical, as_of).build(prof.crown_jewel_services)
    # dry-run the real pipeline (in-memory store) to get today's numbers, then back-fill history
    settings = load_settings(overrides={"mode": "demo", "deployment_phase": 4})
    tmp = Store(out_dir / f".tmp_{vertical}.db")
    try:
        res = Orchestrator(settings, store=tmp, dataset=ds).run(persist=False)
    finally:
        try:
            (out_dir / f".tmp_{vertical}.db").unlink()
            for suffix in ("-wal", "-shm"):
                p = out_dir / f".tmp_{vertical}.db{suffix}"
                if p.exists():
                    p.unlink()
        except OSError:
            pass
    ds["history"] = synth_history(res.snapshot.model_dump(), history_days, ORGS[vertical]["seed"], as_of)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{vertical}.json"
    path.write_text(json.dumps(ds, indent=1, default=str), encoding="utf-8")
    return path


def generate_all(out_dir: Path, as_of: datetime | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    return [generate(v, out_dir, as_of) for v in ORGS]
