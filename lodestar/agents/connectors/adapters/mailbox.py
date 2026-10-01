"""Advisory / alert / researcher-report e-mails from a dedicated, read-only mailbox.

Typical senders: national CERT / NCSC, sector ISAC, regulator circulars, vendor PSIRT
notifications, MSSP alerts, HackerOne / VDP (security@) notifications.

Modes
  imap  : IMAP over TLS, mailbox opened READ-ONLY (settings: imap_host, imap_user, imap_password, folder)
  graph : Microsoft Graph, application permission Mail.Read restricted to this one mailbox with an
          Exchange ApplicationAccessPolicy (settings: tenant_id, client_id, client_secret, mailbox)
  path  : folder of .eml files (offline / air-gapped import, demos, tests)

Safety
  * only allow-listed senders are processed; everything else is counted and ignored
  * DKIM/SPF result from Authentication-Results is checked; unverified mail is kept but tagged
    `unverified_sender` and capped at medium severity
  * links are never followed, HTML is stripped, only small CSAF/STIX JSON attachments are parsed
  * TLP marking in subject/body is carried onto the finding (TLP:RED never leaves the dashboard)
  * content is parsed deterministically (no LLM), so prompt-injection text in e-mails has no effect

senders: [{match: "@ncsc.example", kind: advisory, source: "National CERT"},
          {match: "@hackerone.com", kind: bug_bounty, source: "HackerOne"},
          {match: "security-alerts@mssp.example", kind: alert, source: "MSSP"}]
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from ....models import ControlHealth, Domain, Finding, FindingType, Severity
from .base import Adapter, AdapterResult, http_client, request_with_retry
from .intel_common import CVE_RE, advisory_finding, extract_iocs, refang, severity_from_cvss, severity_from_text, tlp_of

CVSS_RE = re.compile(r"CVSS(?:v3(?:\.\d)?)?[^0-9]{0,20}(\d{1,2}\.\d)", re.I)
HOST_RE = re.compile(r"https?://([a-z0-9.-]+)", re.I)
TAG_RE = re.compile(r"<[^>]+>")
MAX_ATTACH = 2 * 1024 * 1024
SECTOR_WORDS = {"energy": "energy", "electric": "utilities", "water": "utilities", "utilities": "utilities",
                "financial": "financial-services", "banking": "financial-services", "telecommunication": "telecommunications",
                "aviation": "aviation", "airport": "aviation", "maritime": "maritime", "port ": "maritime",
                "transport": "transportation", "oil and gas": "energy", "retail": "retail", "government": "government-national"}


def _text(msg) -> str:
    part = msg.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else ""
    return TAG_RE.sub(" ", body) if part and part.get_content_type() == "text/html" else body


def _attachments(msg) -> list[dict]:
    out = []
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        data = part.get_payload(decode=True) or b""
        if name.endswith(".json") and len(data) <= MAX_ATTACH:
            try:
                out.append(json.loads(data))
            except ValueError:
                continue
    return out


def classify(sender: str, rules: list[dict]) -> dict | None:
    s = sender.lower()
    return next((r for r in rules if r.get("match", "").lower() in s), None)


def parse_message(raw: bytes, rules: list[dict], require_auth: bool = True) -> tuple[list[Finding], str]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    sender = parseaddr(msg.get("From", ""))[1]
    rule = classify(sender, rules)
    if not rule:
        return [], "ignored_sender"
    subject = str(msg.get("Subject", ""))
    try:
        when = parsedate_to_datetime(msg.get("Date")) if msg.get("Date") else datetime.now(timezone.utc)
    except (TypeError, ValueError):
        when = datetime.now(timezone.utc)
    body = _text(msg)
    auth = str(msg.get("Authentication-Results", "")).lower()
    verified = ("dkim=pass" in auth or "spf=pass" in auth) if require_auth else True
    text = f"{subject}\n{body}"
    tlp = tlp_of(text)
    cvss = [float(x) for x in CVSS_RE.findall(text)]
    sev = severity_from_cvss(max(cvss)) if cvss else severity_from_text(subject)
    if not verified and sev in (Severity.CRITICAL, Severity.HIGH):
        sev = Severity.MEDIUM
    tags = [] if verified else ["unverified_sender"]
    kind = rule.get("kind", "advisory")
    source = rule.get("source", sender)
    if kind == "bug_bounty":
        hosts = [h.lower() for h in HOST_RE.findall(refang(body)) if "hackerone.com" not in h.lower()]
        fid = "bug_bounty-mail-" + hashlib.sha1(f"{sender}|{subject}".encode()).hexdigest()[:12]
        return [Finding(finding_id=fid, domain=Domain.BUG_BOUNTY, source=f"{source} (e-mail)", finding_type=FindingType.VULNERABILITY,
                        title=subject[:300], severity=sev, asset_id=hosts[0] if hosts else None, app_id=hosts[0] if hosts else None,
                        first_seen=when, last_seen=when, tlp=tlp,
                        evidence={"tags": ["researcher_report"] + tags, "state": "new", "sender": sender, "source_kind": "email"},
                        remediation="Acknowledge the researcher, triage and reproduce; do not discuss bounty in the first reply.")], "ok"
    low = text.lower()
    sectors = sorted({v for k, v in SECTOR_WORDS.items() if k in low})
    findings = [advisory_finding(
        source=f"{source} (e-mail)", source_kind="email", title=subject, description=body[:2000], severity=sev, published=when,
        cves=CVE_RE.findall(text), sectors=sectors, iocs=extract_iocs(body),
        exploited=any(w in low for w in ("actively exploited", "exploited in the wild", "active exploitation", "under attack")),
        tlp=tlp, advisory_id=str(msg.get("Message-ID", "")) or None)]
    for f in findings:
        f.evidence["tags"] += tags + ([kind] if kind != "advisory" else [])
    from .csaf import parse_csaf  # attached machine-readable advisories
    for att in _attachments(msg):
        if "document" in att and verified:
            findings.append(parse_csaf(att, f"{source} (e-mail attachment)"))
    return findings, "ok"


class MailboxAdapter(Adapter):
    name = "mailbox"
    supported_domains = (Domain.THREAT_INTEL, Domain.BUG_BOUNTY)

    def _raw_messages(self, ctx) -> list[bytes]:
        mode = self.settings.get("mode", "path")
        since = datetime.now(timezone.utc) - timedelta(days=int(self.settings.get("lookback_days", 7)))
        limit = int(self.settings.get("max_messages", 200))
        if mode == "path":
            folder = Path(self.settings["path"])
            folder = folder if folder.is_absolute() else ctx.settings.path(folder)
            return [p.read_bytes() for p in sorted(folder.glob("*.eml"))[:limit]]
        if mode == "imap":
            import imaplib
            self.require("imap_host", "imap_user", "imap_password")
            out = []
            with imaplib.IMAP4_SSL(self.settings["imap_host"], int(self.settings.get("imap_port", 993))) as m:
                m.login(self.settings["imap_user"], self.settings["imap_password"])
                m.select(self.settings.get("folder", "INBOX"), readonly=True)
                _, ids = m.search(None, "SINCE", since.strftime("%d-%b-%Y"))
                for i in ids[0].split()[-limit:]:
                    _, data = m.fetch(i, "(BODY.PEEK[])")
                    out.append(data[0][1])
            return out
        if mode == "graph":
            from .ms_graph_security import GRAPH, get_token
            self.require("tenant_id", "client_id", "client_secret", "mailbox")
            out = []
            with http_client(60) as c:
                tok = get_token(c, self.settings["tenant_id"], self.settings["client_id"], self.settings["client_secret"])
                h = {"Authorization": f"Bearer {tok}"}
                url = f"{GRAPH}/users/{self.settings['mailbox']}/mailFolders/inbox/messages"
                params = {"$filter": f"receivedDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}", "$select": "id", "$top": 50}
                while url and len(out) < limit:
                    data = request_with_retry(c, "GET", url, params=params, headers=h).json()
                    for m in data.get("value", []):
                        out.append(request_with_retry(c, "GET", f"{GRAPH}/users/{self.settings['mailbox']}/messages/{m['id']}/$value",
                                                      headers=h).content)
                    url, params = data.get("@odata.nextLink"), None
            return out
        raise ValueError(f"mailbox mode must be path, imap or graph (got {mode})")

    def fetch(self, ctx) -> AdapterResult:
        rules = self.settings.get("senders") or []
        findings, counts = [], {"ok": 0, "ignored_sender": 0, "unverified": 0}
        for raw in self._raw_messages(ctx):
            fs, outcome = parse_message(raw, rules, bool(self.settings.get("require_dkim", True)))
            counts[outcome] = counts.get(outcome, 0) + 1
            for f in fs:
                if f.domain != self.domain:
                    continue
                counts["unverified"] += "unverified_sender" in f.evidence.get("tags", [])
                findings.append(f)
        return AdapterResult(findings=findings, health=ControlHealth(
            domain=self.domain, product=self.product or "Advisory mailbox", coverage_pct=100.0, data_freshness_hours=0.0,
            kpis={"emails_processed": counts["ok"], "emails_ignored": counts["ignored_sender"],
                  "unverified_senders": counts["unverified"]},
            health_issues=[f"{counts['unverified']} message(s) failed DKIM/SPF"] if counts["unverified"] else []))
