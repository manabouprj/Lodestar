"""CorrelationAgent (Phase 2) - finds 'toxic combinations'.

Individual tools each say "medium". Together they describe an attack path.
Each rule has 2+ legs; a leg is a predicate over findings. Legs are joined on
a shared entity key (asset, user, app or arbitrary entity key such as a
domain name). When every leg matches for the same entity a Correlation is
raised and all contributing findings receive an attack-path boost.

Rules are data-like and easy to extend - see RULES at the bottom.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from ...models import Correlation, Domain, Exposure, Finding, FindingType, Severity, Status
from ..base import AgentContext, BaseAgent, PipelineState

Pred = Callable[[Finding, dict], bool]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    join: str                       # asset | user | app | key
    legs: tuple[Pred, ...]
    severity: Severity
    narrative: str
    action: str
    mitre: tuple[str, ...] = ()
    min_domains: int = 2


def _keys(f: Finding, join: str) -> list[str]:
    if join == "asset":
        return [f.asset_id] if f.asset_id else []
    if join == "user":
        return [f.user_id] if f.user_id else []
    if join == "app":
        return [f.app_id] if f.app_id else []
    return list(f.entity_keys)


def d(*domains: Domain) -> Pred:
    return lambda f, a: f.domain in domains


def all_of(*preds: Pred) -> Pred:
    return lambda f, a: all(p(f, a) for p in preds)


def ftype(*types: FindingType) -> Pred:
    return lambda f, a: f.finding_type in types


def sev_at_least(s: Severity) -> Pred:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return lambda f, a: order.index(f.severity) >= order.index(s)


def tag(t: str) -> Pred:
    return lambda f, a: t in f.evidence.get("tags", [])


def internet(f: Finding, assets: dict) -> bool:
    a = assets.get(f.asset_id)
    return bool(a and a.exposure == Exposure.INTERNET)


def kev(f: Finding, a) -> bool:
    return f.kev


def asset_crit_at_least(n: int) -> Pred:
    return lambda f, assets: bool(f.asset_id in assets and assets[f.asset_id].criticality >= n)


RULES: tuple[Rule, ...] = (
    Rule("LDS-001", "Known-exploited vulnerability under active attack on internet-facing asset", "asset",
         (all_of(d(Domain.VMDR), kev, internet),
          all_of(d(Domain.WAF, Domain.FIREWALL, Domain.SOC, Domain.EDR), ftype(FindingType.DETECTION))),
         Severity.CRITICAL,
         "An internet-facing system has a CISA-KEV vulnerability AND perimeter/SOC telemetry shows attack traffic against it.",
         "Emergency patch or isolate within 24h; apply WAF/IPS virtual patch immediately; hunt for compromise.",
         ("T1190",)),
    Rule("LDS-002", "Blind spot: vulnerable asset without EDR", "asset",
         (all_of(d(Domain.EDR), ftype(FindingType.COVERAGE_GAP)),
          all_of(d(Domain.VMDR), sev_at_least(Severity.HIGH), asset_crit_at_least(3))),
         Severity.HIGH,
         "A host with high/critical vulnerabilities has no functioning EDR sensor - exploitation would go undetected.",
         "Deploy/repair EDR sensor and prioritise patching; add to SOC watchlist until covered.",
         ("T1562.001",)),
    Rule("LDS-003", "Privileged account takeover risk", "user",
         (all_of(d(Domain.IDENTITY), ftype(FindingType.DETECTION)),
          all_of(d(Domain.PAM), ftype(FindingType.POLICY_VIOLATION, FindingType.COVERAGE_GAP, FindingType.MISCONFIGURATION))),
         Severity.CRITICAL,
         "A privileged identity shows risky sign-in behaviour AND sits outside PAM controls (unvaulted / standing privilege).",
         "Force credential reset, revoke sessions, onboard account to PAM vault with JIT access today.",
         ("T1078.002", "T1621")),
    Rule("LDS-004", "Phishing click followed by endpoint detection", "user",
         (all_of(d(Domain.EMAIL), tag("user_clicked")),
          all_of(d(Domain.EDR), ftype(FindingType.DETECTION))),
         Severity.HIGH,
         "A user clicked a malicious email link and the EDR then raised a detection on their device - likely initial access.",
         "Isolate endpoint, reset credentials, search mailboxes for the same campaign and purge.",
         ("T1566.002", "T1204")),
    Rule("LDS-005", "Active brand impersonation campaign", "key",
         (all_of(d(Domain.BRAND), ftype(FindingType.EXPOSURE)),
          all_of(d(Domain.EMAIL, Domain.WEB_PROXY), ftype(FindingType.DETECTION))),
         Severity.HIGH,
         "A lookalike domain is live AND is being used in phishing / web traffic against our users or customers.",
         "Request takedown, block domain on email/proxy/DNS, notify customers and fraud team.",
         ("T1583.001", "T1566")),
    Rule("LDS-006", "Sensitive data exposed in public cloud storage", "asset",
         (all_of(d(Domain.CLOUD), ftype(FindingType.MISCONFIGURATION), sev_at_least(Severity.HIGH)),
          all_of(d(Domain.DLP))),
         Severity.CRITICAL,
         "A cloud storage resource is publicly accessible AND DLP classification shows it holds sensitive data.",
         "Remove public access now, review access logs for exfiltration, assess breach-notification obligations.",
         ("T1530",)),
    Rule("LDS-007", "Sensitive data flowing to unsanctioned GenAI", "user",
         (all_of(d(Domain.WEB_PROXY, Domain.AI_SECURITY), tag("shadow_ai")),
          all_of(d(Domain.DLP), ftype(FindingType.POLICY_VIOLATION))),
         Severity.HIGH,
         "A user is using an unsanctioned AI service AND DLP recorded sensitive data uploads - AI data leakage.",
         "Block the AI app, route user to the sanctioned enterprise AI tool, review uploaded content with data owner.",
         ("T1567",)),
    Rule("LDS-008", "Exploitable application flaw not shielded by WAF", "app",
         (all_of(d(Domain.SAST, Domain.DAST), sev_at_least(Severity.HIGH)),
          all_of(d(Domain.WAF), ftype(FindingType.MISCONFIGURATION, FindingType.COVERAGE_GAP))),
         Severity.HIGH,
         "A high/critical application vulnerability exists AND the application is unprotected or in detect-only WAF mode.",
         "Switch WAF to blocking with a virtual patch rule; fast-track the code fix through the release pipeline.",
         ("T1190",)),
    Rule("LDS-009", "Unmanaged remote access into OT", "asset",
         (all_of(d(Domain.OT), tag("remote_access")),
          all_of(d(Domain.OT, Domain.VMDR, Domain.ZTNA, Domain.FIREWALL), sev_at_least(Severity.HIGH))),
         Severity.CRITICAL,
         "An OT asset is reachable via unmanaged vendor remote access AND carries high-risk weaknesses.",
         "Disable direct access; force vendor sessions through ZTNA/PAM jump host with recording and approval.",
         ("T0822", "T0866"), min_domains=1),
    Rule("LDS-010", "Ransomware blast radius: crown jewel without immutable backup", "asset",
         (all_of(d(Domain.BACKUP), ftype(FindingType.COVERAGE_GAP, FindingType.MISCONFIGURATION)),
          all_of(d(Domain.EDR, Domain.VMDR), sev_at_least(Severity.HIGH))),
         Severity.HIGH,
         "A critical system has no immutable backup AND has active threats or exploitable vulnerabilities.",
         "Enable immutable/air-gapped backup and run a restore test this week; remediate the exposure.",
         ("T1486", "T1490")),
    # ---- cyber-enabled fraud (financial institutions, wallets, loyalty, telco) ----
    Rule("LDS-011", "Cyber-enabled fraud: lookalike phishing driving customer account takeover", "key",
         (all_of(d(Domain.BRAND), ftype(FindingType.EXPOSURE)),
          all_of(d(Domain.FRAUD), tag("ato"))),
         Severity.CRITICAL,
         "A live lookalike domain is harvesting credentials AND the fraud engine sees account takeover from sessions "
         "referred by that domain - cyber and fraud teams are looking at the same campaign.",
         "Joint cyber-fraud response: takedown + block the domain, step-up authentication and payment holds for "
         "affected accounts, customer notification.", ("T1566.002", "T1078")),
    Rule("LDS-012", "Compromised employee credentials linked to anomalous payment", "user",
         (all_of(d(Domain.BRAND, Domain.IDENTITY), ftype(FindingType.EXPOSURE, FindingType.DETECTION)),
          all_of(d(Domain.FRAUD), tag("internal"))),
         Severity.CRITICAL,
         "An employee's credentials are exposed or used riskily AND the same identity approved an anomalous payment - "
         "insider fraud or account misuse.",
         "Hold or recall the payment, suspend the employee's payment rights, reset credentials, preserve evidence.",
         ("T1078", "T1657")),
    Rule("LDS-013", "Bot-driven account takeover on a customer channel", "app",
         (all_of(d(Domain.WAF), ftype(FindingType.DETECTION), sev_at_least(Severity.HIGH)),
          all_of(d(Domain.FRAUD), tag("ato"))),
         Severity.HIGH,
         "Credential stuffing against a customer-facing login AND confirmed account-takeover activity on the same channel.",
         "Turn on bot management and device-bound step-up for the login; reset affected customer credentials.",
         ("T1110.004",)),
)


class CorrelationAgent(BaseAgent):
    name = "CorrelationAgent"
    phase = 2
    description = "Joins signals across controls into attack paths ('toxic combinations')."

    def __init__(self, rules: tuple[Rule, ...] = RULES):
        self.rules = rules

    def run(self, ctx: AgentContext, state: PipelineState) -> PipelineState:
        assets = state.assets
        live = [f for f in state.findings if f.status in (Status.OPEN, Status.IN_PROGRESS)]
        out: list[Correlation] = []
        for rule in self.rules:
            index: dict[str, list[list[Finding]]] = defaultdict(lambda n=len(rule.legs): [[] for _ in range(n)])
            for f in live:
                for i, leg in enumerate(rule.legs):
                    if leg(f, assets):
                        for k in _keys(f, rule.join):
                            index[k][i].append(f)
            for entity, legs in index.items():
                if not all(legs):
                    continue
                members = {f.finding_id: f for leg in legs for f in leg}
                domains = sorted({f.domain for f in members.values()}, key=lambda x: x.value)
                if len(domains) < rule.min_domains or len(members) < 2:
                    continue
                cid = "COR-" + hashlib.sha1(f"{rule.rule_id}|{entity}".encode()).hexdigest()[:10]
                for f in members.values():
                    if cid not in f.correlation_ids:
                        f.correlation_ids.append(cid)
                asset = assets.get(entity)
                if asset:
                    label = asset.name if not asset.business_service or asset.business_service in asset.name \
                        else f"{asset.name} - {asset.business_service}"
                else:
                    label = entity.split(":", 1)[1] if ":" in entity else entity
                out.append(Correlation(
                    correlation_id=cid, rule_id=rule.rule_id, title=rule.title, narrative=rule.narrative,
                    severity=rule.severity, finding_ids=sorted(members), domains=list(domains), entity=label,
                    recommended_action=rule.action, mitre=list(rule.mitre)))
        state.correlations = out
        return state
