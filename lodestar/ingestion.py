"""Ingestion validation rules - shared by the one-off sanity test (`lodestar check-ingestion`) and the
continuous IngestionMonitorAgent that runs inside every pipeline run.

Expectations come from three levels (later wins):
  1. DEFAULT_EXPECT below
  2. ingestion.expect                      in lodestar.yaml (deployment-wide)
  3. connectors.<domain>.expect            and connectors.<domain>.sources[n].expect

    expect:
      min_items: 1             fewer items than this from a successful fetch -> FAIL (0 = no minimum)
      max_items: 50000         more items than this -> WARN (runaway query / wrong filter)
      max_age_hours: 24        no successful fetch, or the source's own data older than this -> stale
                               (default: max(24h, 3 x the source's cadence))
      max_silence_hours: 12    fetches succeed but return no items for this long -> stale (off by default;
                               set it for always-busy sources: SOC alerts, EDR detections, proxy, firewall)
      asset_match_pct: 50      share of asset-bearing findings that must resolve to the CMDB
      max_unmapped_pct: 20     share of rows allowed to fall back to "Untitled finding" (field_map broken)
      failing_after: 2         consecutive failed fetches before a source is "failing" (alerted)
      volume_drop_pct: 80      snapshot sources: alert when a pull is this much below the recent median
      volume_spike_x: 5        snapshot sources: alert when a pull is this many times the recent median
      baseline_runs: 14        how many recent pulls form the volume baseline (needs at least 5)

Source states (continuous): healthy | degraded | retrying | failing | stale | volume_drop | volume_spike |
awaiting_data. Only failing, stale and volume_drop raise findings and alerts by default.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

from .agents.connectors.domains import default_cadence

DEFAULT_EXPECT: dict[str, Any] = {
    "min_items": 0, "max_items": None, "max_age_hours": None, "max_silence_hours": None, "asset_match_pct": 50, "max_unmapped_pct": 20,
    "failing_after": 2, "volume_drop_pct": 80, "volume_spike_x": 5, "baseline_runs": 14,
}
ALERT_STATES = ("failing", "stale", "volume_drop")
BAD_STATES = ("failing", "stale", "volume_drop", "volume_spike", "degraded")
STATE_RANK = {"healthy": 0, "awaiting_data": 1, "retrying": 2, "degraded": 3, "volume_spike": 4, "volume_drop": 5,
              "stale": 6, "failing": 7}
UNTITLED = "Untitled finding"


@dataclass
class Check:
    name: str
    status: str          # pass | warn | fail
    detail: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def expectations(settings, info: dict[str, Any]) -> dict[str, Any]:
    glob = ((settings.raw.get("ingestion") or {}).get("expect") or {}) if settings is not None else {}
    return {**DEFAULT_EXPECT, **glob, **(info.get("expect") or {})}


def max_age_hours(exp: dict[str, Any], info: dict[str, Any]) -> float:
    if exp.get("max_age_hours"):
        return float(exp["max_age_hours"])
    cadence = info.get("cadence_minutes") or info.get("interval_minutes") or default_cadence(info.get("domain", "soc"))
    return max(24.0, 3 * cadence / 60)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def quality_checks(info: dict[str, Any], findings: list, assets: dict, exp: dict[str, Any], now: datetime) -> list[Check]:
    """Checks on one fetch of one source (what the sanity test prints and the monitor evaluates)."""
    out: list[Check] = []
    status = info.get("status")
    if status == "failed":
        return [Check("fetch", "fail", f"fetch failed: {info.get('error', '')[:200]}")]
    if status == "skipped":
        return [Check("fetch", "pass", f"not due ({info.get('reason', '')})")]
    warnings = [str(w) for w in info.get("warnings") or []]
    if status == "no_data":
        hint = next((w for w in warnings if "no " in w.lower()), "the source returned nothing")
        return [Check("fetch", "warn", f"connected but no data: {hint}")]
    n = int(info.get("items") or 0)
    out.append(Check("fetch", "pass", f"{n} item(s), {info.get('mode')} sync"))

    lo, hi = int(exp.get("min_items") or 0), exp.get("max_items")
    if lo and n < lo:
        out.append(Check("volume", "fail", f"{n} item(s), expected at least {lo}"))
    elif hi and n > int(hi):
        out.append(Check("volume", "warn", f"{n} item(s), expected at most {hi} - query or filter too broad?"))
    else:
        out.append(Check("volume", "pass", f"{n} item(s) within bounds"))

    drift = [w for w in warnings if w.startswith("schema drift")]
    sev = [w for w in warnings if w.startswith("unknown severity")]
    rejected = [w for w in warnings if w.startswith("rejected")]
    untitled = sum(1 for f in findings if f.title == UNTITLED)
    pct = round(100 * untitled / len(findings), 1) if findings else 0.0
    if drift:
        out.append(Check("schema", "warn", "; ".join(drift)[:300]))
    elif findings:
        out.append(Check("schema", "pass", "every mapped column present"))
    if pct > float(exp.get("max_unmapped_pct", 20)):
        out.append(Check("mapping", "warn", f"{pct}% of rows have no title - check field_map.title"))
    elif sev or rejected:
        out.append(Check("mapping", "warn", "; ".join(sev + rejected)[:300]))
    elif findings:
        out.append(Check("mapping", "pass", "titles and severities mapped"))

    with_asset = [f for f in findings if f.asset_id]
    if with_asset:
        matched = sum(1 for f in with_asset if f.asset_id in assets)
        mp = round(100 * matched / len(with_asset), 1)
        need = float(exp.get("asset_match_pct", 50))
        out.append(Check("entities", "pass" if mp >= need or not assets else "warn",
                         f"{mp}% of {len(with_asset)} asset-bearing items match the CMDB (expected >= {need:g}%)"
                         + ("" if assets else " - no CMDB loaded")))

    limit = max_age_hours(exp, info)
    fresh = (info.get("health") or {}).get("data_freshness_hours")
    future = [f for f in findings if _aware(f.first_seen) > now + timedelta(hours=1)]
    if future:
        out.append(Check("timestamps", "warn", f"{len(future)} item(s) dated in the future - time zone or epoch unit wrong"))
    if fresh is not None and fresh > limit:
        out.append(Check("freshness", "warn", f"source data is {fresh:.0f}h old (expected within {limit:.0f}h)"))
    elif fresh is not None:
        out.append(Check("freshness", "pass", f"source data {fresh:.1f}h old"))
    if info.get("health") is None:
        out.append(Check("telemetry", "warn", "no control-health telemetry (coverage) from this source"))
    return out


def volume_state(history: list[dict[str, Any]], current: int, exp: dict[str, Any]) -> tuple[str | None, str]:
    """history = previous successful pulls (newest first), excluding this one."""
    base = [h["items"] for h in history if h.get("status") == "ok" and h.get("items") is not None]
    base = base[: int(exp.get("baseline_runs", 14))]
    if len(base) < 5:
        return None, ""
    m = median(base)
    if m < 10:
        return None, ""
    drop = float(exp.get("volume_drop_pct", 80))
    if current < m * (1 - drop / 100):
        return "volume_drop", f"{current} items vs a median of {m:g} over the last {len(base)} pulls"
    if current > m * float(exp.get("volume_spike_x", 5)):
        return "volume_spike", f"{current} items vs a median of {m:g} over the last {len(base)} pulls"
    return None, ""


def classify(info: dict[str, Any], st: dict[str, Any], checks: list[Check], history: list[dict[str, Any]],
             exp: dict[str, Any], now: datetime, prev: dict[str, Any] | None = None) -> tuple[str, str]:
    """Continuous state of one source after this run."""
    status = info.get("status")
    failures = int(st.get("failures") or info.get("consecutive_failures") or 0)
    last = st.get("last_success")
    age = (now - _aware(last)).total_seconds() / 3600 if last else None
    limit = max_age_hours(exp, info)
    if status == "failed":
        if failures >= int(exp.get("failing_after", 2)):
            return "failing", f"{failures} consecutive failed fetches: {str(info.get('error', ''))[:160]}"
        return "retrying", f"fetch failed ({failures}x, alert after {exp.get('failing_after', 2)}): {str(info.get('error', ''))[:120]}"
    if last is None:
        return "awaiting_data", "no successful fetch yet"
    if age is not None and age > limit:
        return "stale", f"no successful fetch for {age:.0f}h (expected within {limit:.0f}h)"
    silence = exp.get("max_silence_hours")
    quiet_since = st.get("last_items_at")
    if silence and status in ("ok", "no_data") and not info.get("items") and quiet_since:
        quiet = (now - _aware(quiet_since)).total_seconds() / 3600
        if quiet > float(silence):
            return "stale", f"no items for {quiet:.0f}h although fetches succeed (max_silence_hours {float(silence):g})"
    if status == "skipped":
        prev_state = (prev or {}).get("state")
        return (prev_state, (prev or {}).get("detail", "")) if prev_state and prev_state not in ("retrying",) else ("healthy", "")
    fresh = next((c for c in checks if c.name == "freshness" and c.status != "pass"), None)
    if fresh:
        return "stale", fresh.detail
    if status == "ok" and info.get("mode") == "snapshot":
        vs, detail = volume_state(history, int(info.get("items") or 0), exp)
        if vs:
            return vs, detail
    bad = [c for c in checks if c.status == "fail"] + [c for c in checks if c.status == "warn" and c.name in ("schema", "mapping", "volume")]
    if bad:
        return "degraded", "; ".join(f"{c.name}: {c.detail}" for c in bad)[:240]
    return "healthy", ""


def sanity_check(settings, domain: str | None = None, full: bool = False, store=None) -> dict[str, Any]:
    """Live, one-off ingestion sanity test (`lodestar check-ingestion`, MCP `check_ingestion`).
    Fetches every enabled source (or one domain) right now, ignoring cadences, maps and entity-resolves the
    rows, and grades each source PASS / WARN / FAIL. Nothing is stored: no cursors, no findings, no state.
    full=True ignores the stored sync cursors and reads the whole lookback window."""
    from .agents.base import AgentContext, PipelineState
    from .agents.connectors import build_connector_agents
    from .agents.core import AssetContextAgent, DataQualityAgent
    from .orchestrator import load_dataset
    from .store import Store
    from .verticals import load_vertical
    agents = [a for a in build_connector_agents(settings, 4) if domain in (None, a.spec.domain.value)]
    dataset = load_dataset(settings.demo_dataset) if settings.mode == "demo" else None
    if dataset:
        settings.org_name = dataset.get("org_name", settings.org_name)
    now = datetime.now(timezone.utc)
    store = store or Store(settings.sqlite_path)
    ctx = AgentContext(settings=settings, vertical=load_vertical(dataset.get("vertical") if dataset else settings.vertical),
                       now=now, dataset=dataset, store=store, dry_run=True, force=True, ignore_cursor=full)
    st = PipelineState()
    for agent in (AssetContextAgent(), *agents, DataQualityAgent()):
        st = agent(ctx, st)
    by_src: dict[str, list] = {}
    for f in st.findings:
        by_src.setdefault(f.evidence.get("_src", ""), []).append(f)
    out: dict[str, Any] = {}
    for key, info in (st.data_quality.get("sources") or {}).items():
        if "adapter" not in info:
            continue
        exp = expectations(settings, info)
        checks = quality_checks(info, by_src.get(key, []), st.assets, exp, now)
        cs = store.connector_state(settings.org_name, key)
        verdict = "fail" if any(c.status == "fail" for c in checks) else "warn" if any(c.status == "warn" for c in checks) else "pass"
        out[key] = {"verdict": verdict, "domain": info["domain"], "adapter": info["adapter"], "product": info.get("product"),
                    "mode": info.get("mode"), "items": info.get("items", 0), "checks": [c.as_dict() for c in checks],
                    "cadence_minutes": info.get("cadence_minutes", default_cadence(info["domain"])),
                    "phase_enabled": next((a.phase for a in agents if a.spec.domain.value == info["domain"]), 0)
                    <= settings.deployment_phase,
                    "last_success": cs["last_success"].isoformat() if cs.get("last_success") else None,
                    "monitor_state": (cs.get("monitor") or {}).get("state"),
                    "samples": [{"severity": f.severity.value, "title": f.title[:120], "asset": f.asset_id}
                                for f in by_src.get(key, [])[:3]]}
    verdicts = [v["verdict"] for v in out.values()]
    return {"org": settings.org_name, "mode": settings.mode, "checked_at": now.isoformat(), "full_window": full,
            "sources": out, "summary": {k: verdicts.count(k) for k in ("pass", "warn", "fail")},
            "result": "fail" if "fail" in verdicts else "warn" if "warn" in verdicts else ("pass" if out else "none")}
