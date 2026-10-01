"""LODESTAR command line.

  python -m lodestar demo                 # one command: generate data for 8 industries, run, reports, dashboard
  python -m lodestar demo-data [--vertical banking]
  python -m lodestar run [--config cfg.yaml] [--phase N] [--org key] [--force]   # every tenant unless --org
  python -m lodestar backup [--out file.db]
  python -m lodestar report --period weekly|monthly|quarterly|all [--org slug]
  python -m lodestar export-dashboard --out dist/dashboard.html
  python -m lodestar serve [--host 0.0.0.0 --port 8080]
  python -m lodestar schedule [--interval-hours 4]   # long-running: pipeline + calendar-based reports
  python -m lodestar chat ["what needs attention now"]   # talk to the prioritisation agent (same engine as Slack/Teams)
  python -m lodestar notify [--channel slack|teams|stdout]  # push the focus brief
  python -m lodestar init                 # generate a live config: org, industry, SIEM-first connectors, .env secrets
  python -m lodestar doctor [--online]    # readiness report with the fix for every problem
  python -m lodestar validate             # config, secrets and phase-readiness checks
  python -m lodestar test-connector edr      # integrate one product at a time: run it alone and inspect the result
  python -m lodestar kpis                 # KRI provenance: connector / measured by LODESTAR / manual / not measured
  python -m lodestar agents               # print the agent catalogue
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import ROOT, ConfigError, load_settings


def _settings(args, **over):
    o = dict(over)
    if getattr(args, "phase", None) is not None:
        o["deployment_phase"] = args.phase
    if getattr(args, "dataset", None):
        o["mode"] = "demo"
        o["demo"] = {"dataset": args.dataset}
    return load_settings(getattr(args, "config", None), overrides=o)


def cmd_demo_data(args) -> int:
    from .demo.generator import ORGS, generate
    as_of = datetime.fromisoformat(args.as_of).replace(tzinfo=timezone.utc) if args.as_of else None
    targets = list(ORGS) if args.vertical == "all" else [args.vertical]
    for v in targets:
        p = generate(v, ROOT / "data" / "demo", as_of)
        print(f"  generated {p.relative_to(ROOT)}")
    return 0


def _tenants(args, **over):
    """Organisations to act on: config/tenants/*.yaml (multi-tenant) or the single config; --org filters."""
    from .config import load_tenants
    o = dict(over)
    if getattr(args, "phase", None) is not None:
        o["deployment_phase"] = args.phase
    if getattr(args, "dataset", None):
        return [_settings(args, **over)]
    ts = load_tenants(getattr(args, "config", None), overrides=o)
    want = getattr(args, "org", None)
    if want:
        ts = [t for t in ts if t.org_key == want]
        if not ts:
            raise SystemExit(f"Unknown org '{want}'")
    return ts


def cmd_run(args) -> int:
    from .orchestrator import Orchestrator
    from .store import LockBusy
    rc = 0
    for s in _tenants(args):
        try:
            res = Orchestrator(s).run(force=getattr(args, "force", False))
        except LockBusy:
            print(f"{s.org_name}: another run is in progress - skipped", file=sys.stderr)
            rc = 3
            continue
        snap = res.snapshot
        print(f"{res.org_name} [{res.vertical}] phase {s.deployment_phase}: posture {snap.posture_score}/100"
              f"{' (provisional)' if snap.posture_provisional else ''} | today {snap.open_by_horizon['today']} | "
              f"week {snap.open_by_horizon['week']} | attack paths {len(res.correlations)} | signals {len(res.findings)} | "
              f"KRIs measured {snap.kri_coverage_pct}%")
        srcs = res.data_quality.get("sources") or {}
        bad = {k: v for k, v in srcs.items() if v.get("status") == "failed"}
        if bad:
            rc = rc or 1
            for k, v in bad.items():
                print(f"  source FAILED {k}: {v.get('error', '')[:200]}  (its findings were carried forward, not closed)")
    return rc


def cmd_report(args) -> int:
    from .reporting import write_reports
    from .store import Store
    from .web import slug
    s = _settings(args)
    store = Store(s.sqlite_path)
    orgs = [o for o in store.list_orgs() if not args.org or slug(o) == args.org]
    if not orgs:
        print("No results in store. Run `python -m lodestar run` first.", file=sys.stderr)
        return 1
    periods = ("weekly", "monthly", "quarterly") if args.period == "all" else (args.period,)
    for org in orgs:
        for p in write_reports(store.latest_result(org), s.reports_dir, periods, llm_cfg=s.llm):
            print(f"  wrote {p.relative_to(ROOT) if p.is_relative_to(ROOT) else p}")
    return 0


def cmd_export(args) -> int:
    from .dashboard import build_payload
    from .store import Store
    from .web import render_dashboard
    s = _settings(args)
    store = Store(s.sqlite_path)
    payloads = [build_payload(store.latest_result(o)) for o in store.list_orgs()]
    payloads.sort(key=lambda p: (p["vertical_id"] != "banking", p["org"]))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_dashboard(payloads, demo=s.mode == "demo", api=False, full_document=not args.fragment),
                   encoding="utf-8")
    print(f"  dashboard -> {out} ({out.stat().st_size // 1024} KB, {len(payloads)} organisation(s))")
    return 0


def cmd_demo(args) -> int:
    from .demo.generator import ORGS, generate
    from .orchestrator import Orchestrator
    from .reporting import write_reports
    from .store import Store
    base = load_settings(getattr(args, "config", None), overrides={"mode": "demo"})
    store = Store(base.sqlite_path)
    as_of = datetime.fromisoformat(args.as_of).replace(tzinfo=timezone.utc) if args.as_of else None
    print("LODESTAR demo - generating fictional organisations for 8 industries")
    for v in ORGS:
        path = generate(v, ROOT / "data" / "demo", as_of)
        s = load_settings(getattr(args, "config", None), overrides={"mode": "demo", "demo": {"dataset": str(path)}})
        res = Orchestrator(s, store=store).run()
        write_reports(res, s.reports_dir, llm_cfg=s.llm)
        print(f"  {res.org_name:32s} {res.vertical:16s} posture {res.snapshot.posture_score:5.1f} | "
              f"signals {len(res.findings):5d} -> today {res.snapshot.open_by_horizon['today']:3d} | "
              f"attack paths {len(res.correlations):2d}")
    args.out = args.out or str(ROOT / "dist" / "lodestar-dashboard.html")
    args.fragment = False
    cmd_export(argparse.Namespace(config=getattr(args, "config", None), out=args.out, fragment=False,
                                  phase=None, dataset=None))
    print(f"  reports -> {base.reports_dir}")
    print("Next: python -m lodestar serve   then open http://127.0.0.1:8080")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    if args.config:
        os.environ["LODESTAR_CONFIG"] = args.config
    uvicorn.run("lodestar.api.app:app", host=args.host, port=args.port, log_level="info")
    return 0


def cmd_schedule(args) -> int:
    """Long-running scheduler for every organisation: pipeline every N hours; reports on calendar boundaries
    (weekly = Monday, monthly = 1st, quarterly = 1st of Jan/Apr/Jul/Oct, local time); chat brief, new-urgent
    alerts and escalations; nightly prune + backup (ops.backup_dir)."""
    import time

    from .orchestrator import Orchestrator
    from .reporting import write_reports
    from .store import LockBusy, Store
    tenants = _tenants(args)
    base = tenants[0]
    store = Store(base.sqlite_path, keep_runs=int((base.raw.get("storage") or {}).get("keep_runs", 5)))
    last_report_day: dict[str, object] = {}
    last_brief_day: dict[str, object] = {}
    last_maint = None
    while True:
        for s in tenants:
            try:
                started = datetime.now(timezone.utc)
                res = Orchestrator(s, store=store).run(lock_wait=0)
                cfg = s.chatops or {}
                if cfg:
                    from .chatops import notifier
                    if notifier.channels(cfg):
                        if cfg.get("alert_on_new_now_decisions", True):
                            raised = {k: v["first_raised"] for k, v in store.decision_state(res.org_name).items()}
                            for r in notifier.new_urgent(res, raised, started, cfg):
                                print("  chat alert:", r, flush=True)
                        for r in notifier.escalate(res, store, cfg, datetime.now(timezone.utc)):
                            print("  escalation:", r, flush=True)
                        if datetime.now().hour >= int(cfg.get("daily_brief_hour", 7)) and \
                                last_brief_day.get(s.org_key) != datetime.now().date():
                            for r in notifier.daily_brief(res, cfg):
                                print("  daily brief:", r, flush=True)
                            last_brief_day[s.org_key] = datetime.now().date()
                print(f"[{datetime.now().isoformat(timespec='seconds')}] {s.org_key}: run ok, posture "
                      f"{res.snapshot.posture_score} today {res.snapshot.open_by_horizon['today']}", flush=True)
                today = datetime.now().date()
                if today != last_report_day.get(s.org_key):
                    periods = []
                    if today.weekday() == 0:
                        periods.append("weekly")
                    if today.day == 1:
                        periods.append("monthly")
                        if today.month in (1, 4, 7, 10):
                            periods.append("quarterly")
                    if periods:
                        write_reports(res, s.reports_dir, tuple(periods), llm_cfg=s.llm)
                        print(f"  reports written: {periods}", flush=True)
                    last_report_day[s.org_key] = today
            except LockBusy:
                print(f"[{datetime.now().isoformat(timespec='seconds')}] {s.org_key}: run in progress elsewhere - skipped",
                      flush=True)
            except Exception as exc:  # keep the scheduler alive; failures are visible in logs, audit and /metrics
                print(f"[{datetime.now().isoformat(timespec='seconds')}] {s.org_key}: run FAILED: {exc}", file=sys.stderr, flush=True)
        if last_maint != datetime.now().date():
            try:
                ops = base.raw.get("ops") or {}
                pruned = store.prune(**{k: v for k, v in (ops.get("retention") or {}).items()})
                print(f"  maintenance: pruned {pruned}", flush=True)
                if ops.get("backup_dir"):
                    dest = base.path(ops["backup_dir"]) / f"lodestar-{datetime.now():%Y%m%d}.db"
                    store.backup(dest)
                    _rotate_backups(dest.parent, int(ops.get("backup_keep", 14)))
                    print(f"  maintenance: backup {dest}", flush=True)
            except Exception as exc:
                print(f"  maintenance FAILED: {exc}", file=sys.stderr, flush=True)
            last_maint = datetime.now().date()
        if args.once:
            return 0
        time.sleep(max(0.25, args.interval_hours) * 3600)


def _rotate_backups(folder: Path, keep: int) -> None:
    files = sorted(folder.glob("lodestar-*.db"))
    for f in files[:-keep] if keep > 0 else []:
        f.unlink(missing_ok=True)


def cmd_backup(args) -> int:
    """Consistent online backup of the store (safe while the API and scheduler run)."""
    from .store import Store
    s = _settings(args)
    dest = Path(args.out) if args.out else s.path("data/backups") / f"lodestar-{datetime.now():%Y%m%d-%H%M%S}.db"
    out = Store(s.sqlite_path).backup(dest)
    print(f"backup written: {out} ({out.stat().st_size // 1024} KB). Restore: stop LODESTAR, copy it over "
          f"{s.sqlite_path}, start LODESTAR.")
    return 0


def _latest(s, org_slug=None):
    from .decisions import overlay
    from .store import Store
    from .web import slug
    store = Store(s.sqlite_path)
    orgs = [o for o in store.list_orgs() if not org_slug or slug(o) == org_slug]
    if not orgs:
        raise SystemExit("No results in store. Run `python -m lodestar run` (or `demo`) first.")
    return store, overlay(store, store.latest_result(orgs[0]))


def cmd_chat(args) -> int:
    """Talk to the prioritisation agent from the terminal - same engine as Slack/Teams."""
    from .chatops import ChatEngine
    from .decisions import record
    s = _settings(args)
    store, res = _latest(s, args.org)
    eng = ChatEngine(res, (s.chatops or {}).get("dashboard_url"))
    rec = (lambda d, c, r: record(store, res, d, c, r, channel="cli", itsm_cfg=s.itsm))

    def show(text):
        rep = eng.handle(text, args.role, rec)
        print("\n" + rep.markdown().replace("**", "") + "\n")
    if args.text:
        show(" ".join(args.text))
        return 0
    print(f"LODESTAR chat - {res.org_name} (role: {args.role}). Type 'help', or 'quit'.")
    while True:
        try:
            line = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if line.lower() in ("quit", "exit"):
            return 0
        show(line)


def cmd_notify(args) -> int:
    from .chatops import notifier
    s = _settings(args)
    _, res = _latest(s, args.org)
    cfg = s.chatops or {}
    if args.channel == "stdout" or not notifier.channels(cfg):
        from .chatops import ChatEngine
        print(ChatEngine(res, cfg.get("dashboard_url")).brief().markdown().replace("**", ""))
        if args.channel != "stdout":
            print("\n(no chat channel enabled in config - printed instead)")
        return 0
    for r in notifier.daily_brief(res, cfg, None if args.channel == "all" else args.channel):
        print(" ", r)
    return 0


def cmd_validate(args) -> int:
    from .agents.connectors.adapters import REGISTRY
    from .agents.connectors.domains import SPECS
    from .verticals import list_verticals, load_vertical
    ok = True
    try:
        s = _settings(args)
    except ConfigError as exc:
        print(f"[FAIL] config: {exc}")
        return 2
    print(f"[ OK ] config loaded: org='{s.org_name}' vertical={s.vertical} mode={s.mode} phase={s.deployment_phase}")
    for v in list_verticals():
        load_vertical(v)
    print(f"[ OK ] {len(list_verticals())} vertical profiles valid: {', '.join(list_verticals())}")
    vert = load_vertical(s.vertical)
    for d, cc in sorted(s.connectors.items(), key=lambda x: (SPECS[x[0]].phase, x[0].value)):
        sp = SPECS[d]
        if sp.phase > s.deployment_phase or not cc.enabled:
            status = "SKIP" if not cc.enabled else "LATER"
            print(f"[{status:>4}] phase {sp.phase} {sp.agent_name:24s} {cc.adapter}")
            continue
        problems = []
        srcs = cc.sources or [{"adapter": cc.adapter, "product": cc.product, "settings": cc.settings}]
        for src in srcs:
            tag = f"{src['product'] or src['adapter']}: " if len(srcs) > 1 else ""
            if src["adapter"] not in REGISTRY:
                problems.append(f"{tag}unknown adapter '{src['adapter']}'")
            if s.mode == "live":
                st = src["settings"]
                missing = [k for k, v in st.items() if v in ("", None) and k != "coverage_pct"]
                if missing:
                    problems.append(f"{tag}missing settings/env: {missing}")
                if src["adapter"] in ("file_drop", "csaf", "taxii", "mailbox") and st.get("path") and \
                        (st.get("mode", "path") == "path") and not s.path(st["path"]).exists():
                    problems.append(f"{tag}folder missing: {st['path']}")
        ok &= not problems
        label = "+".join(x["adapter"] for x in srcs)
        print(f"[{'FAIL' if problems else ' OK '}] phase {sp.phase} {sp.agent_name:24s} {label[:26]:26s} {'; '.join(problems)}")
    missing_mand = [m for m in vert.mandatory_domains if not (s.connectors.get(m) and s.connectors[m].enabled)]
    if missing_mand:
        print(f"[WARN] mandatory controls for {vert.name} not enabled: {missing_mand}")
    if s.mode == "live":
        if not os.environ.get("LODESTAR_API_KEYS"):
            ok = False
            print("[FAIL] LODESTAR_API_KEYS not set - live mode requires authenticated API")
        if not os.environ.get("LODESTAR_WEBHOOK_SECRET") and any(
                c.adapter == "webhook" and c.enabled and SPECS[d].phase <= s.deployment_phase for d, c in s.connectors.items()):
            ok = False
            print("[FAIL] LODESTAR_WEBHOOK_SECRET not set but webhook adapters are configured")
    print("RESULT:", "ready" if ok else "fix the FAIL items above")
    return 0 if ok else 1


def cmd_test_connector(args) -> int:
    """Run ONE connector agent (plus asset context and data quality) and print what it collected.
    Nothing is stored. Use it while integrating a product: credentials, field maps, asset matching."""
    from .agents.base import AgentContext, PipelineState
    from .agents.connectors import build_connector_agents
    from .agents.core import AssetContextAgent, DataQualityAgent
    from .models import Domain
    from .orchestrator import load_dataset
    from .verticals import load_vertical
    try:
        domain = Domain(args.domain)
    except ValueError:
        print(f"Unknown domain '{args.domain}'. Choose from: {', '.join(d.value for d in Domain)}", file=sys.stderr)
        return 2
    s = _settings(args, deployment_phase=4)
    agents = [a for a in build_connector_agents(s, 4) if a.spec.domain == domain]
    if not agents:
        print(f"Connector '{domain.value}' is not enabled in {s.raw.get('_path', 'config')}. Add it under connectors:.", file=sys.stderr)
        return 2
    dataset = load_dataset(s.demo_dataset) if s.mode == "demo" else None
    from .store import Store
    ctx = AgentContext(settings=s, vertical=load_vertical(dataset.get("vertical") if dataset else s.vertical),
                       now=datetime.now(timezone.utc), dataset=dataset, store=Store(s.sqlite_path), dry_run=True, force=True)
    st = PipelineState()
    for agent in (AssetContextAgent(), agents[0], DataQualityAgent()):
        st = agent(ctx, st)
    failed = [e for e in ctx.audit if e["event"] in ("failed", "source_failed")]
    dq = st.data_quality.get("connectors", {}).get(domain.value, {})
    print(f"Connector : {agents[0].name} ({domain.value}) via {dq.get('adapter', ', '.join(a.name for a in agents[0].adapters))}  [mode={s.mode}]")
    if failed:
        print(f"RESULT    : FAILED - {failed[0].get('error')}")
        return 1
    if domain.value in (st.data_quality.get("not_integrated") or []):
        print("RESULT    : no data returned (check the adapter settings, drop folder or webhook sender)")
        return 1
    h = next((c for c in st.controls if c.domain == domain), None)
    found = [f for f in st.findings if f.domain == domain]
    unmatched = sorted({f.asset_id for f in found if f.asset_id and f.asset_id not in st.assets})
    print(f"Findings  : {len(found)} collected; by severity " +
          ", ".join(f"{k}={sum(1 for f in found if f.severity.value == k)}" for k in ("critical", "high", "medium", "low", "info")))
    if h:
        print(f"Health    : product='{h.product}' coverage={h.coverage_pct}% freshness={h.data_freshness_hours}h issues={h.health_issues or 'none'}")
        if h.kpis:
            print("KPIs      : " + ", ".join(f"{k}={v}" for k, v in list(h.kpis.items())[:10]))
    matched = sum(1 for f in found if f.asset_id in st.assets)
    no_asset = sum(1 for f in found if not f.asset_id)
    print(f"Assets    : {matched} matched to CMDB, {len(found) - matched - no_asset} unmatched, {no_asset} user/advisory-level"
          + (f" (unmatched e.g. {', '.join(unmatched[:5])} - add them or their aliases to the CMDB export)" if unmatched else ""))
    if domain == Domain.THREAT_INTEL:
        print("Note      : relevance filtering (our CVEs / products / IOC sightings / sector) runs in the full pipeline (`lodestar run`)")
    for w in (dq.get("warnings") or [])[:5] + (dq.get("source_failures") or [])[:5]:
        print(f"Warning   : {w}")
    for f in found[: args.show]:
        print(f"  - [{f.severity.value:8s}] {f.title[:90]}  asset={f.asset_id or '-'} user={f.user_id or '-'}")
    if not found:
        print("RESULT    : CONNECTED, NO FINDINGS YET - check the drop folder / webhook sender / lookback window")
        return 0
    print("RESULT    : OK")
    return 0


def _ask(prompt: str, default: str | None = None, choices: list[str] | None = None) -> str:
    if not sys.stdin.isatty():
        if default is None:
            raise SystemExit(f"{prompt}: required (pass it as an option when not running interactively)")
        return default
    hint = f" [{'/'.join(choices)}]" if choices else ""
    while True:
        v = input(f"{prompt}{hint}{f' ({default})' if default else ''}: ").strip() or (default or "")
        if v and (not choices or v in choices):
            return v


def cmd_init(args) -> int:
    """Generate a working live configuration in minutes (see docs/QUICKSTART.md)."""
    from .agents.connectors.domains import SPECS
    from .onboarding import init
    from .verticals import list_verticals, load_vertical
    org = args.org or _ask("Organisation name")
    vertical = args.vertical or _ask("Industry profile", "banking", list_verticals())
    siem = args.siem or _ask("Which SIEM already receives your security alerts", "sentinel", ["sentinel", "splunk", "none"])
    v = load_vertical(vertical)
    default_domains = list(dict.fromkeys([*v.mandatory_domains, "threat_intel"]))
    if args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    else:
        if sys.stdin.isatty():
            print("Control domains: " + ", ".join(d.value for d in SPECS))
        domains = [d.strip() for d in _ask("Domains to integrate first (comma separated)", ",".join(default_domains)).split(",")]
    bad = [d for d in domains if d not in {x.value for x in SPECS}]
    if bad:
        raise SystemExit(f"unknown domain(s): {bad}")
    pd = args.primary_domain or _ask("Primary e-mail / UPN domain (e.g. acme.com)", "")
    out = init(org=org, vertical=vertical, siem=siem, domains=domains, primary_domain=pd or None, tenant=args.tenant,
               out=Path(args.out) if args.out else None)
    print(f"\nLODESTAR initialised for {org} ({v.name}) - org key '{out['org_key']}'")
    for f in out["files"]:
        print(f"  + {f}")
    print("  connector templates: " + ", ".join(f"{d}={k}" for d, k in out["templates"].items()))
    if out["generated"].get("LODESTAR_API_KEYS"):
        print("\n  API keys (also in .env - store them in your password vault):")
        for pair in out["generated"]["LODESTAR_API_KEYS"].split(","):
            role, _, key = pair.partition(":")
            print(f"    {role:8s} {key}")
    if out["mandatory_missing"]:
        print(f"\n  note: {v.name} normally needs {out['mandatory_missing']} too - add them when you can.")
    print("\nNext:\n  1. fill the blank values in .env (" + ", ".join(e for e in out["env_to_fill"] if not e.startswith("LODESTAR_"))[:200]
          + ")\n  2. export your CMDB into config/assets.csv\n  3. lodestar doctor\n  4. lodestar test-connector <domain>   (one at a time)"
          "\n  5. lodestar run   then   lodestar serve")
    return 0


def cmd_doctor(args) -> int:
    from .onboarding import doctor
    rep = doctor(getattr(args, "config", None), online=args.online)
    print(rep.render())
    return 1 if rep.failed else 0


def cmd_kpis(args) -> int:
    """Where every KRI comes from, and how to measure the ones that are missing."""
    from .metrics import KRI_CONNECTOR, KRI_REQUIRES, kri_table
    from .verticals import load_vertical
    s = _settings(args)
    _, res = _latest(s, args.org)
    snap, v = res.snapshot, load_vertical(res.vertical)
    print(f"{res.org_name} [{v.name}] - KRIs measured: {snap.kri_coverage_pct}%"
          + ("  (posture score is PROVISIONAL)" if snap.posture_provisional else ""))
    for k in kri_table(snap.kris, v, snap.kri_sources):
        if k["metric"] == "posture_score":
            continue
        val = "not measured" if k["value"] is None else f"{k['value']:g}{k.get('unit', '') if k.get('unit') != 'count' else ''}"
        print(f"  {k['status']:12s} {k['label'][:44]:44s} {val:>14s}   {k['source']}")
        if k["value"] is None:
            if k["metric"] in KRI_CONNECTOR:
                dom, keys = KRI_CONNECTOR[k["metric"]]
                hint = (f"integrate the '{dom}' connector and report KPI '{keys[0]}' (SIEM health_query column or "
                        f"settings.health.kpis), or")
            elif KRI_REQUIRES.get(k["metric"]):
                hint = f"integrate one of {list(KRI_REQUIRES[k['metric']])}, or"
            else:
                hint = "LODESTAR computes this after ~3 closed items (run history), or"
            print(f"  {'':12s}   -> {hint} add kpis_manual.{k['metric']} {{value, as_of, source}} to the config")
    stale = res.data_quality.get("kpis", {}).get("manual_stale") or []
    if stale:
        print(f"  manual KPIs ignored because they are older than max_age_days: {', '.join(stale)}")
    return 0


def cmd_agents(args) -> int:
    from .catalog import agent_catalog
    for a in agent_catalog():
        print(f"phase {a['phase']}  {a['kind']:9s}  {a['name']:26s} {a['description']}")
    return 0


def main(argv=None) -> int:
    from .ops import configure_logging
    configure_logging()
    p = argparse.ArgumentParser(prog="lodestar", description="LODESTAR security posture agents")
    p.add_argument("--config", help="path to lodestar.yaml (default config/lodestar.yaml or $LODESTAR_CONFIG)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo-data"); d.add_argument("--vertical", default="all"); d.add_argument("--as-of")
    d.set_defaults(fn=cmd_demo_data)
    r = sub.add_parser("run", help="run the pipeline for every configured organisation (or --org)")
    r.add_argument("--phase", type=int); r.add_argument("--dataset"); r.add_argument("--org")
    r.add_argument("--force", action="store_true", help="ignore connector interval_minutes"); r.set_defaults(fn=cmd_run)
    rp = sub.add_parser("report"); rp.add_argument("--period", default="all", choices=["weekly", "monthly", "quarterly", "all"])
    rp.add_argument("--org"); rp.set_defaults(fn=cmd_report, phase=None, dataset=None)
    e = sub.add_parser("export-dashboard"); e.add_argument("--out", default=str(ROOT / "dist" / "lodestar-dashboard.html"))
    e.add_argument("--fragment", action="store_true", help="omit <html>/<body> wrapper (for embedding/publishing)")
    e.set_defaults(fn=cmd_export, phase=None, dataset=None)
    dm = sub.add_parser("demo"); dm.add_argument("--out"); dm.add_argument("--as-of"); dm.set_defaults(fn=cmd_demo)
    sv = sub.add_parser("serve"); sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(fn=cmd_serve)
    ch = sub.add_parser("chat"); ch.add_argument("text", nargs="*"); ch.add_argument("--org")
    ch.add_argument("--role", default="ciso", choices=["exec", "analyst", "ciso"]); ch.set_defaults(fn=cmd_chat, phase=None, dataset=None)
    nt = sub.add_parser("notify"); nt.add_argument("--channel", default="all", choices=["all", "slack", "teams", "stdout"])
    nt.add_argument("--org"); nt.set_defaults(fn=cmd_notify, phase=None, dataset=None)
    sc = sub.add_parser("schedule"); sc.add_argument("--interval-hours", type=float, default=4.0)
    sc.add_argument("--once", action="store_true"); sc.add_argument("--org")
    sc.set_defaults(fn=cmd_schedule, phase=None, dataset=None)
    bk = sub.add_parser("backup", help="online backup of the SQLite store"); bk.add_argument("--out")
    bk.set_defaults(fn=cmd_backup, phase=None, dataset=None)
    v = sub.add_parser("validate"); v.add_argument("--phase", type=int); v.set_defaults(fn=cmd_validate, dataset=None)
    a = sub.add_parser("agents"); a.set_defaults(fn=cmd_agents)
    it = sub.add_parser("init", help="generate a live configuration: org, industry, SIEM-first connectors, .env secrets")
    it.add_argument("--org"); it.add_argument("--vertical"); it.add_argument("--siem", choices=["sentinel", "splunk", "none"])
    it.add_argument("--domains", help="comma separated, default = the industry's mandatory domains + threat_intel")
    it.add_argument("--primary-domain"); it.add_argument("--out")
    it.add_argument("--tenant", action="store_true", help="add an organisation as config/tenants/<key>.yaml")
    it.set_defaults(fn=cmd_init)
    dr = sub.add_parser("doctor", help="readiness report: config, secrets, CMDB, every connector, KRIs, SSO, backups")
    dr.add_argument("--online", action="store_true", help="also test network reachability of every API endpoint")
    dr.set_defaults(fn=cmd_doctor)
    kp = sub.add_parser("kpis", help="show where each KRI comes from and how to measure missing ones")
    kp.add_argument("--org"); kp.set_defaults(fn=cmd_kpis, phase=None, dataset=None)
    tc = sub.add_parser("test-connector", help="run one connector agent and show what it collects (nothing stored)")
    tc.add_argument("domain"); tc.add_argument("--show", type=int, default=5); tc.add_argument("--dataset")
    tc.set_defaults(fn=cmd_test_connector, phase=None)
    args = p.parse_args(argv)
    return args.fn(args)
