"""LODESTAR command line.

  python -m lodestar demo                 # one command: generate data for 8 industries, run, reports, dashboard
  python -m lodestar demo-data [--vertical banking]
  python -m lodestar run [--config cfg.yaml] [--phase N] [--dataset path]
  python -m lodestar report --period weekly|monthly|quarterly|all [--org slug]
  python -m lodestar export-dashboard --out dist/dashboard.html
  python -m lodestar serve [--host 0.0.0.0 --port 8080]
  python -m lodestar schedule [--interval-hours 4]   # long-running: pipeline + calendar-based reports
  python -m lodestar chat ["what needs attention now"]   # talk to the prioritisation agent (same engine as Slack/Teams)
  python -m lodestar notify [--channel slack|teams|stdout]  # push the focus brief
  python -m lodestar validate             # config, secrets and phase-readiness checks
  python -m lodestar test-connector edr      # integrate one product at a time: run it alone and inspect the result
  python -m lodestar agents               # print the agent catalogue
"""
from __future__ import annotations

import argparse
import json
import logging
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


def cmd_run(args) -> int:
    from .orchestrator import Orchestrator
    s = _settings(args)
    res = Orchestrator(s).run()
    print(f"{res.org_name} [{res.vertical}] phase {s.deployment_phase}: posture {res.snapshot.posture_score}/100 | "
          f"today {res.snapshot.open_by_horizon['today']} | week {res.snapshot.open_by_horizon['week']} | "
          f"attack paths {len(res.correlations)} | signals {len(res.findings)}")
    fails = res.data_quality.get("agent_failures")
    if fails:
        print("  agent failures:", json.dumps(fails, indent=1))
    return 0


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
    """Long-running scheduler: pipeline every N hours; reports on calendar boundaries.
    weekly = Monday, monthly = 1st of month, quarterly = 1st of Jan/Apr/Jul/Oct (local time of the container)."""
    import time

    from .orchestrator import Orchestrator
    from .reporting import write_reports
    from .store import Store
    s = _settings(args)
    store = Store(s.sqlite_path)
    last_report_day = None
    last_brief_day = None
    while True:
        try:
            started = datetime.now(timezone.utc)
            res = Orchestrator(s, store=store).run()
            cfg = s.chatops or {}
            if cfg:
                from .chatops import notifier
                if notifier.channels(cfg):
                    if cfg.get("alert_on_new_now_decisions", True):
                        raised = {k: v["first_raised"] for k, v in store.decision_state(res.org_name).items()}
                        for r in notifier.new_urgent(res, raised, started, cfg):
                            print("  chat alert:", r, flush=True)
                    if datetime.now().hour >= int(cfg.get("daily_brief_hour", 7)) and last_brief_day != datetime.now().date():
                        for r in notifier.daily_brief(res, cfg):
                            print("  daily brief:", r, flush=True)
                        last_brief_day = datetime.now().date()
            print(f"[{datetime.now().isoformat(timespec='seconds')}] run ok: posture {res.snapshot.posture_score} "
                  f"today {res.snapshot.open_by_horizon['today']}", flush=True)
            today = datetime.now().date()
            if today != last_report_day:
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
                last_report_day = today
        except Exception as exc:  # keep the scheduler alive; failures are visible in logs and audit
            print(f"[{datetime.now().isoformat(timespec='seconds')}] run FAILED: {exc}", file=sys.stderr, flush=True)
        if args.once:
            return 0
        time.sleep(max(0.25, args.interval_hours) * 3600)


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
                       now=datetime.now(timezone.utc), dataset=dataset, store=Store(s.sqlite_path))
    st = PipelineState()
    for agent in (AssetContextAgent(), agents[0], DataQualityAgent()):
        st = agent(ctx, st)
    failed = [e for e in ctx.audit if e["event"] == "failed"]
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


def cmd_agents(args) -> int:
    from .catalog import agent_catalog
    for a in agent_catalog():
        print(f"phase {a['phase']}  {a['kind']:9s}  {a['name']:26s} {a['description']}")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=os.environ.get("LODESTAR_LOG", "WARNING"), format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="lodestar", description="LODESTAR security posture agents")
    p.add_argument("--config", help="path to lodestar.yaml (default config/lodestar.yaml or $LODESTAR_CONFIG)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo-data"); d.add_argument("--vertical", default="all"); d.add_argument("--as-of")
    d.set_defaults(fn=cmd_demo_data)
    r = sub.add_parser("run"); r.add_argument("--phase", type=int); r.add_argument("--dataset"); r.set_defaults(fn=cmd_run)
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
    sc.add_argument("--once", action="store_true"); sc.set_defaults(fn=cmd_schedule, phase=None, dataset=None)
    v = sub.add_parser("validate"); v.add_argument("--phase", type=int); v.set_defaults(fn=cmd_validate, dataset=None)
    a = sub.add_parser("agents"); a.set_defaults(fn=cmd_agents)
    tc = sub.add_parser("test-connector", help="run one connector agent and show what it collects (nothing stored)")
    tc.add_argument("domain"); tc.add_argument("--show", type=int, default=5); tc.add_argument("--dataset")
    tc.set_defaults(fn=cmd_test_connector, phase=None)
    args = p.parse_args(argv)
    return args.fn(args)
