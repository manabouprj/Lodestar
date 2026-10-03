"""Ingestion operations: cadence, sanity test, continuous validation (monitor, alerts, metrics), store fixes."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import yaml

from lodestar.agents.connectors.adapters.base import set_transport
from lodestar.config import ROOT, load_settings
from lodestar.orchestrator import Orchestrator
from lodestar.store import Store

URL = "https://siem.example/api/alerts"


def _rows(n, prefix="a"):
    return [{"id": f"{prefix}{i}", "name": f"Blocked intrusion attempt {i}", "sev": "high", "host": f"fw-{i % 3}",
             "created": "2026-09-30T10:00:00Z"} for i in range(n)]


@pytest.fixture
def feed():
    """A switchable fake REST source: feed['rows'] is served, feed['status'] != 200 makes the fetch fail."""
    state = {"rows": _rows(20), "status": 200, "calls": 0}

    def handler(req: httpx.Request):
        state["calls"] += 1
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"error": "unauthorized"})
        return httpx.Response(200, json={"data": state["rows"]})
    set_transport(httpx.MockTransport(handler))
    yield state
    set_transport(None)


def _cfg(tmp_path, **conn_extra):
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw.update({"mode": "live", "deployment_phase": 2, "storage": {"sqlite_path": str(tmp_path / "i.db")},
                "assets": {"path": None}, "chatops": {}})
    raw["connectors"] = {"firewall": {"enabled": True, "adapter": "http_json", "product": "Example NGFW",
                                      "settings": {"url": URL, "records": "data", "finding_type": "detection",
                                                   "field_map": {"finding_id": "id", "title": "name", "severity": "sev",
                                                                 "asset_id": "host", "first_seen": "created"},
                                                   "health": {"coverage_pct": 99}},
                                      **conn_extra}}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(raw))
    return load_settings(p)


def _ing(res, key="firewall/http_json"):
    return res.data_quality["ingestion"]["sources"][key]


# ------------------------------------------------------------------ cadence
def test_cadence_defaults_apply_to_scheduled_runs_only(tmp_path, feed):
    from lodestar.agents.connectors.domains import DEFAULT_CADENCE_MINUTES
    from lodestar.models import Domain
    assert set(DEFAULT_CADENCE_MINUTES) == set(Domain)
    s = _cfg(tmp_path)
    assert s.connectors[Domain.FIREWALL].interval_minutes is None
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run(scheduled=True)
    r2 = Orchestrator(s, store=store).run(scheduled=True)               # firewall default = 60 min -> not due
    src = r2.data_quality["sources"]["firewall/http_json"]
    assert src["status"] == "skipped" and src["interval_minutes"] == 60 and feed["calls"] == 1
    fw = next(c for c in r2.controls if c.domain.value == "firewall")   # last good health carried, domain still integrated
    assert fw.coverage_pct == 99 and "firewall" in r2.data_quality["integrated_domains"]
    assert len([f for f in r2.findings if f.domain.value == "firewall" and f.source != "lodestar.control_assurance"]) == 20
    Orchestrator(s, store=store).run()                                  # manual run: no default cadence
    assert feed["calls"] == 2


def test_explicit_interval_and_due_slack(tmp_path, feed):
    from lodestar.agents.connectors.agent import ConnectorAgent
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    assert ConnectorAgent.is_due(15, now - timedelta(minutes=14), now)       # within the 10% / 5 min slack
    assert not ConnectorAgent.is_due(60, now - timedelta(minutes=50), now)
    assert ConnectorAgent.is_due(0, now, now) and ConnectorAgent.is_due(60, None, now)
    s = _cfg(tmp_path, interval_minutes=0)
    store = Store(s.sqlite_path)
    for _ in range(2):
        Orchestrator(s, store=store).run(scheduled=True)
    assert feed["calls"] == 2                                            # explicit 0 = every tick


def test_bad_interval_rejected(tmp_path):
    from lodestar.config import ConfigError
    with pytest.raises(ConfigError):
        _cfg(tmp_path, interval_minutes=-5)


# ------------------------------------------------------------------ continuous validation
def test_failure_grace_then_failing_then_recovery(tmp_path, feed):
    s = _cfg(tmp_path)
    store = Store(s.sqlite_path)
    org = s.org_name
    r1 = Orchestrator(s, store=store).run()
    assert _ing(r1)["state"] == "healthy"

    feed["status"] = 401                                                 # credential expired
    r2 = Orchestrator(s, store=store).run()
    assert _ing(r2)["state"] == "retrying"
    fw = next(c for c in r2.controls if c.domain.value == "firewall")
    assert fw.coverage_pct == 99 and fw.data_freshness_hours < 1        # one miss: last good health, not a dead control
    assert not [f for f in r2.findings if f.finding_id.startswith("ing-")]

    r3 = Orchestrator(s, store=store).run()
    rec = _ing(r3)
    assert rec["state"] == "failing" and rec["consecutive_failures"] == 2 and "401" in rec["detail"]
    assert {"source": "firewall/http_json", "from": "retrying", "to": "failing"}.items() <= r3.data_quality["ingestion"]["transitions"][0].items()
    ing = next(f for f in r3.findings if f.finding_id == "ing-firewall-http_json")
    assert ing.finding_type.value == "coverage_gap" and ing.source == "lodestar.ingestion_monitor"
    assert any("ingestion firewall/http_json failing" in i for i in next(c for c in r3.controls if c.domain.value == "firewall").health_issues)
    assert "ing-firewall-http_json" in store.open_findings(org)
    assert len([f for f in r3.findings if f.domain.value == "firewall" and f.evidence.get("_src")]) == 20   # carried, not closed

    feed["status"] = 200
    r4 = Orchestrator(s, store=store).run()
    assert _ing(r4)["state"] == "healthy"
    assert "ing-firewall-http_json" not in store.open_findings(org)     # auto-resolved: condition cleared
    assert store.connector_state(org, "firewall/http_json")["failures"] == 0


def test_volume_drop_against_baseline(tmp_path, feed):
    s = _cfg(tmp_path)
    store = Store(s.sqlite_path)
    for _ in range(6):
        Orchestrator(s, store=store).run()
    feed["rows"] = _rows(2)                                              # export truncated
    r = Orchestrator(s, store=store).run()
    assert _ing(r)["state"] == "volume_drop" and "median of 20" in _ing(r)["detail"]
    assert any(f.finding_id == "ing-firewall-http_json" for f in r.findings)


def test_schema_drift_degrades_source(tmp_path, feed):
    feed["rows"] = [{k if k != "name" else "alert_name": v for k, v in row.items()} for row in _rows(5)]   # vendor renamed a field
    s = _cfg(tmp_path)
    r = Orchestrator(s, store=Store(s.sqlite_path)).run()
    rec = _ing(r)
    assert rec["state"] == "degraded"
    assert any(c["name"] == "schema" and c["status"] == "warn" and "name (title)" in c["detail"] for c in rec["checks"])


def test_silent_source_goes_stale(tmp_path, feed):
    s = _cfg(tmp_path, expect={"max_silence_hours": 12})
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run()
    with sqlite3.connect(s.sqlite_path) as c:                            # last items arrived 3 days ago
        c.execute("UPDATE source_runs SET at=?", ((datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),))
    feed["rows"] = []                                                    # API answers 200, log forwarding broke
    r = Orchestrator(s, store=store).run()
    rec = _ing(r)
    assert rec["state"] == "stale" and "no items for" in rec["detail"]
    assert any(f.finding_id == "ing-firewall-http_json" for f in r.findings)


def test_export_job_stopped_goes_stale(tmp_path):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "x.csv").write_text("title,severity,host\nAny-any rule,high,fw-1\n")
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw.update({"mode": "live", "deployment_phase": 2, "storage": {"sqlite_path": str(tmp_path / "f.db")},
                "assets": {"path": None}})
    raw["connectors"] = {"firewall": {"adapter": "file_drop", "product": "PAN",
                                      "settings": {"path": str(drop), "field_map": {"asset_id": "host"},
                                                   "health": {"coverage_pct": 100}}}}
    (tmp_path / "c.yaml").write_text(yaml.safe_dump(raw))
    s = load_settings(tmp_path / "c.yaml")
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run()
    with sqlite3.connect(s.sqlite_path) as c:
        c.execute("UPDATE connector_state SET last_success=?", ((datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),))
    (drop / "x.csv").unlink()                                             # export job stopped writing files
    r = Orchestrator(s, store=store).run()
    rec = _ing(r, "firewall/file_drop")
    assert rec["status"] == "no_data" and rec["state"] == "stale" and "no successful fetch for 72h" in rec["detail"]


def test_lodestar_findings_raised_after_lifecycle_stay_open(tmp_path, demo_dir):
    """Regression: ctl-* (control health) findings were resolved by the same save that re-raised them."""
    s = load_settings(overrides={"mode": "demo", "demo": {"dataset": str(demo_dir / "banking.json")},
                                 "storage": {"sqlite_path": str(tmp_path / "d.db")}})
    store = Store(s.sqlite_path)
    for _ in range(3):
        r = Orchestrator(s, store=store).run()
    ctl = {f.finding_id for f in r.findings if f.finding_id.startswith("ctl-")}
    assert ctl and ctl <= set(store.open_findings(r.org_name))


# ------------------------------------------------------------------ alerts + metrics
def test_ingestion_alerts_fire_once_and_on_recovery(tmp_path, feed, monkeypatch):
    from lodestar.chatops import notifier, slack
    sent = []
    monkeypatch.setattr(slack, "post", lambda reply, cfg, channel=None: sent.append((reply.title, channel)) or {"ok": True})
    chat = {"slack": {"enabled": True, "bot_token": "x", "channel": "C1"}}
    icfg = {"alerts": {"slack_channel": "#ingestion"}}
    s = _cfg(tmp_path)
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run()
    feed["status"] = 500
    monkeypatch.setattr("lodestar.agents.connectors.adapters.base.time.sleep", lambda *_: None)
    for _ in range(2):
        r = Orchestrator(s, store=store).run()
    now = datetime.now(timezone.utc)
    assert notifier.ingestion_alerts(r, store, icfg, chat, now)[0]["ok"]
    assert "need attention" in sent[-1][0] and sent[-1][1] == "#ingestion"
    r = Orchestrator(s, store=store).run()
    assert notifier.ingestion_alerts(r, store, icfg, chat, now) == []          # still failing: no repeat within 24h
    assert notifier.ingestion_alerts(r, store, icfg, chat, now + timedelta(hours=25))   # reminder
    feed["status"] = 200
    r = Orchestrator(s, store=store).run()
    notifier.ingestion_alerts(r, store, icfg, chat, now + timedelta(hours=26))
    assert "recovered" in sent[-1][0].lower()
    assert notifier.ingestion_alerts(r, store, icfg, chat, now + timedelta(hours=27)) == []


def test_metrics_expose_source_state(tmp_path, feed):
    from lodestar.ops import prometheus
    s = _cfg(tmp_path)
    store = Store(s.sqlite_path)
    r = Orchestrator(s, store=store).run()
    text = prometheus(store, {"o": r.org_name}, {}, [0.0, 0])
    assert 'lodestar_source_state{org="o",source="firewall/http_json",state="healthy"} 1' in text
    assert 'lodestar_source_consecutive_failures{org="o",source="firewall/http_json"} 0' in text
    assert "lodestar_source_cadence_minutes" in text


# ------------------------------------------------------------------ sanity test
def test_check_ingestion_cli(tmp_path, feed, capsys, monkeypatch):
    from lodestar.cli import main
    s = _cfg(tmp_path)
    cfg = str(tmp_path / "c.yaml")
    assert main(["--config", cfg, "check-ingestion"]) == 0
    out = capsys.readouterr().out
    assert "[PASS] firewall/http_json" in out and "RESULT: PASS" in out
    assert not Store(s.sqlite_path).all_connector_state(s.org_name)     # nothing stored

    raw = yaml.safe_load(open(cfg))
    raw["connectors"]["firewall"]["expect"] = {"min_items": 50}
    open(cfg, "w").write(yaml.safe_dump(raw))
    assert main(["--config", cfg, "check-ingestion", "--json"]) == 1
    rep = json.loads(capsys.readouterr().out)
    vol = next(c for c in rep["sources"]["firewall/http_json"]["checks"] if c["name"] == "volume")
    assert vol["status"] == "fail" and rep["result"] == "fail"

    feed["status"] = 403
    assert main(["--config", cfg, "check-ingestion"]) == 1
    assert "[FAIL] firewall/http_json" in capsys.readouterr().out


def test_check_ingestion_demo(demo_dir, capsys):
    from lodestar.cli import main
    assert main(["check-ingestion", "--dataset", str(demo_dir / "banking.json"), "--domain", "edr"]) == 0
    assert "edr/mock" in capsys.readouterr().out
