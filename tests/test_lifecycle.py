"""Finding lifecycle across runs: sticky first-seen, snapshot resolution, carry-forward on failure."""
import shutil

import yaml

from lodestar.config import ROOT, load_settings
from lodestar.orchestrator import Orchestrator
from lodestar.store import Store

ROWS = ["rule_issue,risk,device,detected",
        "Any-any allow rule on DMZ policy,4,fw-dmz-01,2026-09-01T00:00:00Z",
        "SMB from user VLAN,4,fw-core-02,2026-09-02T00:00:00Z",
        "Unused rule,2,fw-core-02,2026-07-01T00:00:00Z"]


def _cfg(tmp_path, drop):
    raw = yaml.safe_load((ROOT / "config" / "lodestar.yaml").read_text())
    raw["mode"] = "live"
    raw["deployment_phase"] = 2
    raw["storage"] = {"sqlite_path": str(tmp_path / "l.db")}
    raw["assets"] = {"path": None}
    raw["connectors"] = {"firewall": {"enabled": True, "adapter": "file_drop", "product": "PAN",
                         "settings": {"path": str(drop), "finding_type": "misconfiguration",
                                      "field_map": {"title": "rule_issue", "severity": "risk", "asset_id": "device",
                                                    "first_seen": "detected"},
                                      "health": {"coverage_pct": 100}}}}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(raw))
    return load_settings(p)


def _open(store, org):
    return {fid for fid in store.open_findings(org)}


def test_snapshot_resolution_and_failure_carry_forward(tmp_path):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "x.csv").write_text("\n".join(ROWS))
    s = _cfg(tmp_path, drop)
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run()
    org = s.org_name
    assert len(_open(store, org)) == 3

    (drop / "x.csv").write_text("\n".join(ROWS[:3]))          # 'Unused rule' fixed
    r2 = Orchestrator(s, store=store).run()
    assert len(_open(store, org)) == 3                          # missed once -> still open (carried)
    assert r2.data_quality["lifecycle"]["carried_forward"] == 1

    shutil.rmtree(drop)                                         # export job broken -> source returns no data
    Orchestrator(s, store=store).run()
    assert len(_open(store, org)) == 3                          # nothing resolved because the tool was down

    drop.mkdir()
    (drop / "x.csv").write_text("\n".join(ROWS[:3]))
    Orchestrator(s, store=store).run()
    assert len(_open(store, org)) == 2                          # second consecutive full pull without it -> resolved
    stats = store.resolution_stats(org)
    assert len(stats) == 1 and stats[0]["resolved_at"] is not None


def test_first_seen_is_sticky(tmp_path):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "x.csv").write_text("\n".join(ROWS[:2]))
    s = _cfg(tmp_path, drop)
    store = Store(s.sqlite_path)
    Orchestrator(s, store=store).run()
    (drop / "x.csv").write_text(ROWS[0] + "\nAny-any allow rule on DMZ policy,4,fw-dmz-01,2026-09-30T00:00:00Z")
    r = Orchestrator(s, store=store).run()
    f = next(f for f in r.findings if f.title.startswith("Any-any"))
    assert f.first_seen.isoformat().startswith("2026-09-01")


def test_migration_from_v1_database(tmp_path):
    import sqlite3
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as c:   # minimal v1 schema with a pushed webhook item
        c.executescript("""CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, org TEXT, generated_at TEXT, result TEXT);
        CREATE TABLE findings (org TEXT, finding_id TEXT, domain TEXT, status TEXT, score REAL, horizon TEXT,
            first_seen TEXT, resolved_at TEXT, data TEXT, PRIMARY KEY (org, finding_id));
        CREATE TABLE webhook (domain TEXT, finding_id TEXT, received_at TEXT, data TEXT, PRIMARY KEY (domain, finding_id));
        INSERT INTO webhook VALUES ('waf','w1','2099-01-01T00:00:00+00:00','{"finding_id":"w1"}');""")
    st = Store(db)
    assert st.schema_version() == 3
    assert st.webhook_findings("waf", org="anything")[0]["finding_id"] == "w1"


def test_lease_lock_blocks_concurrent_run(tmp_path):
    import pytest

    st = Store(tmp_path / "k.db")
    with st.lease("run:x"):
        import threading
        err = []
        t = threading.Thread(target=lambda: err.append(_try(st)))
        t.start(); t.join()
        assert err == ["busy"]
    with st.lease("run:x"):
        pass
    assert pytest  # noqa


def _try(st):
    from lodestar.store import LockBusy
    try:
        with st.lease("run:x"):
            return "got"
    except LockBusy:
        return "busy"
