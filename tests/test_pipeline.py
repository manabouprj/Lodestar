import json

from lodestar.config import load_settings
from lodestar.models import Horizon, Status
from lodestar.orchestrator import Orchestrator
from lodestar.store import Store


def test_pipeline_produces_focused_today_list(banking_result):
    r = banking_result
    act = [f for f in r.findings if f.status in (Status.OPEN, Status.IN_PROGRESS)]
    today = [f for f in act if f.horizon == Horizon.TODAY]
    assert len(r.findings) > 1000
    assert 5 <= len(today) <= 60
    assert len(today) / len(act) < 0.05          # noise reduction is the point
    assert all(f.why for f in today)
    assert 0 <= r.snapshot.posture_score <= 100


def test_scripted_attack_paths_are_found(banking_result):
    rules = {c.rule_id for c in banking_result.correlations}
    assert {"LDS-001", "LDS-002", "LDS-003", "LDS-004", "LDS-005", "LDS-006", "LDS-007", "LDS-008", "LDS-010"} <= rules


def test_ot_rule_only_for_ot_verticals(demo_dir, tmp_path):
    s = load_settings(overrides={"mode": "demo", "demo": {"dataset": str(demo_dir / "power_utilities.json")}})
    r = Orchestrator(s, store=Store(tmp_path / "p.db")).run(persist=False)
    assert "LDS-009" in {c.rule_id for c in r.correlations}



def test_ot_rule_absent_for_banking(banking_result):
    assert "LDS-009" not in {c.rule_id for c in banking_result.correlations}


def test_phase_gating(demo_dir, tmp_path):
    s = load_settings(overrides={"mode": "demo", "deployment_phase": 1,
                                 "demo": {"dataset": str(demo_dir / "banking.json")}})
    r = Orchestrator(s, store=Store(tmp_path / "p1.db")).run(persist=False)
    assert {c.domain.value for c in r.controls} <= {"edr", "vmdr", "identity", "soc", "email"}
    assert r.correlations == []                   # correlation is a phase-2 agent
    assert r.data_quality["phase"] == 1


def test_generator_is_deterministic(demo_dir, tmp_path):
    from conftest import AS_OF

    from lodestar.demo.generator import generate
    p = generate("banking", tmp_path, AS_OF, history_days=45)
    a = json.loads(p.read_text())
    b = json.loads((demo_dir / "banking.json").read_text())
    assert a["domains"] == b["domains"] and a["history"] == b["history"]


def test_store_round_trip_and_history(banking_result, tmp_path):
    store = Store(tmp_path / "s.db")
    store.save_result(banking_result)
    back = store.latest_result(banking_result.org_name)
    assert back and len(back.findings) == len(banking_result.findings)
    assert len(banking_result.history) >= 30


def test_agent_failure_is_isolated(demo_dir, tmp_path, monkeypatch):
    from lodestar.agents.core import correlation
    monkeypatch.setattr(correlation.CorrelationAgent, "run", lambda self, ctx, st: 1 / 0)
    s = load_settings(overrides={"mode": "demo", "demo": {"dataset": str(demo_dir / "banking.json")}})
    r = Orchestrator(s, store=Store(tmp_path / "f.db")).run(persist=False)
    assert r.data_quality["agent_failures"][0]["agent"] == "CorrelationAgent"
    assert r.snapshot.posture_score > 0
