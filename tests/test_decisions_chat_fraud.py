import base64
import copy
import hashlib
import hmac
import json
import time

import pytest

from lodestar.chatops import ChatEngine, slack, teams
from lodestar.decisions import DecisionError, overlay, record
from lodestar.store import Store


@pytest.fixture
def res(banking_result):
    return copy.deepcopy(banking_result)


def test_decision_desk_contract(res):
    assert len(res.decisions) >= 10
    for d in res.decisions:
        assert d["deciders"] and d["options"] and d["will_not"] and d["prepared"] and d["if_no_decision"]
        assert d["urgency"] in ("now", "today", "this_week") and d["status"] == "pending"
    types = {d["type"] for d in res.decisions}
    assert {"emergency_change", "identity_containment", "fraud_response", "str_filing", "risk_acceptance"} <= types


def test_roles_and_verdicts(res, tmp_path):
    store = Store(tmp_path / "d.db")
    store.save_result(res)
    ops = next(d for d in res.decisions if d["type"] == "containment")
    reg = next(d for d in res.decisions if d.get("regulatory"))
    with pytest.raises(DecisionError):
        record(store, res, ops["decision_id"], "1", "exec")
    with pytest.raises(DecisionError):
        record(store, res, reg["decision_id"], "1", "analyst")
    out = record(store, res, ops["decision_id"], "1", "analyst", channel="test")
    assert out["status"] == "approved" and out["choice"] == ops["options"][0]
    fresh = overlay(store, store.latest_result(res.org_name))
    assert next(d for d in fresh.decisions if d["decision_id"] == ops["decision_id"])["status"] == "approved"
    rej = record(store, res, reg["decision_id"], reg["options"][-1], "ciso")
    assert rej["status"] in ("rejected", "approved", "deferred")


def test_fraud_paths_and_mlro_only_for_regulated(res, demo_dir, tmp_path):
    from lodestar.config import load_settings
    from lodestar.orchestrator import Orchestrator
    assert {"LDS-011", "LDS-012", "LDS-013"} <= {c.rule_id for c in res.correlations}
    assert any(d["type"] == "str_filing" for d in res.decisions)
    s = load_settings(overrides={"mode": "demo", "demo": {"dataset": str(demo_dir / "power_utilities.json")}})
    p = Orchestrator(s, store=Store(tmp_path / "p.db")).run(persist=False)
    assert not any(c.domain.value == "fraud" for c in p.controls)
    assert not any(d["type"] == "str_filing" for d in p.decisions)


def test_chat_engine_intents(res, tmp_path):
    eng = ChatEngine(res, "https://lodestar.example")
    brief = eng.handle("what needs attention now?")
    assert brief.intent == "brief" and "decisions needed now" in brief.lines[0] and brief.buttons
    assert eng.handle("fraud").intent == "fraud"
    assert eng.handle("help").intent == "help"
    assert eng.handle(f"why {res.decisions[0]['decision_id']}").intent == "why"
    store = Store(tmp_path / "c.db")
    store.save_result(res)
    d = next(x for x in res.decisions if x["type"] == "containment")
    rec = lambda i, c, r: record(store, res, i, c, r, channel="test")  # noqa: E731
    assert "Recorded" in eng.handle(f"approve {d['decision_id']} 1", "analyst", rec).lines[0]
    assert "can view decisions but not make them" in eng.handle(f"approve {d['decision_id']} 1", "exec", rec).lines[0]


def test_slack_signature():
    body, secret, ts = b"text=brief", "shh", str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    assert slack.verify(secret, ts, body, sig)
    assert not slack.verify(secret, str(int(time.time()) - 600), body, sig)
    assert not slack.verify(secret, ts, body + b"x", sig)


def test_teams_signature_and_card(res):
    token = base64.b64encode(b"teams-secret").decode()
    body = json.dumps({"text": "<at>LODESTAR</at> brief"}).encode()
    auth = "HMAC " + base64.b64encode(hmac.new(b"teams-secret", body, hashlib.sha256).digest()).decode()
    assert teams.verify(token, body, auth) and not teams.verify(token, body, "HMAC abc")
    act = teams.activity(ChatEngine(res).brief())
    assert act["attachments"][0]["content"]["type"] == "AdaptiveCard"
    assert teams.strip_mention("<at>LODESTAR</at> brief") == "brief"


def test_slack_blocks_have_buttons(res):
    msg = slack.message(ChatEngine(res, "https://x.example").brief())
    kinds = [b["type"] for b in msg["blocks"]]
    assert kinds[0] == "header" and "actions" in kinds and kinds[-1] == "context"
