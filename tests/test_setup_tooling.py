import hashlib
import hmac
import json
from pathlib import Path

from lodestar.cli import main
from lodestar.config import load_dotenv

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "webhooks" / "waf_findings.json"


def test_dotenv_loader_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('# c\nLODESTAR_X1="quoted value"\nexport LODESTAR_X2=plain\nLODESTAR_X3=keep\nEMPTY=\n')
    monkeypatch.setenv("LODESTAR_X3", "already-set")
    monkeypatch.delenv("LODESTAR_X1", raising=False)
    monkeypatch.delenv("LODESTAR_X2", raising=False)
    assert load_dotenv(env) == 2
    import os
    assert os.environ["LODESTAR_X1"] == "quoted value" and os.environ["LODESTAR_X2"] == "plain"
    assert os.environ["LODESTAR_X3"] == "already-set"
    monkeypatch.delenv("LODESTAR_X1"); monkeypatch.delenv("LODESTAR_X2")


def test_test_connector_cli_demo(demo_dir, capsys):
    rc = main(["test-connector", "edr", "--dataset", str(demo_dir / "banking.json"), "--show", "2"])
    out = capsys.readouterr().out
    assert rc == 0 and "RESULT    : OK" in out and "matched to CMDB" in out
    assert main(["test-connector", "not-a-domain"]) == 2


def test_webhook_with_health_block(client):
    body = SAMPLE.read_bytes()
    sig = "sha256=" + hmac.new(b"s3cret-for-tests", body, hashlib.sha256).hexdigest()
    r = client.post("/api/ingest/waf", content=body, headers={"X-Lodestar-Signature": sig})
    assert r.status_code == 202 and r.json()["accepted"] == 2
    health_only = json.dumps({"health": {"coverage_pct": 77}}).encode()
    sig2 = "sha256=" + hmac.new(b"s3cret-for-tests", health_only, hashlib.sha256).hexdigest()
    assert client.post("/api/ingest/waf", content=health_only, headers={"X-Lodestar-Signature": sig2}).status_code == 202
    from lodestar.api.app import get_store
    _, h = get_store().webhook_health("waf")
    assert h["coverage_pct"] == 77 and h["kpis"]["block_mode_pct"] == 85
