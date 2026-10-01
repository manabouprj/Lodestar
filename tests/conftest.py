import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
AS_OF = datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory):
    from lodestar.demo.generator import generate
    d = tmp_path_factory.mktemp("demo")
    for v in ("banking", "power_utilities"):
        generate(v, d, AS_OF, history_days=45)
    return d


@pytest.fixture(scope="session")
def banking_result(demo_dir, tmp_path_factory):
    from lodestar.config import load_settings
    from lodestar.orchestrator import Orchestrator
    from lodestar.store import Store
    s = load_settings(overrides={"mode": "demo", "demo": {"dataset": str(demo_dir / "banking.json")}})
    store = Store(tmp_path_factory.mktemp("db") / "t.db")
    return Orchestrator(s, store=store).run()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("LODESTAR_API_KEYS", "LODESTAR_WEBHOOK_SECRET", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
