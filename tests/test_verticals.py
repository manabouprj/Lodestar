import pytest

from lodestar.models import Domain
from lodestar.verticals import list_verticals, load_vertical


def test_all_verticals_load():
    vs = list_verticals()
    assert {"aviation", "banking", "fintech", "retail", "energy", "power_utilities", "telecom", "logistics_ports"} <= set(vs)
    for v in vs:
        p = load_vertical(v)
        assert p.kris and p.frameworks and p.sla_days["critical"] > 0
        assert all(d in {x.value for x in Domain} for d in p.mandatory_domains)


def test_inheritance_appends_kris_and_keeps_defaults():
    p = load_vertical("power_utilities")
    metrics = [k["metric"] for k in p.kris]
    assert "posture_score" in metrics and "ot_unmanaged_remote_access_count" in metrics
    assert p.weight("ot") > 1.0 and p.weight("email") == 1.0


def test_unknown_domain_rejected(tmp_path):
    (tmp_path / "_default.yaml").write_text("id: _default\nname: d\nkris: []\n")
    (tmp_path / "bad.yaml").write_text("inherits: _default\nname: Bad\ndomain_weights: {mainframe: 2}\n")
    with pytest.raises(ValueError):
        load_vertical("bad", str(tmp_path))
