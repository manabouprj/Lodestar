from datetime import timedelta

import pytest
from conftest import AS_OF

from lodestar.models import Asset, Domain, Exposure, Finding, FindingType, Horizon, Severity
from lodestar.scoring import ScoringConfig, score_finding
from lodestar.verticals import load_vertical

BANK = load_vertical("banking")


def f(**kw):
    base = dict(finding_id="x", domain=Domain.VMDR, source="t", finding_type=FindingType.VULNERABILITY,
                title="t", severity=Severity.CRITICAL, first_seen=AS_OF - timedelta(days=2))
    base.update(kw)
    return Finding(**base)


CROWN = Asset(asset_id="a", name="gw", criticality=5, exposure=Exposure.INTERNET, business_service="Core banking")
LOW = Asset(asset_id="b", name="lab", criticality=1, exposure=Exposure.ISOLATED)


def test_kev_on_internet_crown_jewel_is_today():
    out = score_finding(f(kev=True, cve="CVE-2023-4966"), CROWN, BANK, AS_OF)
    assert out.horizon == Horizon.TODAY and out.score >= 75
    assert any("Known Exploited" in w for w in out.why)


def test_low_severity_on_isolated_lab_is_backlog():
    out = score_finding(f(severity=Severity.LOW), LOW, BANK, AS_OF)
    assert out.horizon == Horizon.BACKLOG


def test_medium_without_urgency_never_today():
    out = score_finding(f(severity=Severity.MEDIUM, domain=Domain.PAM, finding_type=FindingType.DETECTION,
                          first_seen=AS_OF - timedelta(days=90)), CROWN, BANK, AS_OF)
    assert out.score >= 75 and out.horizon != Horizon.TODAY


def test_compensating_control_reduces_score():
    a = score_finding(f(), CROWN, BANK, AS_OF).score
    b = score_finding(f(compensating_controls=["WAF virtual patch"]), CROWN, BANK, AS_OF).score
    assert b < a or a == 100


def test_score_bounded_and_explained():
    out = score_finding(f(kev=True, actively_exploited_in_env=True, correlation_ids=["c"]), CROWN, BANK, AS_OF)
    assert 0 <= out.score <= 100
    assert set(out.score_factors) >= {"severity", "exploitability", "asset_criticality", "exposure", "time_pressure"}


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        ScoringConfig(w_severity=0.5).validate()
