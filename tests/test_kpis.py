"""KPI sourcing: provenance, lifecycle-measured KPIs, manual staleness, honest 'not measured'."""
from datetime import datetime, timedelta, timezone

from lodestar.metrics import compute_kris, kri_coverage, lifecycle_kpis, manual_kpis, posture_score
from lodestar.models import ControlHealth, Domain, Finding, FindingType, Severity
from lodestar.verticals import load_vertical

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _vuln(i, sev=Severity.CRITICAL, due_days=10):
    return Finding(finding_id=f"v{i}", domain=Domain.VMDR, source="t", finding_type=FindingType.VULNERABILITY,
                   title="x", severity=sev, first_seen=NOW - timedelta(days=5), due_date=NOW + timedelta(days=due_days))


def test_missing_tools_are_not_measured_not_perfect():
    kris = compute_kris([], [], [], {}, NOW)
    assert "critical_vuln_sla_pct" not in kris and "kev_open_count" not in kris
    edr = ControlHealth(domain=Domain.EDR, product="x", coverage_pct=100.0,
                        health_issues=["Coverage not reported - set settings.health.coverage_pct"])
    kris = compute_kris([], [edr], [], {}, NOW)
    assert "edr_coverage_pct" not in kris            # an unreported coverage is not 100%
    assert kris["toxic_combinations_open"] == 0      # LODESTAR's own count is valid once anything is integrated


def test_provenance_precedence_connector_over_lifecycle_over_manual():
    vm = ControlHealth(domain=Domain.VMDR, product="t", coverage_pct=99, kpis={"critical_sla_pct": 91.0})
    prov = {}
    kris = compute_kris([], [vm], [], {}, NOW, computed={"critical_vuln_sla_pct": 70.0, "mttr_critical_days": 9.0},
                        manual={"mttr_critical_days": 30.0, "phishing_click_rate_pct": 4.0},
                        manual_sources={"phishing_click_rate_pct": "manual: awareness report (2026-09-01)"}, provenance=prov)
    assert kris["critical_vuln_sla_pct"] == 91.0 and prov["critical_vuln_sla_pct"] == "connector:vmdr"
    assert kris["mttr_critical_days"] == 9.0 and prov["mttr_critical_days"] == "lodestar:lifecycle"
    assert kris["phishing_click_rate_pct"] == 4.0 and prov["phishing_click_rate_pct"].startswith("manual")
    assert prov["kev_open_count"] == "lodestar:findings"


def test_lifecycle_kpis_from_history():
    stats = [{"severity": "critical", "domain": "vmdr", "first_seen": NOW - timedelta(days=d + 10),
              "resolved_at": NOW - timedelta(days=10), "due_date": NOW - timedelta(days=10 + d - 15)} for d in (4, 8, 12, 20)]
    k = lifecycle_kpis(stats, [_vuln(1), _vuln(2, due_days=-1)], NOW)
    assert k["mttr_critical_days"] == 11.0
    # closed: 3 within the 15-day SLA, 1 late; open: 1 on time, 1 overdue -> 4/6
    assert k["critical_vuln_sla_pct"] == 66.7
    assert lifecycle_kpis(stats[:2], [], NOW) == {}   # too few samples to publish a number


def test_manual_kpis_expire():
    vals, prov, stale = manual_kpis({
        "phishing_click_rate_pct": {"value": 4.2, "as_of": "2026-09-01", "source": "Q3 report"},
        "mttd_hours": {"value": 3, "as_of": "2026-01-01", "max_age_days": 90},
        "backup_immutability_pct": {"value": 99}}, NOW)
    assert vals == {"phishing_click_rate_pct": 4.2} and "Q3 report" in prov["phishing_click_rate_pct"]
    assert set(stale) == {"mttd_hours", "backup_immutability_pct"}


def test_unmeasured_kris_cannot_raise_posture():
    v = load_vertical("banking")
    good = {k["metric"]: (k["appetite"] * 1.1 if k["direction"] == "higher_better" else 0) for k in v.kris}
    some = dict(list(good.items())[:2])
    assert posture_score(some, [], [], [], v) < posture_score(good, [], [], [], v)
    cov, missing = kri_coverage(some, v)
    assert cov < 30 and missing
