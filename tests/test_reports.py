import json

import pytest

from lodestar.agents.core.narrative import numbers_grounded, template_summary
from lodestar.dashboard import build_payload
from lodestar.reporting import exposure_estimate, render
from lodestar.web import render_dashboard


@pytest.mark.parametrize("period", ["weekly", "monthly", "quarterly"])
def test_reports_render_all_formats(banking_result, period):
    html = render(banking_result, period, "html")
    assert "<html" in html and "Executive summary" in html and "Key risk indicators" in html
    md = render(banking_result, period, "md")
    assert md.startswith("#") and "&amp;" not in md
    data = json.loads(render(banking_result, period, "json"))
    assert data["posture"] == banking_result.snapshot.posture_score


def test_board_report_has_decisions_and_exposure(banking_result):
    html = render(banking_result, "quarterly", "html")
    assert "Decisions requested" in html and "Indicative financial exposure" in html
    ex = exposure_estimate(banking_result)
    assert ex["rows"] and ex["range"].startswith("USD")


def test_numeric_guardrail_rejects_hallucinated_numbers():
    facts = {"posture_score": 63.7, "today": 25, "kris": [{"value": 95.5}]}
    assert numbers_grounded("Posture is 63.7 with 25 items; EDR at 95.5%.", facts)[0]
    ok, bad = numbers_grounded("Posture is 71 and we saved 4.2 million.", facts)
    assert not ok and "71" in bad


def test_template_summary_runs_without_llm():
    txt = template_summary({"posture_score": 60, "posture_prev": 55, "today": 3, "week": 9, "total_open": 400,
                            "controls": 12, "attack_paths": 0, "kris": []}, "weekly")
    assert "60/100" in txt and "up 5" in txt


def test_dashboard_export_is_self_contained(banking_result):
    html = render_dashboard([build_payload(banking_result)], demo=True)
    assert "</script>" in html and "LODESTAR_DATA = {" in html
    assert "<\\/" in html or "</" not in html.split("LODESTAR_DATA = ", 1)[1].split(";\n", 1)[0]
