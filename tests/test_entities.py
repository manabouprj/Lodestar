from lodestar.entities import EntityResolver, Identity
from lodestar.models import Asset

ASSETS = {a.asset_id: a for a in [
    Asset(asset_id="dxb-tos-db-01", name="TOS database", aliases=["tos-db.corp.example"], ips=["10.1.2.3"],
          macs=["00-1A-2B-3C-4D-5E"], external_ids=["mde:8f1c2d"]),
    Asset(asset_id="web01.dmz.example", name="Web 01"),
    Asset(asset_id="web01.corp.example", name="Web 01 internal"),
    Asset(asset_id="portal", name="Portal", aliases=["*.portal.example"]),
]}


def test_host_resolution_methods():
    r = EntityResolver(ASSETS)
    assert r.asset("DXB-TOS-DB-01.corp.example") == ("dxb-tos-db-01", "short-name")
    assert r.asset("https://tos-db.corp.example:8443/x")[0] == "dxb-tos-db-01"
    assert r.asset(None, "10.1.2.3") == ("dxb-tos-db-01", "ip")
    assert r.asset("00:1a:2b:3c:4d:5e") == ("dxb-tos-db-01", "mac")
    assert r.asset("mde:8f1c2d")[0] == "dxb-tos-db-01"
    assert r.asset("api.portal.example") == ("portal", "wildcard")


def test_ambiguous_short_name_is_not_guessed():
    r = EntityResolver(ASSETS)
    assert r.asset("WEB01") == (None, "unmatched")
    assert "web01" in r.ambiguous
    assert r.asset("web01.dmz.example")[0] == "web01.dmz.example"


def test_identity_resolution():
    ids = [Identity(identity_id="j.doe@corp.example", upn="j.doe@corp.example", email="john.doe@corp.example",
                    sam="corp\\jdoe", entra_object_id="6f1c-aa")]
    r = EntityResolver({}, ids, primary_domain="corp.example", domains=["corp-mail.example"])
    assert r.user("JOHN.DOE@corp.example")[0] == "j.doe@corp.example"
    assert r.user("CORP\\jdoe")[0] == "j.doe@corp.example"
    assert r.user("jdoe")[0] == "j.doe@corp.example"
    assert r.user("6F1C-AA")[0] == "j.doe@corp.example"
    assert r.user("a.khan@corp-mail.example") == ("a.khan@corp.example", "normalised")
    assert r.user("partner@other.example") == ("partner@other.example", "normalised")


def test_pipeline_correlates_across_naming(tmp_path):
    """EDR reports an FQDN, VMDR a short name - they must land on the same asset so LDS-002 can fire."""
    from datetime import datetime, timezone

    from lodestar.agents.base import AgentContext, PipelineState
    from lodestar.agents.core import CorrelationAgent, DataQualityAgent
    from lodestar.config import load_settings
    from lodestar.models import Domain, Finding, FindingType, Severity
    from lodestar.verticals import load_vertical
    s = load_settings()
    st = PipelineState(assets={"dxb-tos-db-01": Asset(asset_id="dxb-tos-db-01", name="TOS DB", criticality=5)})
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    st.findings = [
        Finding(finding_id="e1", domain=Domain.EDR, source="t", finding_type=FindingType.COVERAGE_GAP, title="no sensor",
                severity=Severity.MEDIUM, asset_id="DXB-TOS-DB-01.corp.example"),
        Finding(finding_id="v1", domain=Domain.VMDR, source="t", finding_type=FindingType.VULNERABILITY, title="crit",
                severity=Severity.CRITICAL, asset_id="dxb-tos-db-01")]
    ctx = AgentContext(settings=s, vertical=load_vertical("banking"), now=now)
    st = DataQualityAgent()(ctx, st)
    st = CorrelationAgent()(ctx, st)
    assert {f.asset_id for f in st.findings} == {"dxb-tos-db-01"}
    assert any(c.rule_id == "LDS-002" for c in st.correlations)
