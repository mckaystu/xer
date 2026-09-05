"""Performance & NIF anti-pattern regression tests (PERF-001..003)."""

from __future__ import annotations

import pytest

from analytics.code_auditor.models import RULE_CATALOG
from tests.audit.conftest import FixtureCase, case_to_unit, rule_ids


class TestPerfCatalog:
    def test_perf_rules_registered(self):
        for rid in ("PERF-001", "PERF-002", "PERF-003"):
            assert rid in RULE_CATALOG
            assert RULE_CATALOG[rid]["category"] == "Performance & NIF Indexing"


class TestPerfLotusScript:
    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("ls_perf001_no_autoupdate", "PERF-001"),
            ("ls_perf002_getview_loop", "PERF-002"),
            ("ls_perf003_save_loop", "PERF-003"),
        ],
    )
    def test_positive(self, ls_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        hit = rule_ids(case_to_unit(ls_cases_by_id[case_id]))
        assert rule in hit, f"{case_id}: expected {rule}, got {sorted(hit)}"

    def test_autoupdate_false_suppresses_perf001(self, ls_cases_by_id: dict[str, FixtureCase]):
        hit = rule_ids(case_to_unit(ls_cases_by_id["ls_perf001_ok"]))
        assert "PERF-001" not in hit


class TestPerfJava:
    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("perf001_no_autoupdate", "PERF-001"),
            ("perf002_getview_loop", "PERF-002"),
            ("perf003_save_loop", "PERF-003"),
        ],
    )
    def test_positive(self, java_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        hit = rule_ids(case_to_unit(java_cases_by_id[case_id]))
        assert rule in hit, f"{case_id}: expected {rule}, got {sorted(hit)}"

    def test_autoupdate_false_suppresses_perf001(self, java_cases_by_id: dict[str, FixtureCase]):
        hit = rule_ids(case_to_unit(java_cases_by_id["perf001_ok"]))
        assert "PERF-001" not in hit

    def test_perf_findings_include_impact_callout(self, java_cases_by_id: dict[str, FixtureCase]):
        from analytics.code_auditor.rules import run_rule_engine

        unit = case_to_unit(java_cases_by_id["perf001_no_autoupdate"])
        findings = [f for f in run_rule_engine([unit]) if f.rule_id == "PERF-001"]
        assert findings
        impact = findings[0].technical_impact or ""
        assert "PERF-001" in impact
        assert "AutoUpdate" in impact or "NIF" in impact or "index" in impact.lower()


class TestPerfViaGraphAudit:
    def test_mock_graph_includes_perf_findings(self, mock_xboss_graph: dict):
        from analytics.code_auditor import run_audit

        report = run_audit(graph=mock_xboss_graph, use_llm=False)
        ids = {f.rule_id for f in report.findings}
        assert "PERF-001" in ids or "PERF-002" in ids or "PERF-003" in ids
        payload = report.to_dict()
        assert "findings" in payload
        perf = [f for f in payload["findings"] if str(f["rule_id"]).startswith("PERF-")]
        assert perf
        assert all(f.get("category", "").find("Performance") >= 0 or f["rule_id"].startswith("PERF-") for f in perf)
