"""Deterministic rule regression tests for DOM-* and LS-DOM-* detectors.

Loads annotated fixtures from ``fixtures/lotusscript_samples.lss`` and
``fixtures/java_ssjs_samples.java`` and asserts @expect / @forbid contracts.
"""

from __future__ import annotations

import pytest

from analytics.code_auditor.models import RULE_CATALOG
from tests.audit.conftest import FixtureCase, case_to_unit, rule_ids


class TestLotusScriptHandleRules:
    def test_fixture_cases_present(self, lotusscript_cases: list[FixtureCase]):
        ids = {c.case_id for c in lotusscript_cases}
        for required in (
            "ls_dom001_leak",
            "ls_dom001_ok",
            "ls_dom005_item_leak",
            "ls_dom006_viewnav_leak",
            "ls_dom007_error_bypass",
            "ls_dom008_search_in_loop",
        ):
            assert required in ids

    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("ls_dom001_leak", "LS-DOM-001"),
            ("ls_dom002_lookup_leak", "LS-DOM-002"),
            ("ls_dom003_public", "LS-DOM-003"),
            ("ls_dom004_set_nothing", "LS-DOM-004"),
            ("ls_dom005_item_leak", "LS-DOM-005"),
            ("ls_dom006_viewnav_leak", "LS-DOM-006"),
            ("ls_dom007_error_bypass", "LS-DOM-007"),
            ("ls_dom008_search_in_loop", "LS-DOM-008"),
        ],
    )
    def test_positive_expect(self, ls_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        case = ls_cases_by_id[case_id]
        hit = rule_ids(case_to_unit(case))
        assert rule in hit, f"{case_id}: expected {rule}, got {sorted(hit)}"

    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("ls_dom001_ok", "LS-DOM-001"),
            ("ls_dom007_error_ok", "LS-DOM-007"),
            ("ls_safe_no_handles", "LS-DOM-001"),
        ],
    )
    def test_negative_forbid(self, ls_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        case = ls_cases_by_id[case_id]
        hit = rule_ids(case_to_unit(case))
        assert rule not in hit, f"{case_id}: unexpected {rule} in {sorted(hit)}"

    def test_annotation_contracts(self, lotusscript_cases: list[FixtureCase]):
        """Every LS fixture case honors its @expect / @forbid tags for handle rules."""
        for case in lotusscript_cases:
            expect = case.expect - {"PERF-001", "PERF-002", "PERF-003"}
            forbid = case.forbid - {"PERF-001", "PERF-002", "PERF-003"}
            if not expect and not forbid:
                continue
            hit = rule_ids(case_to_unit(case))
            missing = expect - hit
            unexpected = forbid & hit
            assert not missing, f"{case.case_id}: missing {sorted(missing)}; hit={sorted(hit)}"
            assert not unexpected, f"{case.case_id}: unexpected {sorted(unexpected)}; hit={sorted(hit)}"


class TestJavaHandleRules:
    def test_fixture_cases_present(self, java_cases: list[FixtureCase]):
        ids = {c.case_id for c in java_cases}
        for required in (
            "dom001_chained",
            "dom002_loop_no_recycle",
            "dom014_mime_leak",
            "dom015_viewnav_leak",
            "dom016_search_in_loop",
        ):
            assert required in ids

    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("dom001_chained", "DOM-001"),
            ("dom002_loop_no_recycle", "DOM-002"),
            ("dom003_missing_try", "DOM-003"),
            ("dom004_oda_recycle", "DOM-004"),
            ("dom006_static_handle", "DOM-006"),
            ("dom010_missing_finally", "DOM-010"),
            ("dom014_mime_leak", "DOM-014"),
            ("dom015_viewnav_leak", "DOM-015"),
            ("dom016_search_in_loop", "DOM-016"),
        ],
    )
    def test_positive_expect(self, java_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        case = java_cases_by_id[case_id]
        hit = rule_ids(case_to_unit(case))
        assert rule in hit, f"{case_id}: expected {rule}, got {sorted(hit)}"

    @pytest.mark.parametrize(
        "case_id,rule",
        [
            ("dom002_loop_ok", "DOM-002"),
            ("dom014_item_ok", "DOM-014"),
            ("java_inventory_protected", "DOM-002"),
        ],
    )
    def test_negative_forbid(self, java_cases_by_id: dict[str, FixtureCase], case_id: str, rule: str):
        case = java_cases_by_id[case_id]
        hit = rule_ids(case_to_unit(case))
        assert rule not in hit, f"{case_id}: unexpected {rule} in {sorted(hit)}"

    def test_annotation_contracts(self, java_cases: list[FixtureCase]):
        for case in java_cases:
            expect = case.expect - {"PERF-001", "PERF-002", "PERF-003"}
            forbid = case.forbid - {"PERF-001", "PERF-002", "PERF-003"}
            if not expect and not forbid:
                continue
            hit = rule_ids(case_to_unit(case))
            missing = expect - hit
            unexpected = forbid & hit
            assert not missing, f"{case.case_id}: missing {sorted(missing)}; hit={sorted(hit)}"
            assert not unexpected, f"{case.case_id}: unexpected {sorted(unexpected)}; hit={sorted(hit)}"


class TestCatalogCoverage:
    def test_handle_rules_registered(self):
        for rid in (
            *(f"DOM-{i:03d}" for i in range(1, 17)),
            *(f"LS-DOM-{i:03d}" for i in range(1, 9)),
        ):
            assert rid in RULE_CATALOG, f"missing catalog entry {rid}"

    def test_mock_graph_fires_advanced_rules(self, mock_xboss_graph: dict):
        from analytics.code_auditor import run_audit

        report = run_audit(graph=mock_xboss_graph, use_llm=False)
        ids = {f.rule_id for f in report.findings}
        for rid in ("LS-DOM-001", "LS-DOM-005", "LS-DOM-007", "DOM-014", "DOM-015", "DOM-016"):
            assert rid in ids, f"mock graph missing {rid}; got {sorted(ids)}"
