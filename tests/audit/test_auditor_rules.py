"""Deterministic rule regression tests for DOM-* detectors (Handle Exhaustion).

LS-DOM-* is not wired into the auditor — LotusScript is out of scope for
C-API handle exhaustion. LotusScript fixtures still exercise PERF/SEC and
confirm no LS-DOM findings are emitted.
"""

from __future__ import annotations

import pytest

from analytics.code_auditor.models import RULE_CATALOG
from tests.audit.conftest import FixtureCase, case_to_unit, rule_ids


class TestLotusScriptHandleRulesDisabled:
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
        "case_id",
        [
            "ls_dom001_leak",
            "ls_dom002_lookup_leak",
            "ls_dom003_public",
            "ls_dom004_set_nothing",
            "ls_dom005_item_leak",
            "ls_dom006_viewnav_leak",
            "ls_dom007_error_bypass",
            "ls_dom008_search_in_loop",
            "ls_dom001_ok",
            "ls_dom007_error_ok",
            "ls_safe_no_handles",
        ],
    )
    def test_ls_dom_not_emitted(self, ls_cases_by_id: dict[str, FixtureCase], case_id: str):
        case = ls_cases_by_id[case_id]
        hit = rule_ids(case_to_unit(case))
        assert not any(r.startswith("LS-DOM") for r in hit), f"{case_id}: unexpected LS-DOM in {sorted(hit)}"

    def test_annotation_contracts_ignore_ls_expect(self, lotusscript_cases: list[FixtureCase]):
        """LotusScript units emit no findings from this auditor."""
        for case in lotusscript_cases:
            hit = rule_ids(case_to_unit(case))
            assert hit == set(), f"{case.case_id}: unexpected findings {sorted(hit)}"


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
            expect = case.expect - {"PERF-001", "PERF-002", "PERF-003", "PERF-004"}
            forbid = case.forbid - {"PERF-001", "PERF-002", "PERF-003", "PERF-004"}
            expect = {r for r in expect if not r.startswith("LS-DOM")}
            forbid = {r for r in forbid if not r.startswith("LS-DOM")}
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
            *(f"LS-DOM-{i:03d}" for i in range(1, 9)),  # catalog retained; detectors unwired
        ):
            assert rid in RULE_CATALOG, f"missing catalog entry {rid}"

    def test_mock_graph_no_ls_dom_java_advanced_rules_fire(self, mock_xboss_graph: dict):
        from analytics.code_auditor import run_audit

        report = run_audit(graph=mock_xboss_graph, use_llm=False)
        ids = {f.rule_id for f in report.findings}
        assert not any(r.startswith("LS-DOM") for r in ids), f"unexpected LS-DOM: {sorted(ids)}"
        for rid in ("DOM-014", "DOM-015", "DOM-016"):
            assert rid in ids, f"mock graph missing {rid}; got {sorted(ids)}"
