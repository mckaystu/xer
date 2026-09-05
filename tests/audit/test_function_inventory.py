"""Function inventory & handle-safety / recycle-coverage regression tests."""

from __future__ import annotations

import pytest

from analytics.code_auditor.function_inventory import build_inventory, run_function_inventory, summarize_inventory
from analytics.code_auditor.models import CodeUnit
from tests.audit.conftest import FixtureCase, case_to_unit


def _status_for(unit: CodeUnit, fn_name: str | None = None) -> str:
    recs = build_inventory([unit])
    assert recs, f"no inventory for {unit.element_name}"
    if fn_name:
        match = [r for r in recs if r.function_name == fn_name]
        assert match, f"{fn_name} not in {[r.function_name for r in recs]}"
        return match[0].status
    return recs[0].status


class TestInventoryClassification:
    def test_protected_lotusscript_loop(self, ls_cases_by_id: dict[str, FixtureCase]):
        unit = case_to_unit(ls_cases_by_id["ls_inventory_protected"])
        assert _status_for(unit, "LsInventoryProtected") == "PROTECTED"

    def test_unprotected_leak_loop(self, ls_cases_by_id: dict[str, FixtureCase]):
        unit = case_to_unit(ls_cases_by_id["ls_dom001_leak"])
        status = _status_for(unit, "LsDom001Leak")
        assert status == "UNPROTECTED_ALLOCATION"

    def test_safe_no_handles(self, ls_cases_by_id: dict[str, FixtureCase]):
        unit = case_to_unit(ls_cases_by_id["ls_safe_no_handles"])
        assert _status_for(unit, "LsSafeNoHandles") == "SAFE_NO_HANDLES"

    def test_protected_java_walk(self, java_cases_by_id: dict[str, FixtureCase]):
        unit = case_to_unit(java_cases_by_id["java_inventory_protected"])
        assert _status_for(unit, "protectedWalk") == "PROTECTED"

    def test_unprotected_java_loop(self, java_cases_by_id: dict[str, FixtureCase]):
        unit = case_to_unit(java_cases_by_id["dom002_loop_no_recycle"])
        assert _status_for(unit, "walk") == "UNPROTECTED_ALLOCATION"
        assert "recycle" not in unit.body


class TestInventorySummaryMetrics:
    def test_summarize_rates(self, ls_cases_by_id: dict[str, FixtureCase]):
        units = [
            case_to_unit(ls_cases_by_id["ls_inventory_protected"]),
            case_to_unit(ls_cases_by_id["ls_dom001_leak"]),
            case_to_unit(ls_cases_by_id["ls_safe_no_handles"]),
        ]
        recs = build_inventory(units)
        summary = summarize_inventory(recs)
        assert summary["total_functions_scanned"] >= 3
        assert 0 <= summary["handle_safety_rate"] <= 100
        assert 0 <= summary["recycle_coverage_rate"] <= 100
        # One protected + one safe + one unprotected → safety = 2/3 ≈ 66.7
        assert summary["unprotected_functions"] >= 1
        assert summary["functions_with_cleanup"] >= 1
        assert summary["functions_safe_no_handles"] >= 1

    def test_run_function_inventory_on_mock_graph(self, mock_xboss_graph: dict):
        result = run_function_inventory(graph=mock_xboss_graph)
        summary = result["summary"]
        inventory = result["inventory"]
        assert summary["total_functions_scanned"] >= 1
        assert isinstance(inventory, list)
        assert inventory
        statuses = {row["status"] for row in inventory}
        assert statuses & {"PROTECTED", "UNPROTECTED_ALLOCATION", "SAFE_NO_HANDLES"}
        # Primary UX metric present for Code Analysis ring
        assert "handle_safety_rate" in summary
        assert "recycle_coverage_rate" in summary


class TestInventoryEdgeCases:
    def test_empty_graph(self):
        result = run_function_inventory(graph={"business_logic": []})
        assert result["summary"]["total_functions_scanned"] == 0
        assert result["summary"]["handle_safety_rate"] == 100.0

    def test_formula_blocks_skipped(self):
        graph = {
            "business_logic": [
                {
                    "language": "formula",
                    "owner_name": "Computed",
                    "owner_type": "field",
                    "body": '@If(1=1;"Y";"N")',
                    "source_file": "f.dxl",
                }
            ]
        }
        result = run_function_inventory(graph=graph)
        assert result["summary"]["total_functions_scanned"] == 0
