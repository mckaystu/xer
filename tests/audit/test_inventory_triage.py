"""Tests for inventory FP triage helpers."""

from __future__ import annotations

from analytics.code_auditor.function_inventory import FunctionRecord, summarize_inventory
from neon_db import apply_triage_overrides


def _rec(**kwargs) -> FunctionRecord:
    base = dict(
        id="FUNC-001",
        design_element="Lib",
        function_name="uploadFile",
        language="javascript",
        allocates_handles=True,
        recycle_call_count=0,
        status="UNPROTECTED_ALLOCATION",
        loc=20,
        risk_severity="CRITICAL",
        in_loop=True,
    )
    base.update(kwargs)
    return FunctionRecord(**base)


def test_summarize_excludes_false_positives_from_unprotected():
    records = [
        _rec(id="FUNC-001"),
        _rec(id="FUNC-002", function_name="other", is_false_positive=True, risk_severity="LOW"),
        _rec(
            id="FUNC-003",
            function_name="safe",
            allocates_handles=False,
            status="SAFE_NO_HANDLES",
            risk_severity="LOW",
        ),
    ]
    summary = summarize_inventory(records)
    assert summary["unprotected_functions"] == 1
    assert summary["false_positive_functions"] == 1
    assert summary["total_functions_scanned"] == 3


def test_apply_triage_overrides_inventory_and_findings():
    inventory = {
        "summary": {},
        "inventory": [
            {"id": "FUNC-001", "status": "UNPROTECTED_ALLOCATION", "is_false_positive": False},
            {"id": "FUNC-002", "status": "UNPROTECTED_ALLOCATION", "is_false_positive": True},
        ],
    }
    audit = {
        "findings": [
            {"id": "F-001", "is_false_positive": False, "severity": "HIGH"},
        ]
    }
    overrides = {
        "inventory": {
            "FUNC-001": {
                "is_false_positive": True,
                "reason": "caller recycles",
                "source": "human",
                "ai_validation_status": "FALSE_POSITIVE",
            },
            "FUNC-002": {
                "is_false_positive": False,
                "reason": "Cleared by reviewer",
                "source": "human",
                "ai_validation_status": "",
            },
        },
        "findings": {
            "F-001": {
                "is_false_positive": True,
                "reason": "ODA",
                "source": "human",
                "ai_validation_status": "FALSE_POSITIVE",
            }
        },
    }
    apply_triage_overrides(audit, inventory, overrides)
    assert inventory["inventory"][0]["is_false_positive"] is True
    assert inventory["inventory"][1]["is_false_positive"] is False
    assert audit["findings"][0]["is_false_positive"] is True
    assert audit["findings"][0]["severity"] == "LOW"
