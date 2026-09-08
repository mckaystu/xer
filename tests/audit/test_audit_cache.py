"""Tests for Neon-cached Code Analysis payloads (schema v3)."""

from __future__ import annotations

from neon_db import cached_code_audit_from_row, cached_function_inventory_from_row


def test_cached_helpers_require_schema_v3():
    row_v2 = {
        "audit_snapshot_at": "2026-09-08T15:00:00+00:00",
        "audit_snapshot": {
            "schema_version": 2,
            "code_audit": {"findings": []},
            "function_inventory": {"summary": {}},
        },
    }
    assert cached_code_audit_from_row(row_v2) is None
    assert cached_function_inventory_from_row(row_v2) is None


def test_cached_helpers_return_payloads():
    row = {
        "audit_snapshot_at": "2026-09-08T15:26:00+00:00",
        "audit_snapshot": {
            "schema_version": 3,
            "captured_at": "2026-09-08T15:26:00+00:00",
            "code_audit": {"findings": [{"id": "F1"}], "source": "x.nsf"},
            "function_inventory": {
                "summary": {"handle_safety_rate": 79.2},
                "inventory": [],
            },
        },
    }
    audit = cached_code_audit_from_row(row)
    inv = cached_function_inventory_from_row(row)
    assert audit["cached"] is True
    assert audit["cached_at"] == "2026-09-08T15:26:00+00:00"
    assert audit["findings"][0]["id"] == "F1"
    assert inv["cached"] is True
    assert inv["summary"]["handle_safety_rate"] == 79.2
