"""Tests for Word priority checklist export."""

from __future__ import annotations

import io
import zipfile

from analytics.code_auditor.docx_export import build_code_audit_checklist_docx, slug_filename
from analytics.code_auditor.models import AuditReport, Finding


def _finding(**kwargs) -> Finding:
    base = dict(
        id="F-001",
        rule_id="DOM-001",
        title="Session not recycled",
        severity="HIGH",
        confidence=90,
        source_file="Boss.java",
        element_name="exportUnprocessed",
        element_type="java",
        language="java",
        line=42,
        evidence="Session s = NotesFactory.createSession();",
        technical_impact="Handle table growth",
        remediation="s.recycle();",
        action_required="Add recycle in finally",
        category="handle",
        code_snippet_as_is="Session s = NotesFactory.createSession();",
        code_snippet_to_be="try { ... } finally { if (s != null) s.recycle(); }",
    )
    base.update(kwargs)
    return Finding(**base)


def test_slug_filename():
    assert slug_filename("xBoss REST Services").endswith("_priority_checklist.docx")
    assert " " not in slug_filename("xBoss REST Services")


def test_build_checklist_docx_priority_functions():
    report = AuditReport(
        source="test.nsf",
        files_scanned=1,
        blocks_scanned=2,
        blocks_prefiltered=1,
        findings=[
            _finding(),
            _finding(
                id="F-002",
                rule_id="DOM-002",
                title="Document leak in loop",
                severity="CRITICAL",
                language="javascript",
                element_name="uploadFile",
            ),
            _finding(
                id="F-LS",
                rule_id="DOM-001",
                title="LS ignored",
                language="lotusscript",
                element_name="Initialize",
            ),
        ],
    )
    inventory = {
        "summary": {
            "handle_safety_rate": 79.2,
            "recycle_coverage_rate": 0,
            "unprotected_functions": 2,
            "total_functions_scanned": 10,
            "functions_partial_cleanup": 1,
            "functions_conditional_cleanup": 0,
            "functions_escape_path_gap": 0,
        },
        "inventory": [
            {
                "function_name": "safeHelper",
                "design_element": "Utils",
                "language": "java",
                "status": "SAFE_NO_HANDLES",
                "risk_severity": "LOW",
            },
            {
                "function_name": "mediumPartial",
                "design_element": "Lib",
                "language": "java",
                "status": "PARTIAL_CLEANUP",
                "risk_severity": "MEDIUM",
                "in_loop": False,
                "allocates_handles": True,
                "recycle_call_count": 1,
            },
            {
                "function_name": "uploadFile",
                "design_element": "ssjs",
                "language": "javascript",
                "status": "UNPROTECTED_ALLOCATION",
                "risk_severity": "CRITICAL",
                "in_loop": True,
                "allocates_handles": True,
                "recycle_call_count": 0,
                "problem_breakdown": "Allocates in loop without recycle",
                "remediation_guide": "recycle in finally",
            },
            {
                "function_name": "exportUnprocessed",
                "design_element": "Boss",
                "language": "java",
                "status": "UNPROTECTED_ALLOCATION",
                "risk_severity": "HIGH",
                "in_loop": False,
                "allocates_handles": True,
                "recycle_call_count": 0,
            },
        ],
    }
    data = build_code_audit_checklist_docx(
        report,
        database_title="xBoss REST Services",
        nsf_path="bossrest.nsf",
        inventory=inventory,
    )
    assert data[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml = zf.read("word/document.xml").decode("utf-8")
    assert "Priority Checklist" in xml or "Condensed analysis" in xml
    assert "uploadFile" in xml
    assert "exportUnprocessed" in xml
    assert "mediumPartial" in xml
    assert "safeHelper" not in xml  # not actionable
    assert "LS ignored" not in xml
    # Priority order: CRITICAL uploadFile before HIGH exportUnprocessed
    assert xml.index("uploadFile") < xml.index("exportUnprocessed")
    assert "Document leak in loop" in xml
