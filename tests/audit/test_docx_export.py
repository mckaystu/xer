"""Tests for Word checklist export of Code Analysis findings."""

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
    assert slug_filename("xBoss REST Services").endswith("_handle_checklist.docx")
    assert " " not in slug_filename("xBoss REST Services")


def test_build_checklist_docx_contains_finding_text():
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
            # LotusScript should be excluded from checklist
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
            "unprotected_functions": 1,
            "total_functions_scanned": 10,
        },
        "inventory": [
            {
                "function_name": "uploadFile",
                "design_element": "ssjs",
                "language": "javascript",
                "status": "UNPROTECTED_ALLOCATION",
            }
        ],
    }
    data = build_code_audit_checklist_docx(
        report,
        database_title="xBoss REST Services",
        nsf_path="bossrest.nsf",
        inventory=inventory,
    )
    assert data[:2] == b"PK"  # zip/docx magic
    assert len(data) > 2000

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml = zf.read("word/document.xml").decode("utf-8")
    assert "Handle Exhaustion" in xml
    assert "exportUnprocessed" in xml or "Session not recycled" in xml
    assert "Document leak in loop" in xml
    assert "LS ignored" not in xml
    assert "uploadFile" in xml
    assert "Developer Checklist" in xml or "Working checklist" in xml
