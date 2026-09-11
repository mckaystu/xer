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
                "code_snippet_as_is": (
                    "   10 | var doc = view.getFirstDocument();\n"
                    "   11▶| while (doc != null) {\n"
                    "   12 |   doc = view.getNextDocument(doc);\n"
                    "   13 | }"
                ),
                "code_snippet_to_be": (
                    "Document doc = view.getFirstDocument();\n"
                    "while (doc != null) {\n"
                    "  Document nextDoc = view.getNextDocument(doc);\n"
                    "  try {\n"
                    "    // Process current document\n"
                    "  } finally {\n"
                    "    doc.recycle(); // Release native C-API handle\n"
                    "  }\n"
                    "  doc = nextDoc;\n"
                    "}"
                ),
                "code_snippet_lines": [
                    {"line": 10, "text": "var doc = view.getFirstDocument();", "highlight": False},
                    {"line": 11, "text": "while (doc != null) {", "highlight": True},
                    {"line": 12, "text": "  doc = view.getNextDocument(doc);", "highlight": False},
                    {"line": 13, "text": "}", "highlight": False},
                ],
                "highlight_line": 11,
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
                "code_snippet_as_is": "Session s = NotesFactory.createSession();",
                "code_snippet_to_be": "try { ... } finally { if (s != null) s.recycle(); }",
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
    # Bad code present; generic To-Be templates omitted
    assert "Bad code" in xml
    assert "view.getNextDocument(doc)" in xml
    assert "Release native C-API handle" not in xml
    assert "Process current document" not in xml
    assert "Notes: " not in xml  # dropped per-item notes lines for brevity
    # Yellow highlight applied to problem line(s)
    assert "w:highlight" in xml and 'w:val="yellow"' in xml


def test_build_code_analysis_rubric_docx():
    from analytics.code_auditor.docx_export import build_code_analysis_rubric_docx

    data = build_code_analysis_rubric_docx()
    assert data[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml = zf.read("word/document.xml").decode("utf-8")
    assert "Rules &amp; Rubric" in xml or "Rules & Rubric" in xml
    assert "DOM-002" in xml
    assert "Pass 1" in xml
    assert "Pass 2" in xml
    assert "Pass 3" in xml
    assert "Static search rules" in xml or "search rules" in xml.lower()
    assert "LS-DOM" not in xml
    assert "LotusScript Handle Lifecycle" not in xml
    assert "hygiene reference" not in xml.lower()
    # Formula Quality is not C-API handle exhaustion — omit from handle rubric
    assert "FORM-001" not in xml
    assert "Formula Quality" not in xml
    assert "Handle Exhaustion = Java" in xml
    # Scope callout may mention LotusScript as out of scope; LS rule tables must stay out
    assert "out of scope" in xml.lower()
