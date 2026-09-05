"""Regression tests for loop-aware severity, SEC rules, and upgrade_scan language scoping."""

from __future__ import annotations

from pathlib import Path

import pytest

from analytics.code_auditor.context import (
    body_has_loop,
    calibrate_handle_severity,
    inventory_risk_severity,
    inventory_ring_risk_class,
)
from analytics.code_auditor.function_inventory import build_inventory
from analytics.code_auditor.models import CodeUnit, RULE_CATALOG
from analytics.code_auditor.rules import run_rule_engine
from analytics.code_auditor.snippets import remediation_template
from upgrade_scan import scan_dxl_text


def ls(name: str, body: str) -> CodeUnit:
    return CodeUnit(
        source_file="t.dxl",
        element_name=name,
        element_type="agent",
        language="lotusscript",
        event=None,
        body=body.strip("\n") + "\n",
    )


class TestLoopAwareSeverity:
    def test_encode_base64_is_low_non_loop(self):
        unit = ls(
            "EncodeBase64",
            """
Function EncodeBase64 (StrIn As String) As String
  Dim session As New NotesSession
  Dim db As NotesDatabase
  Dim doc As NotesDocument
  Dim body As NotesMIMEEntity
  Set db = session.CurrentDatabase
  Set doc = db.CreateDocument
  Set body = doc.CreateMIMEEntity
  EncodeBase64 = body.ContentAsText
  Set doc = Nothing
End Function
""",
        )
        findings = run_rule_engine([unit])
        assert findings
        assert all(f.severity in {"LOW", "MEDIUM"} for f in findings)
        assert any(f.rule_id == "LS-DOM-004" and f.severity == "LOW" for f in findings)
        rem = findings[0].remediation or findings[0].code_snippet_to_be
        assert "GetNextDocument" not in rem
        assert "Delete" in rem
        assert "Non-loop" in (findings[0].technical_impact or "")

        inv = build_inventory([unit])
        enc = next(r for r in inv if r.function_name == "EncodeBase64")
        assert enc.in_loop is False
        assert enc.risk_severity == "LOW"
        assert "GetNextDocument" not in enc.code_snippet_to_be

    def test_loop_leak_stays_critical(self):
        unit = ls(
            "LoopLeak",
            """
Sub Initialize
  Dim doc As NotesDocument
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Print doc.NoteID
    Set doc = view.GetNextDocument(doc)
  Loop
End Sub
""",
        )
        findings = run_rule_engine([unit])
        ls001 = [f for f in findings if f.rule_id == "LS-DOM-001"]
        assert ls001
        assert ls001[0].severity == "CRITICAL"

    def test_calibrate_helper(self):
        assert calibrate_handle_severity("LS-DOM-004", "MEDIUM", in_loop=False) == "LOW"
        assert calibrate_handle_severity("LS-DOM-004", "MEDIUM", in_loop=True) == "CRITICAL"
        assert body_has_loop("Do While Not doc Is Nothing") is True
        assert body_has_loop("Function EncodeBase64") is False

    def test_safe_no_handles_is_low_severity(self):
        assert inventory_risk_severity(status="SAFE_NO_HANDLES", in_loop=False) == "LOW"


class TestInventoryRingRiskClass:
    """Python mirror of web/app.js inventoryRiskClass()."""

    def test_low_allocator_cleanup_forces_high(self):
        # Blended safety can look healthy while 0% of allocators clean up
        assert inventory_ring_risk_class(80.0, 0.0, allocating=9) == "risk-high"
        assert inventory_ring_risk_class(90.0, 49.9, allocating=10) == "risk-high"

    def test_falls_back_to_safety_rate_bands(self):
        assert inventory_ring_risk_class(30.0, 100.0, allocating=5) == "risk-high"
        assert inventory_ring_risk_class(50.0, 80.0, allocating=5) == "risk-moderate"
        assert inventory_ring_risk_class(90.0, 80.0, allocating=5) == "risk-low"

    def test_no_allocators_ignores_recycle_gate(self):
        assert inventory_ring_risk_class(100.0, 0.0, allocating=0) == "risk-low"


class TestSecRules:
    def test_sec001_hardcoded_http(self):
        unit = ls(
            "Creds",
            """
Sub Initialize
  Dim password As String
  password = "s3cret!"
  url$ = "http://mbrexp33.mbre.local/abms/bossrest.nsf"
  Print password
End Sub
""",
        )
        ids = {f.rule_id for f in run_rule_engine([unit])}
        assert "SEC-001" in ids
        assert "SEC-001" in RULE_CATALOG

    def test_sec002_query_unid(self):
        unit = ls(
            "QueryUnid",
            """
Sub Initialize
  Dim unid As String
  Dim doc As NotesDocument
  unid = Query_String
  Set doc = db.GetDocumentByUNID(unid)
  Print doc.NoteID
End Sub
""",
        )
        ids = {f.rule_id for f in run_rule_engine([unit])}
        assert "SEC-002" in ids


class TestUpgradeScanLanguageScoping:
    def test_ls_not_counted_as_java(self):
        dxl = """
<database>
  <agent name="A"><code event="Initialize"><lotusscript>
Sub Initialize
  Dim db As NotesDatabase
  Set db = session.GetDatabase("","app.nsf")
End Sub
  </lotusscript></code></agent>
  <scriptlibrary name="J"><javaproject>
    <java>
public void open(Session s) {
  Database db = s.getDatabase(null, "app.nsf");
}
    </java>
  </javaproject></scriptlibrary>
</database>
"""
        report = scan_dxl_text(dxl, source="fixture.dxl")
        totals = report.totals_by_language()
        assert totals.get("lotusscript", 0) >= 1
        assert totals.get("java", 0) >= 1
        # Ensure GetDatabase is not under java bucket
        java_patterns = {h.pattern for h in report.hits if h.language == "java"}
        ls_patterns = {h.pattern for h in report.hits if h.language == "lotusscript"}
        assert "GetDatabase" in ls_patterns
        assert "GetDatabase" not in java_patterns
        assert "getDatabase" in java_patterns

    def test_fromboss_dxl_no_java_false_positives(self):
        path = Path("dxl_input_fromboss/Code_FrombossRest.dxl")
        if not path.exists():
            pytest.skip("FrombossRest DXL not present")
        from upgrade_scan import scan_path

        report = scan_path(path)
        assert report.blocks_by_language.get("lotusscript", 0) > 0
        assert report.totals_by_language().get("java", 0) == 0
        assert any("not labeled as Java" in n or "no Java" in n for n in report.notes)


class TestLinearTemplates:
    def test_non_loop_template_has_no_getnext(self):
        rem = remediation_template("LS-DOM-004", "lotusscript", has_loop=False)
        assert "GetNextDocument" not in rem
        assert "Delete" in rem
        loop_rem = remediation_template("LS-DOM-001", "lotusscript", has_loop=True)
        assert "GetNextDocument" in loop_rem
