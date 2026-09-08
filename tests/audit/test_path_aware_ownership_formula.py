"""Regression tests for path-aware inventory, ownership, formula, and API catalog."""

from __future__ import annotations

from analytics.code_auditor.api_catalog import analyze_handle_cleanup
from analytics.code_auditor.engine import run_audit
from analytics.code_auditor.form_rules import detect_form001, detect_form002, detect_form003
from analytics.code_auditor.form_rules import bind_helpers as bind_form
from analytics.code_auditor.function_inventory import build_inventory
from analytics.code_auditor.models import CodeUnit
from analytics.code_auditor.ownership_rules import bind_helpers as bind_own
from analytics.code_auditor.ownership_rules import detect_dom_own001
from analytics.code_auditor.rules import _finding, _line_of, _snippet


def _ls(name: str, body: str) -> CodeUnit:
    return CodeUnit(
        source_file="t.dxl",
        element_name=name,
        element_type="agent",
        language="lotusscript",
        event=None,
        body=body,
    )


class TestPathAwareCleanup:
    def test_partial_cleanup_when_one_var_missing_delete(self):
        body = """
Sub PartialClean
  Dim doc As NotesDocument
  Dim mime As NotesMIMEEntity
  Set doc = db.GetDocumentByUNID(uid)
  Set mime = doc.GetMIMEEntity()
  Delete mime
End Sub
"""
        analysis = analyze_handle_cleanup(body, "lotusscript")
        assert analysis.status == "PARTIAL_CLEANUP"
        assert "doc" in analysis.unclean_vars
        assert "mime" in analysis.cleaned_vars

    def test_protected_when_all_named_vars_deleted(self):
        body = """
Sub FullClean
  Dim doc As NotesDocument
  Set doc = db.GetDocumentByUNID(uid)
  Call doc.Recycle()
  Delete doc
End Sub
"""
        analysis = analyze_handle_cleanup(body, "lotusscript")
        assert analysis.status == "PROTECTED"

    def test_unprotected_no_cleanup(self):
        body = """
Sub Leak
  Dim doc As NotesDocument
  Set doc = coll.GetFirstDocument()
  While Not doc Is Nothing
    Set doc = coll.GetNextDocument(doc)
  Wend
End Sub
"""
        analysis = analyze_handle_cleanup(body, "lotusscript")
        assert analysis.status == "UNPROTECTED_ALLOCATION"

    def test_inventory_records_partial(self):
        unit = _ls(
            "PartialAgent",
            """
Sub Initialize
  Dim doc As NotesDocument
  Dim view As NotesView
  Set view = db.GetView("All")
  Set doc = view.GetFirstDocument()
  Delete view
End Sub
""",
        )
        recs = build_inventory([unit])
        match = [r for r in recs if r.function_name == "Initialize"]
        assert match
        assert match[0].status == "PARTIAL_CLEANUP"


class TestOwnershipStatic:
    def setup_method(self):
        bind_own(finding=_finding, line_of=_line_of, snippet=_snippet)

    def test_return_without_cleanup(self):
        unit = CodeUnit(
            source_file="t.java",
            element_name="OwnLib",
            element_type="scriptlibrary",
            language="java",
            event=None,
            body="""
Document loadDoc(String uid) {
  Document doc = db.getDocumentByUNID(uid);
  return doc;
}
void caller() {
  Document d = loadDoc("001");
  System.out.println(d.getNoteID());
}
""",
        )
        findings = detect_dom_own001([unit])
        assert any(f.rule_id == "DOM-OWN-001" for f in findings)

    def test_caller_recycle_avoids_finding(self):
        unit = CodeUnit(
            source_file="t.java",
            element_name="OwnOk",
            element_type="scriptlibrary",
            language="java",
            event=None,
            body="""
Document loadDoc(String uid) {
  Document doc = db.getDocumentByUNID(uid);
  return doc;
}
void caller() {
  Document d = loadDoc("001");
  System.out.println(d.getNoteID());
  d.recycle();
}
""",
        )
        findings = detect_dom_own001([unit])
        assert not any(f.rule_id == "DOM-OWN-001" for f in findings)

    def test_lotus_script_skipped_for_ownership(self):
        unit = _ls(
            "OwnLib",
            """
Function LoadDoc(uid As String) As NotesDocument
  Dim doc As NotesDocument
  Set doc = db.GetDocumentByUNID(uid)
  Set LoadDoc = doc
End Function

Sub Caller
  Dim d As NotesDocument
  Set d = LoadDoc("001")
End Sub
""",
        )
        findings = detect_dom_own001([unit])
        assert not any(f.rule_id == "DOM-OWN-001" for f in findings)

    def test_cross_library_via_uses_edge(self):
        agent = CodeUnit(
            source_file="a.java",
            element_name="ReportAgent",
            element_type="agent",
            language="java",
            event=None,
            body="""
void Initialize() {
  Document d = loadDoc("001");
  System.out.println(d.getNoteID());
}
""",
        )
        lib = CodeUnit(
            source_file="lib.java",
            element_name="OpenLogFunctions",
            element_type="scriptlibrary",
            language="java",
            event=None,
            body="""
Document loadDoc(String uid) {
  Document doc = db.getDocumentByUNID(uid);
  return doc;
}
""",
        )
        edges = [
            {
                "type": "USES_SCRIPT_LIBRARY",
                "source": {"element_type": "agent", "name": "ReportAgent"},
                "target": {"element_type": "scriptlibrary", "name": "OpenLogFunctions"},
            }
        ]
        findings = detect_dom_own001([agent, lib], edges=edges)
        assert any(f.rule_id == "DOM-OWN-001" for f in findings)
        other = CodeUnit(
            source_file="other.java",
            element_name="OtherLib",
            element_type="scriptlibrary",
            language="java",
            event=None,
            body="""
Document loadDoc(String uid) {
  Document doc = db.getDocumentByUNID(uid);
  return doc;
}
""",
        )
        findings2 = detect_dom_own001([agent, other], edges=edges)
        assert not any(f.rule_id == "DOM-OWN-001" for f in findings2)


class TestEscapePathGap:
    def test_exit_before_delete(self):
        from analytics.code_auditor.api_catalog import analyze_handle_cleanup

        body = """
Sub EarlyExit
  Dim doc As NotesDocument
  Set doc = db.GetDocumentByUNID(uid)
  If doc Is Nothing Then
    Exit Sub
  End If
  Delete doc
End Sub
"""
        analysis = analyze_handle_cleanup(body, "lotusscript")
        assert analysis.status == "ESCAPE_PATH_GAP"
        assert analysis.escape_path_gap is True


class TestFormulaRules:
    def setup_method(self):
        bind_form(finding=_finding, line_of=_line_of, snippet=_snippet)

    def test_form001_repeated_lookups(self):
        unit = CodeUnit(
            source_file="f.dxl",
            element_name="Computed",
            element_type="field",
            language="formula",
            event="defaultvalue",
            body='@DbLookup("";"db";"v";"k1";"c1") + @DbColumn("";"db";"v";2)',
        )
        assert any(f.rule_id == "FORM-001" for f in detect_form001(unit))

    def test_form002_loop_lookup(self):
        unit = CodeUnit(
            source_file="f.dxl",
            element_name="LoopF",
            element_type="field",
            language="formula",
            event=None,
            body='@While(cond; @DbLookup("";"db";"v";"k";"c"))',
        )
        assert any(f.rule_id == "FORM-002" for f in detect_form002(unit))

    def test_form003_secret(self):
        unit = CodeUnit(
            source_file="f.dxl",
            element_name="Sec",
            element_type="field",
            language="formula",
            event=None,
            body='password:="hunter2"; @Return(1)',
        )
        assert any(f.rule_id == "FORM-003" for f in detect_form003(unit))

    def test_engine_includes_formula_from_graph(self):
        graph = {
            "business_logic": [
                {
                    "language": "formula",
                    "owner_name": "Computed",
                    "owner_type": "field",
                    "body": '@DbLookup("";"db";"v";"k";"c") + @DbColumn("";"db";"v";1)',
                    "source_file": "f.dxl",
                }
            ]
        }
        report = run_audit(graph=graph, use_llm=False)
        assert any(f.rule_id == "FORM-001" for f in report.findings)
