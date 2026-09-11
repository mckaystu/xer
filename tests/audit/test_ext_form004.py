"""Tests for EXT-*, LS-EXT-*, and FORM-004 assessment-inspired rules."""

from __future__ import annotations

from analytics.code_auditor.ext_rules import bind_helpers as bind_ext
from analytics.code_auditor.ext_rules import detect_ext001, detect_ext002
from analytics.code_auditor.form_rules import (
    SUMMARY_FIELD_WARN_THRESHOLD,
    bind_helpers as bind_form,
    detect_form004,
    detect_form004_from_graph,
)
from analytics.code_auditor.ls_ext_rules import bind_helpers as bind_ls
from analytics.code_auditor.ls_ext_rules import detect_ls_ext001, detect_ls_ext002
from analytics.code_auditor.models import CodeUnit, RULE_CATALOG
from analytics.code_auditor.rules import _finding, _line_of, _snippet, run_rule_engine


def _unit(body: str, *, language: str = "java", name: str = "Demo") -> CodeUnit:
    return CodeUnit(
        source_file="t.dxl",
        element_name=name,
        element_type="agent",
        language=language,
        event=None,
        body=body,
        start_line=1,
    )


def setup_module():
    bind_ext(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_ls(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_form(finding=_finding, line_of=_line_of, snippet=_snippet)


def test_catalog_includes_ext_and_form004():
    for rid in ("EXT-001", "EXT-002", "LS-EXT-001", "LS-EXT-002", "FORM-004"):
        assert rid in RULE_CATALOG


def test_ext001_jdbc_leak():
    body = """
void query(String url) throws Exception {
  Connection conn = DriverManager.getConnection(url, "u", "p");
  Statement st = conn.createStatement();
  st.execute("select 1 from dual");
}
"""
    hits = detect_ext001(_unit(body))
    assert any(f.rule_id == "EXT-001" for f in hits)


def test_ext001_closed_ok():
    body = """
void query(String url) throws Exception {
  Connection conn = null;
  try {
    conn = DriverManager.getConnection(url, "u", "p");
  } finally {
    if (conn != null) conn.close();
  }
}
"""
    assert detect_ext001(_unit(body)) == []


def test_ext002_http_leak():
    body = """
void fetch(Session session) throws NotesException {
  NotesHTTPRequest http = session.createHTTPRequest();
  String body = http.get("https://example.com/file.pdf");
}
"""
    hits = detect_ext002(_unit(body))
    assert any(f.rule_id == "EXT-002" for f in hits)


def test_ls_ext001_javasession():
    body = """
Sub Initialize
  Dim js As JavaSession
  Set js = New JavaSession
  Dim jc As JavaClass
  Set jc = js.GetClass("com.example.Helper")
End Sub
"""
    hits = detect_ls_ext001(_unit(body, language="lotusscript"))
    assert any(f.rule_id == "LS-EXT-001" for f in hits)


def test_ls_ext001_released_ok():
    body = """
Sub Initialize
  Dim js As JavaSession
  Set js = New JavaSession
  Set js = Nothing
End Sub
"""
    assert detect_ls_ext001(_unit(body, language="lotusscript")) == []


def test_ls_ext002_open_connection():
    body = """
Function SetTheConnection() As Boolean
  Call conn.OpenConnection(dbName)
  SetTheConnection = True
End Function
"""
    hits = detect_ls_ext002(_unit(body, language="lotusscript", name="libDB2"))
    assert any(f.rule_id == "LS-EXT-002" for f in hits)


def test_form004_issummary_true():
    body = """
void write(Document doc) throws NotesException {
  Item item = doc.replaceItemValue("Blob", bigText);
  item.setSummary(true);
}
"""
    # Java uses setSummary — also match IsSummary = True style
    body2 = """
Sub WriteLarge
  Dim item As NotesItem
  Set item = doc.ReplaceItemValue("Blob", big$)
  item.IsSummary = True
End Sub
"""
    hits = detect_form004(_unit(body2, language="lotusscript"))
    assert any(f.rule_id == "FORM-004" for f in hits)


def test_form004_from_graph_threshold():
    fields = [{"name": f"F{i}", "type": "text"} for i in range(SUMMARY_FIELD_WARN_THRESHOLD)]
    graph = {
        "design_elements": {
            "forms": [
                {
                    "name": "DenseForm",
                    "source_file": "app.dxl",
                    "fields": fields,
                    "is_subform": False,
                }
            ]
        }
    }
    hits = detect_form004_from_graph(graph)
    assert any(f.rule_id == "FORM-004" and "DenseForm" in f.element_name for f in hits)


def test_run_rule_engine_keeps_ls_ext():
    body = """
Sub Initialize
  Dim js As JavaSession
  Set js = New JavaSession
End Sub
"""
    findings = run_rule_engine([_unit(body, language="lotusscript")])
    assert any(f.rule_id == "LS-EXT-001" for f in findings)
    assert not any(f.rule_id.startswith("LS-DOM") for f in findings)
