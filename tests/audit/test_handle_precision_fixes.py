"""Precision regressions for handle-exhaustion FP/FN fixes."""

from __future__ import annotations

from analytics.code_auditor.api_catalog import analyze_handle_cleanup, find_allocated_vars
from analytics.code_auditor.context import contributes_to_handle_exhaustion, inventory_risk_severity
from analytics.code_auditor.function_inventory import build_inventory
from analytics.code_auditor.models import CodeUnit, Finding
from analytics.code_auditor.rules import (
    detect_dom002,
    detect_dom003,
    detect_dom011,
    detect_dom012,
    detect_dom013,
    run_rule_engine,
)


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


def test_null_init_is_not_allocation():
    body = "void f() {\n  Document doc = null;\n  View view = null;\n}\n"
    assert find_allocated_vars(body, "java") == []
    assert analyze_handle_cleanup(body, "java").status == "SAFE_NO_HANDLES"


def test_recycle_lotuses_does_not_mask_loop_leak():
    body = """
void walk(View view) {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    Document next = view.getNextDocument(doc);
    process(doc);
    doc = next;
  }
  recycleLotuses();
}
"""
    analysis = analyze_handle_cleanup(body, "java")
    assert analysis.status != "PROTECTED"
    assert "doc" in analysis.unclean_vars or analysis.status == "UNPROTECTED_ALLOCATION"


def test_dom012_null_guard_ok():
    body = """
void walk(DocumentCollection coll) {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    if (doc != null) { doc.recycle(); }
    doc = next;
  }
}
"""
    assert detect_dom012(_unit(body)) == []


def test_dom012_business_if_flags():
    body = """
void walk(DocumentCollection coll) {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    if (shouldProcess(doc)) {
      doc.recycle();
    }
    doc = next;
  }
}
"""
    assert any(f.rule_id == "DOM-012" for f in detect_dom012(_unit(body)))


def test_dom011_correct_order_ok():
    body = """
void walk(View view) {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    Document next = view.getNextDocument(doc);
    try { process(doc); } finally { doc.recycle(); }
    doc = next;
  }
  view.recycle();
}
"""
    assert detect_dom011(_unit(body)) == []


def test_dom011_use_after_parent_recycle():
    body = """
void bad(View view) {
  Document doc = view.getFirstDocument();
  view.recycle();
  String s = doc.getItemValueString("Subject");
}
"""
    assert any(f.rule_id == "DOM-011" for f in detect_dom011(_unit(body)))


def test_dom003_import_only_ok():
    body = "import lotus.domino.Document;\nimport lotus.domino.Database;\n"
    assert detect_dom003(_unit(body)) == []


def test_dom002_coll_only_recycle_still_flags():
    body = """
void walk(DocumentCollection coll) {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    process(doc);
    doc = next;
  }
  coll.recycle();
}
"""
    assert any(f.rule_id == "DOM-002" for f in detect_dom002(_unit(body)))


def test_dom013_temp_next_without_recycle():
    body = """
void walk(DocumentCollection coll) {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    process(doc);
    doc = next;
  }
}
"""
    hits = detect_dom013(_unit(body))
    assert any(f.rule_id == "DOM-013" for f in hits)


def test_perf_rules_not_in_he_ring():
    f = Finding(
        id="F-1",
        rule_id="DOM-008",
        title="t",
        severity="MEDIUM",
        confidence=90,
        source_file="t",
        element_name="e",
        element_type="agent",
        language="java",
        line=1,
        evidence="x",
        technical_impact="x",
        remediation="x",
        action_required="x",
    )
    assert contributes_to_handle_exhaustion(f) is False
    f.rule_id = "DOM-002"
    assert contributes_to_handle_exhaustion(f) is True


def test_unprotected_non_loop_not_lower_than_partial():
    assert inventory_risk_severity(status="UNPROTECTED_ALLOCATION", in_loop=False) == "MEDIUM"
    assert inventory_risk_severity(status="PARTIAL_CLEANUP", in_loop=False) == "MEDIUM"


def test_csjs_skipped_by_rule_engine():
    body = """
function bad() {
  var doc = database.getDocumentByUNID(unid);
}
"""
    unit = _unit(body, language="ssjs", name="csjsClaims")
    unit.event = "client_library"
    findings = run_rule_engine([unit])
    assert findings == []


def test_oda_inventory_not_unprotected():
    body = """
public class OdaHelper {
  public void load(org.openntf.domino.Database db) {
    org.openntf.domino.Document doc = db.getDocumentByUNID(unid);
    String s = doc.getItemValueString("Subject");
  }
}
"""
    recs = build_inventory([_unit(body)])
    assert recs, "expected inventory rows for OdaHelper.load"
    assert recs[0].status == "PROTECTED"
