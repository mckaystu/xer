"""Regression tests for DOM-022..024 and CRITICAL FP guardrail helpers."""

from __future__ import annotations

from analytics.code_auditor.llm_engine import (
    _CRITICAL_FP_GUARDED_RULES,
    _fp_guardrail_allows,
)
from analytics.code_auditor.models import CodeUnit, Finding, RULE_CATALOG
from analytics.code_auditor.rules import (
    detect_dom022,
    detect_dom023,
    detect_dom024,
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


def _finding(rule_id: str, severity: str = "CRITICAL") -> Finding:
    meta = RULE_CATALOG[rule_id]
    return Finding(
        id="F-001",
        rule_id=rule_id,
        title=meta["title"],
        severity=severity,  # type: ignore[arg-type]
        confidence=90,
        source_file="t.dxl",
        element_name="Demo",
        element_type="agent",
        language="java",
        line=1,
        evidence="doc = coll.getNextDocument(prev)",
        technical_impact="leak",
        remediation="recycle",
        action_required="fix",
    )


def test_catalog_includes_022_024():
    for rid in ("DOM-022", "DOM-023", "DOM-024"):
        assert rid in RULE_CATALOG
    assert "DOM-001" in _CRITICAL_FP_GUARDED_RULES
    assert "DOM-018" in _CRITICAL_FP_GUARDED_RULES


def test_dom022_wrapper_after_child_recycle():
    body = """
void walk(Database db, String q) {
  DocumentCollection coll = db.FTSearch(q, 0);
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    String s = doc.getItemValueString("Subject");
    doc.recycle();
    doc = next;
  }
}
"""
    hits = detect_dom022(_unit(body))
    assert any(f.rule_id == "DOM-022" for f in hits)


def test_dom022_ok_when_wrapper_recycled():
    body = """
void walk(Database db, String q) {
  DocumentCollection coll = null;
  try {
    coll = db.FTSearch(q, 0);
    Document doc = coll.getFirstDocument();
    while (doc != null) {
      Document next = coll.getNextDocument(doc);
      doc.recycle();
      doc = next;
    }
  } finally {
    if (coll != null) coll.recycle();
  }
}
"""
    assert detect_dom022(_unit(body)) == []


def test_dom023_bean_field():
    body = """
@ManagedBean(name="orderBean")
@SessionScoped
public class OrderBean {
  private Document orderDoc;
  public void load() {}
}
"""
    hits = detect_dom023(_unit(body, name="OrderBean"))
    assert any(f.rule_id == "DOM-023" for f in hits)


def test_dom023_scope_put():
    body = """
void cache(Document doc) {
  sessionScope.put("orderDoc", doc);
}
"""
    hits = detect_dom023(_unit(body, language="ssjs"))
    assert any(f.rule_id == "DOM-023" for f in hits)


def test_dom024_domino_naf_recycle():
    body = """
void bad() {
  dominoNAF.recycle();
}
"""
    hits = detect_dom024(_unit(body, language="ssjs"))
    assert any(f.rule_id == "DOM-024" for f in hits)


def test_fp_guardrail_rejects_bare_critical_fp():
    finding = _finding("DOM-002", "CRITICAL")
    assert not _fp_guardrail_allows(
        finding,
        {"verdict": "FALSE_POSITIVE", "reasoning": "looks fine", "evidence_quote": ""},
        unit_body="Document doc = coll.getNextDocument(prev);",
    )


def test_fp_guardrail_allows_finally_recycle_evidence():
    finding = _finding("DOM-002", "CRITICAL")
    assert _fp_guardrail_allows(
        finding,
        {
            "verdict": "FALSE_POSITIVE",
            "reasoning": "doc.recycle() is in finally after the loop",
            "evidence_quote": "finally { doc.recycle(); }",
        },
        unit_body="",
    )


def test_fp_guardrail_rejects_oda_ownership_excuse():
    finding = _finding("DOM-001", "CRITICAL")
    assert not _fp_guardrail_allows(
        finding,
        {
            "verdict": "FALSE_POSITIVE",
            "reasoning": "ODA org.openntf.domino.Document auto-lifecycle",
            "evidence_quote": "org.openntf.domino.Document doc = db.getDocumentByUNID(u);",
        },
        unit_body="import org.openntf.domino.Document;",
    )
