"""DOM-004 / DOM-025 ODA deadlock and toLotus() loop tests."""

from __future__ import annotations

from analytics.code_auditor.models import CodeUnit, RULE_CATALOG
from analytics.code_auditor.rules import detect_dom004, detect_dom025, run_rule_engine


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


def test_catalog_dom004_critical_and_dom025():
    assert RULE_CATALOG["DOM-004"]["default_severity"] == "CRITICAL"
    assert "DOM-025" in RULE_CATALOG
    assert RULE_CATALOG["DOM-025"]["default_severity"] == "CRITICAL"


def test_dom004_oda_recycle():
    body = """
import org.openntf.domino.Document;
public void load(org.openntf.domino.Database db) {
  Document doc = db.getDocumentByUNID(unid);
  String s = doc.getItemValueString("Subject");
  doc.recycle();
}
"""
    hits = detect_dom004(_unit(body))
    assert any(f.rule_id == "DOM-004" for f in hits)
    assert all(f.severity == "CRITICAL" for f in hits if f.rule_id == "DOM-004")


def test_dom025_oda_loop_recycle_without_tolotus():
    body = """
import org.openntf.domino.View;
import org.openntf.domino.Document;
void walk(View odaView) {
  Document doc = odaView.getFirstDocument();
  while (doc != null) {
    Document next = odaView.getNextDocument(doc);
    String s = doc.getItemValueString("Subject");
    doc.recycle();
    doc = next;
  }
}
"""
    hits = detect_dom025(_unit(body))
    assert any(f.rule_id == "DOM-025" for f in hits)


def test_dom025_ok_with_tolotus():
    body = """
import org.openntf.domino.View;
void walk(View odaView) {
  lotus.domino.View lotusView = Factory.getWrapperFactory().toLotus(odaView);
  lotus.domino.Document doc = lotusView.getFirstDocument();
  while (doc != null) {
    lotus.domino.Document next = lotusView.getNextDocument(doc);
    try {
      String s = doc.getItemValueString("Subject");
    } finally {
      doc.recycle();
    }
    doc = next;
  }
}
"""
    assert detect_dom025(_unit(body)) == []


def test_pure_oda_missing_recycle_skipped_by_engine():
    body = """
import org.openntf.domino.Document;
public void load(org.openntf.domino.Database db) {
  Document doc = db.getDocumentByUNID(unid);
  String s = doc.getItemValueString("Subject");
}
"""
    findings = run_rule_engine([_unit(body)])
    # No missing-recycle DOM hits; no DOM-004 (no recycle call)
    assert not any(f.rule_id in {"DOM-002", "DOM-010", "DOM-001"} for f in findings)
