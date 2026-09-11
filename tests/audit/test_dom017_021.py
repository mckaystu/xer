"""Regression tests for DOM-017..021 handle antipattern detectors."""

from __future__ import annotations

from analytics.code_auditor.models import CodeUnit, RULE_CATALOG
from analytics.code_auditor.rules import (
    detect_dom017,
    detect_dom018,
    detect_dom019,
    detect_dom020,
    detect_dom021,
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


def test_catalog_includes_new_rules():
    for rid in ("DOM-017", "DOM-018", "DOM-019", "DOM-020", "DOM-021"):
        assert rid in RULE_CATALOG


def test_dom017_embedded_object_leak():
    body = """
void extract() {
  EmbeddedObject emb = rt.getEmbeddedObject("file.pdf");
  String path = emb.getSource();
}
"""
    hits = detect_dom017(_unit(body))
    assert any(f.rule_id == "DOM-017" for f in hits)


def test_dom017_recycled_ok():
    body = """
void extract() {
  EmbeddedObject emb = null;
  try {
    emb = rt.getEmbeddedObject("file.pdf");
  } finally {
    if (emb != null) emb.recycle();
  }
}
"""
    assert detect_dom017(_unit(body)) == []


def test_dom018_entry_get_document_leak():
    body = """
void walk(ViewNavigator nav) {
  ViewEntry entry = nav.getFirst();
  while (entry != null) {
    ViewEntry next = nav.getNext(entry);
    Document doc = entry.getDocument();
    String s = doc.getItemValueString("Subject");
    entry = next;
  }
}
"""
    hits = detect_dom018(_unit(body))
    assert any(f.rule_id == "DOM-018" for f in hits)


def test_dom019_all_documents_by_key():
    body = """
void lookup(View view, String key) {
  DocumentCollection coll = view.getAllDocumentsByKey(key, true);
  Document doc = coll.getFirstDocument();
}
"""
    hits = detect_dom019(_unit(body))
    assert any(f.rule_id == "DOM-019" for f in hits)


def test_dom020_session_recycle():
    body = """
void bad(Session session) {
  session.recycle();
}
"""
    hits = detect_dom020(_unit(body))
    assert any(f.rule_id == "DOM-020" for f in hits)


def test_dom020_ssjs_database_recycle():
    body = """
function cleanup() {
  database.recycle();
}
"""
    hits = detect_dom020(_unit(body, language="ssjs"))
    assert any(f.rule_id == "DOM-020" for f in hits)


def test_dom020_java_local_database_ok():
    body = """
void openOther(Session session) {
  Database database = session.getDatabase(server, path);
  try {
    // work
  } finally {
    if (database != null) database.recycle();
  }
}
"""
    assert detect_dom020(_unit(body, language="java")) == []


def test_dom021_stream_leak():
    body = """
void write(Session session) {
  Stream stream = session.createStream();
  stream.writeText("hi");
}
"""
    hits = detect_dom021(_unit(body))
    assert any(f.rule_id == "DOM-021" for f in hits)
