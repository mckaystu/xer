"""Contextual To-Be / remediation guides use real function handle names."""

from __future__ import annotations

from analytics.code_auditor.function_inventory import build_inventory
from analytics.code_auditor.models import CodeUnit
from analytics.code_auditor.snippets import contextual_remediation, contextual_remediation_guide


def test_ssjs_to_be_names_function_and_typed_handles():
    body = """
getAttachmentData : function(curDoc){
  var attachItem:NotesRichTextItem;
  var embObj:NotesEmbeddedObject;
  var objColl:NotesDocumentCollection;
  for (var i = 0; i < 10; i++) {
    attachItem = curDoc.getFirstItem("FileAttachment");
    embObj = attachItem.getEmbeddedObject("x");
  }
  return files;
}
"""
    unit = CodeUnit(
        source_file="t.dxl",
        element_name="ClaimsLib",
        element_type="scriptlibrary",
        language="ssjs",
        event=None,
        body=body,
        start_line=1950,
    )
    recs = build_inventory([unit])
    match = [r for r in recs if r.function_name == "getAttachmentData"]
    assert match, [r.function_name for r in recs]
    rec = match[0]
    assert "getAttachmentData" in rec.remediation_guide
    assert "attachItem" in rec.remediation_guide or "attachItem" in rec.code_snippet_to_be
    assert "view.getFirstDocument" not in rec.code_snippet_to_be
    assert "getAttachmentData" in rec.code_snippet_to_be
    assert ".recycle()" in rec.code_snippet_to_be


def test_java_doc_walk_uses_real_collection_names():
    to_be = contextual_remediation(
        language="java",
        function_name="walkOrders",
        body=(
            "Document doc = ordersView.getFirstDocument();\n"
            "while (doc != null) {\n"
            "  Document nxt = ordersView.getNextDocument(doc);\n"
            "  process(doc);\n"
            "  doc = nxt;\n"
            "}\n"
        ),
        allocated_vars=["doc"],
        unclean_vars=["doc"],
        has_loop=True,
        rule_id="DOM-002",
    )
    assert "walkOrders" in to_be
    assert "ordersView.getNextDocument" in to_be
    assert "doc.recycle()" in to_be
    assert 'db.getView("Lookup")' not in to_be


def test_guide_lists_unclean_vars():
    guide = contextual_remediation_guide(
        language="ssjs",
        function_name="getAttachmentData",
        allocated_vars=["attachItem", "embObj"],
        unclean_vars=["attachItem", "embObj"],
        has_loop=True,
        rule_id="DOM-002",
    )
    assert "`getAttachmentData`" in guide
    assert "`attachItem`" in guide
    assert "`embObj`" in guide
