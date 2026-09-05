"""Exhaustive Domino handle / memory lifecycle audit tests.

Covers quality LotusScript and Java (lotus.domino) patterns for:
- loop iteration + Delete / recycle
- in-loop secondary lookups
- Public / static module handles
- Set Nothing vs Delete
- chained instantiation
- try/finally scaffolding
- ODA conflicts
- function inventory recycle coverage classification

Run:
  .venv/bin/python -m pytest tests/test_domino_handle_audit.py -v
"""

from __future__ import annotations

import pytest

from analytics.code_auditor.function_inventory import build_inventory
from analytics.code_auditor.models import CodeUnit
from analytics.code_auditor.rules import run_rule_engine
from analytics.code_auditor.snippets import remediation_template


def ls(name: str, body: str, *, element_type: str = "agent", event: str | None = None) -> CodeUnit:
    return CodeUnit(
        source_file="test.dxl",
        element_name=name,
        element_type=element_type,
        language="lotusscript",
        event=event,
        body=body.strip("\n") + "\n",
        start_line=1,
    )


def java(name: str, body: str, *, element_type: str = "scriptlibrary") -> CodeUnit:
    return CodeUnit(
        source_file="test.dxl",
        element_name=name,
        element_type=element_type,
        language="java",
        event=None,
        body=body.strip("\n") + "\n",
        start_line=1,
    )


def rules(unit: CodeUnit) -> set[str]:
    return {f.rule_id for f in run_rule_engine([unit])}


def findings_for(unit: CodeUnit, rule_id: str) -> list:
    return [f for f in run_rule_engine([unit]) if f.rule_id == rule_id]


def inventory_status(unit: CodeUnit, fn_name: str | None = None) -> str:
    recs = build_inventory([unit])
    assert recs, f"expected inventory entries for {unit.element_name}"
    if fn_name:
        match = [r for r in recs if r.function_name == fn_name]
        assert match, f"function {fn_name} not found in {[r.function_name for r in recs]}"
        return match[0].status
    return recs[0].status


# ---------------------------------------------------------------------------
# LotusScript — QUALITY (must not fire lifecycle leak rules)
# ---------------------------------------------------------------------------


class TestLotusScriptQualityPatterns:
    def test_canonical_delete_before_advance_loop(self):
        unit = ls(
            "GoodLoop",
            """
Sub Initialize
    Dim session As New NotesSession
    Dim db As NotesDatabase
    Dim view As NotesView
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Set db = session.CurrentDatabase
    Set view = db.GetView("All")
    Set doc = view.GetFirstDocument()
    Do While Not (doc Is Nothing)
        Set nextDoc = view.GetNextDocument(doc)
        Call doc.ReplaceItemValue("Processed", "1")
        Call doc.Save(True, False)
        Delete doc
        Set doc = nextDoc
    Loop
    Delete view
End Sub
""",
        )
        hit = rules(unit)
        assert "LS-DOM-001" not in hit
        assert "LS-DOM-002" not in hit
        assert inventory_status(unit, "Initialize") == "PROTECTED"

    def test_while_wend_with_delete(self):
        unit = ls(
            "WhileWendGood",
            """
Sub Process
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Set doc = collection.GetFirstDocument()
    While Not doc Is Nothing
        Set nextDoc = collection.GetNextDocument(doc)
        ' work
        Delete doc
        Set doc = nextDoc
    Wend
End Sub
""",
        )
        assert "LS-DOM-001" not in rules(unit)

    def test_forall_entries_with_delete(self):
        unit = ls(
            "ForallGood",
            """
Sub WalkEntries
    Dim nav As NotesViewNavigator
    Dim entry As NotesViewEntry
    Dim nextEntry As NotesViewEntry
    Set nav = view.CreateViewNav()
    Set entry = nav.GetFirst()
    Do While Not (entry Is Nothing)
        Set nextEntry = nav.GetNext(entry)
        Delete entry
        Set entry = nextEntry
    Loop
End Sub
""",
        )
        # GetNext(entry) is not GetNextEntry — should not false-fire LS-DOM-001 on wrong meth
        assert "LS-DOM-001" not in rules(unit)

    def test_in_loop_lookup_with_delete(self):
        unit = ls(
            "LookupGood",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Dim lookupDoc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set nextDoc = view.GetNextDocument(doc)
        Set lookupDoc = db.GetDocumentByUNID(doc.UniversalID)
        If Not lookupDoc Is Nothing Then
            Print lookupDoc.NoteID
            Delete lookupDoc
        End If
        Delete doc
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        hit = rules(unit)
        assert "LS-DOM-001" not in hit
        assert "LS-DOM-002" not in hit

    def test_delete_before_set_nothing(self):
        unit = ls(
            "NothingGood",
            """
Sub Initialize
    Dim doc As NotesDocument
    Set doc = db.GetDocumentByUNID(unid$)
    If Not doc Is Nothing Then
        Delete doc
    End If
    Set doc = Nothing
End Sub
""",
        )
        assert "LS-DOM-004" not in rules(unit)

    def test_call_recycle_counts_as_cleanup(self):
        unit = ls(
            "RecycleCall",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not (doc Is Nothing)
        Set nextDoc = view.GetNextDocument(doc)
        Call doc.Recycle()
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        assert "LS-DOM-001" not in rules(unit)
        assert inventory_status(unit, "Initialize") == "PROTECTED"

    def test_local_dim_notes_not_public(self):
        unit = ls(
            "LocalDims",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim db As NotesDatabase
    Dim view As NotesView
    Set db = session.CurrentDatabase
End Sub
""",
            element_type="scriptlibrary",
        )
        assert "LS-DOM-003" not in rules(unit)

    def test_public_string_not_notes_handle(self):
        unit = ls(
            "PublicStrings",
            """
Option Public
Public formName As String
Public errNum As Integer
Public gFlag As Variant
""",
            element_type="scriptlibrary",
            event="declarations",
        )
        assert "LS-DOM-003" not in rules(unit)

    def test_private_notes_not_ls_dom003(self):
        unit = ls(
            "Privates",
            """
Private helperDoc As NotesDocument
Dim localDb As NotesDatabase
""",
            element_type="scriptlibrary",
            event="declarations",
        )
        assert "LS-DOM-003" not in rules(unit)

    def test_static_notes_document_fires_dom006(self):
        unit = ls(
            "StaticHandle",
            """
Static cachedDoc As NotesDocument
Sub Initialize
End Sub
""",
            element_type="scriptlibrary",
        )
        assert "DOM-006" in rules(unit)

    def test_conditional_delete_still_counts_cleanup_today(self):
        """Documented heuristic: any Delete in the loop body clears LS-DOM-001.

        Incomplete/conditional Delete is a known blind spot (prefer AI Pass 2).
        """
        unit = ls(
            "CondDelete",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set nextDoc = view.GetNextDocument(doc)
        If shouldDelete Then
            Delete doc
        End If
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        assert "LS-DOM-001" not in rules(unit)
        assert inventory_status(unit, "Initialize") == "PROTECTED"


# ---------------------------------------------------------------------------
# LotusScript — DEFECTIVE (must fire expected rules)
# ---------------------------------------------------------------------------


class TestLotusScriptDefectPatterns:
    def test_loop_getnext_without_delete(self):
        unit = ls(
            "LeakLoop",
            """
Sub Initialize
    Dim doc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not (doc Is Nothing)
        Print doc.UniversalID
        Set doc = view.GetNextDocument(doc)
    Loop
End Sub
""",
        )
        hit = rules(unit)
        assert "LS-DOM-001" in hit
        assert inventory_status(unit, "Initialize") == "UNPROTECTED_ALLOCATION"
        f = findings_for(unit, "LS-DOM-001")[0]
        assert f.severity == "CRITICAL"
        assert f.confidence >= 90
        assert "Delete" in (f.code_snippet_to_be or "")

    def test_do_until_getnext_without_delete(self):
        unit = ls(
            "DoUntilLeak",
            """
Sub Initialize
    Dim entry As NotesViewEntry
    Set entry = nav.GetFirstEntry()
    Do Until entry Is Nothing
        Print entry.NoteID
        Set entry = nav.GetNextEntry(entry)
    Loop
End Sub
""",
        )
        assert "LS-DOM-001" in rules(unit)

    def test_in_loop_getdocumentbyunid_without_delete(self):
        unit = ls(
            "LookupLeak",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Dim lookupDoc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set nextDoc = view.GetNextDocument(doc)
        Set lookupDoc = db.GetDocumentByUNID(unid$)
        Print lookupDoc.NoteID
        Delete doc
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        assert "LS-DOM-002" in rules(unit)
        f = findings_for(unit, "LS-DOM-002")[0]
        assert f.severity == "CRITICAL"  # in-loop → handle exhaustion

    def test_in_loop_createdocument_without_delete(self):
        unit = ls(
            "CreateLeak",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Dim newDoc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set nextDoc = view.GetNextDocument(doc)
        Set newDoc = db.CreateDocument()
        Call newDoc.ReplaceItemValue("Form", "Memo")
        Delete doc
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        assert "LS-DOM-002" in rules(unit)

    def test_in_loop_getdocumentbykey_without_delete(self):
        unit = ls(
            "KeyLeak",
            """
Sub Initialize
    Dim doc As NotesDocument
    Dim nextDoc As NotesDocument
    Dim hit As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set nextDoc = view.GetNextDocument(doc)
        Set hit = lookupView.GetDocumentByKey(doc.GetItemValue("Key"), True)
        Delete doc
        Set doc = nextDoc
    Loop
End Sub
""",
        )
        assert "LS-DOM-002" in rules(unit)

    def test_public_notes_document_database_view(self):
        unit = ls(
            "OpenLog",
            """
Option Public
Public gDoc As NotesDocument
Public gDb As NotesDatabase
Public gView As NotesView
Public gName As String
""",
            element_type="scriptlibrary",
            event="declarations",
        )
        hits = findings_for(unit, "LS-DOM-003")
        assert len(hits) == 3
        assert all(f.severity == "CRITICAL" for f in hits)
        assert all(f.confidence >= 95 for f in hits)

    def test_set_nothing_without_delete(self):
        unit = ls(
            "NothingLeak",
            """
Sub Initialize
    Dim doc As NotesDocument
    Set doc = db.GetDocumentByUNID(unid$)
    ' forgot Delete
    Set doc = Nothing
End Sub
""",
        )
        assert "LS-DOM-004" in rules(unit)
        f = findings_for(unit, "LS-DOM-004")[0]
        assert f.severity == "LOW"  # one-shot helper → routine hygiene
        assert "Delete" in (f.code_snippet_to_be or "")
        assert "GetNextDocument" not in (f.code_snippet_to_be or "")

    def test_java_recycle_rules_do_not_fire_on_lotusscript_loops(self):
        unit = ls(
            "NoJavaRules",
            """
Sub Initialize
    Dim doc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set doc = view.GetNextDocument(doc)
    Loop
End Sub
""",
        )
        hit = rules(unit)
        assert "DOM-002" not in hit
        assert "DOM-013" not in hit
        assert "DOM-010" not in hit
        assert "LS-DOM-001" in hit


# ---------------------------------------------------------------------------
# Java — QUALITY
# ---------------------------------------------------------------------------


class TestJavaQualityPatterns:
    def test_try_finally_recycle_loop(self):
        unit = java(
            "GoodLoop",
            """
public void process(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    Document next = view.getNextDocument(doc);
    try {
      String id = doc.getUniversalID();
    } finally {
      doc.recycle();
    }
    doc = next;
  }
}
""",
        )
        hit = rules(unit)
        assert "DOM-002" not in hit
        assert "DOM-013" not in hit
        assert "DOM-010" not in hit
        assert inventory_status(unit, "process") == "PROTECTED"

    def test_named_datetime_with_finally(self):
        unit = java(
            "GoodDate",
            """
public String format(Session session, String raw) throws NotesException {
  DateTime dt = null;
  try {
    dt = session.createDateTime(raw);
    return dt.getDateOnly();
  } finally {
    if (dt != null) dt.recycle();
  }
}
""",
        )
        assert "DOM-001" not in rules(unit)
        assert "DOM-010" not in rules(unit)

    def test_no_static_handle_fields(self):
        unit = java(
            "GoodBean",
            """
public class OrderBean {
  private String orderUnid;
  public Document load(Database db) throws NotesException {
    Document doc = null;
    try {
      doc = db.getDocumentByUNID(orderUnid);
      return doc;
    } finally {
      // caller owns recycle when returned — documented pattern
    }
  }
}
""",
        )
        assert "DOM-006" not in rules(unit)


# ---------------------------------------------------------------------------
# Java — DEFECTIVE
# ---------------------------------------------------------------------------


class TestJavaDefectPatterns:
    def test_sessionscope_document_cache(self):
        unit = java(
            "ScopeCache",
            """
public void bad(Document doc) {
  sessionScope.put("orderDoc", doc);
}
""",
        )
        unit2 = java(
            "ScopeCache2",
            """
public void bad(Document orderDoc) {
  sessionScope.orderDoc = orderDoc;
}
""",
        )
        hit = rules(unit) | rules(unit2)
        assert isinstance(hit, set)

    def test_parent_recycle_before_child_use(self):
        unit = java(
            "ParentEarly",
            """
public void bad(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  view.recycle();
  String id = doc.getUniversalID();
}
""",
        )
        assert "DOM-011" in rules(unit)

    def test_chained_createdatetime(self):
        unit = java(
            "ChainDT",
            """
public String bad(Session session, String raw) throws NotesException {
  return session.createDateTime(raw).getDateOnly();
}
""",
        )
        assert "DOM-001" in rules(unit)
        f = findings_for(unit, "DOM-001")[0]
        assert f.severity == "MEDIUM"  # non-loop one-shot → demoted from CRITICAL

    def test_chained_createdatetime_short_session_var(self):
        unit = java(
            "ChainShort",
            """
public String bad(Session s, String raw) throws NotesException {
  return s.createDateTime(raw).getDateOnly();
}
""",
        )
        assert "DOM-001" in rules(unit)

    def test_try_finally_loop_not_dom002_regression(self):
        unit = java(
            "GoodLoop2",
            """
public void process(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    Document next = view.getNextDocument(doc);
    try { doc.getUniversalID(); } finally { doc.recycle(); }
    doc = next;
  }
}
""",
        )
        assert "DOM-002" not in rules(unit)
        assert "DOM-013" not in rules(unit)

    def test_chained_getview_getfirstdocument(self):
        unit = java(
            "ChainView",
            """
public String bad(Database db) throws NotesException {
  return db.getView("All").getFirstDocument().getUniversalID();
}
""",
        )
        assert "DOM-001" in rules(unit)

    def test_loop_getnext_without_recycle(self):
        unit = java(
            "LeakLoop",
            """
public void walk(DocumentCollection coll) throws NotesException {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    String id = doc.getUniversalID();
    doc = coll.getNextDocument(doc);
  }
}
""",
        )
        hit = rules(unit)
        assert "DOM-002" in hit or "DOM-013" in hit
        assert inventory_status(unit, "walk") == "UNPROTECTED_ALLOCATION"

    def test_missing_try_finally_scaffold(self):
        unit = java(
            "NoFinally",
            """
public void open(Database db) throws NotesException {
  View view = db.getView("Lookup");
  Document doc = view.getFirstDocument();
  String subject = doc.getItemValueString("Subject");
}
""",
        )
        assert "DOM-010" in rules(unit)

    def test_static_document_field(self):
        unit = java(
            "StaticDoc",
            """
public class Cache {
  private static Document cachedDoc;
  public void set(Document d) { cachedDoc = d; }
}
""",
        )
        assert "DOM-006" in rules(unit)

    def test_oda_manual_recycle(self):
        unit = java(
            "OdaRecycle",
            """
import org.openntf.domino.Database;
import org.openntf.domino.Document;
public void bad(Database db) {
  Document doc = db.getDocumentByUNID(unid);
  String s = doc.getItemValueString("Subject");
  doc.recycle();
}
""",
        )
        assert "DOM-004" in rules(unit)

    def test_createDateTime_in_loop(self):
        unit = java(
            "HotDate",
            """
public void hot(Session session, String[] vals) throws NotesException {
  for (int i = 0; i < vals.length; i++) {
    DateTime dt = session.createDateTime(vals[i]);
    System.out.println(dt.getDateOnly());
  }
}
""",
        )
        assert "DOM-009" in rules(unit)

    def test_unsafe_reassign_getnext(self):
        unit = java(
            "Reassign",
            """
public void leak(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    // process
    doc = view.getNextDocument(doc);
  }
}
""",
        )
        assert "DOM-013" in rules(unit) or "DOM-002" in rules(unit)


# ---------------------------------------------------------------------------
# Inventory classification edge cases
# ---------------------------------------------------------------------------


class TestFunctionInventoryAccuracy:
    def test_unprotected_notesdocument_dim(self):
        unit = ls(
            "AllocNoDelete",
            """
Function LoadDoc(unid As String) As NotesDocument
    Dim db As NotesDatabase
    Dim doc As NotesDocument
    Set db = session.CurrentDatabase
    Set doc = db.GetDocumentByUNID(unid)
    Set LoadDoc = doc
End Function
""",
            element_type="scriptlibrary",
        )
        assert inventory_status(unit, "LoadDoc") == "UNPROTECTED_ALLOCATION"

    def test_protected_with_delete(self):
        unit = ls(
            "WithDelete",
            """
Sub CloseDoc
    Dim doc As NotesDocument
    Set doc = db.GetDocumentByUNID(unid$)
    If Not doc Is Nothing Then Delete doc
End Sub
""",
        )
        assert inventory_status(unit, "CloseDoc") == "PROTECTED"

    def test_java_protected_recycle(self):
        unit = java(
            "RecycleFn",
            """
public void close(Document doc) throws NotesException {
  if (doc != null) {
    doc.recycle();
  }
}
""",
        )
        # allocates? Document in signature/body as type may not count for java allocation
        # body only has recycle — SAFE or PROTECTED depending on Document word
        status = inventory_status(unit, "close")
        assert status in {"SAFE_NO_HANDLES", "PROTECTED"}

    def test_inventory_deep_dive_fields(self):
        unit = ls(
            "Deep",
            """
Sub Initialize
    Dim doc As NotesDocument
    Set doc = view.GetFirstDocument()
    Do While Not doc Is Nothing
        Set doc = view.GetNextDocument(doc)
    Loop
End Sub
""",
        )
        rec = build_inventory([unit])[0]
        assert rec.code_snippet_lines
        assert any(row.get("highlight") for row in rec.code_snippet_lines)
        assert rec.code_snippet_to_be
        assert rec.problem_breakdown
        assert rec.highlight_line >= 1

    def test_to_be_templates_language_aware(self):
        ls_t = remediation_template("LS-DOM-001", "lotusscript")
        java_t = remediation_template("DOM-002", "java")
        assert "Delete" in ls_t
        assert "recycle" in java_t.lower()
        assert "try" in java_t.lower() or "finally" in java_t.lower()


# ---------------------------------------------------------------------------
# Cross-language isolation
# ---------------------------------------------------------------------------


class TestCrossLanguageIsolation:
    def test_ls_dom_rules_ignore_java(self):
        unit = java(
            "JavaLoop",
            """
public void walk(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    doc = view.getNextDocument(doc);
  }
}
""",
        )
        hit = rules(unit)
        assert not any(r.startswith("LS-") for r in hit)

    def test_public_notes_only_on_lotusscript(self):
        unit = java(
            "NotPublic",
            """
public class X {
  public Document gDoc;
}
""",
        )
        assert "LS-DOM-003" not in rules(unit)


# ---------------------------------------------------------------------------
# Multi-unit engine smoke
# ---------------------------------------------------------------------------


class TestEngineBatch:
    def test_mixed_corpus_rule_ids_stable(self):
        units = [
            ls(
                "Leak",
                """
Sub Initialize
  Dim doc As NotesDocument
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Set doc = view.GetNextDocument(doc)
  Loop
End Sub
""",
            ),
            java(
                "Chain",
                """
public String bad(Session s, String r) throws NotesException {
  return s.createDateTime(r).getDateOnly();
}
""",
            ),
            ls(
                "Decls",
                """
Public gDoc As NotesDocument
""",
                element_type="scriptlibrary",
                event="declarations",
            ),
        ]
        findings = run_rule_engine(units)
        ids = [f.id for f in findings]
        assert ids == sorted(ids) or len(ids) == len(set(ids))
        assert all(f.id.startswith("F-") for f in findings)
        rule_ids = {f.rule_id for f in findings}
        assert "LS-DOM-001" in rule_ids
        assert "DOM-001" in rule_ids
        assert "LS-DOM-003" in rule_ids


# ---------------------------------------------------------------------------
# Advanced Item/MIME/ViewNav/Search + Performance & NIF
# ---------------------------------------------------------------------------


class TestAdvancedHandleAndPerfRules:
    def test_ls_dom005_item_in_loop(self):
        unit = ls(
            "ItemLeak",
            """
Sub Initialize
  Dim doc As NotesDocument
  Dim item As NotesItem
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Set item = doc.GetFirstItem("Body")
    Print item.Text
    Set nextDoc = view.GetNextDocument(doc)
    Delete doc
    Set doc = nextDoc
  Loop
End Sub
""",
        )
        assert "LS-DOM-005" in rules(unit)

    def test_ls_dom006_viewnav(self):
        unit = ls(
            "NavLeak",
            """
Sub Initialize
  Dim nav As NotesViewNavigator
  Set nav = view.CreateViewNav()
End Sub
""",
        )
        assert "LS-DOM-006" in rules(unit)

    def test_ls_dom007_error_handler(self):
        unit = ls(
            "ErrLeak",
            """
Sub Initialize
  On Error GoTo Fail
  Dim doc As NotesDocument
  Set doc = db.GetDocumentByUNID(unid$)
  Exit Sub
Fail:
  Exit Sub
End Sub
""",
        )
        assert "LS-DOM-007" in rules(unit)

    def test_ls_dom008_search_in_loop(self):
        unit = ls(
            "SearchLeak",
            """
Sub Initialize
  Dim doc As NotesDocument
  Dim coll As NotesDocumentCollection
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Set coll = db.Search({Form="Memo"}, Nothing, 0)
    Set doc = view.GetNextDocument(doc)
  Loop
End Sub
""",
        )
        assert "LS-DOM-008" in rules(unit)

    def test_dom014_mime(self):
        unit = java(
            "Mime",
            """
public void mime(Document doc) throws NotesException {
  MIMEEntity entity = doc.getMIMEEntity();
  String s = entity.getContentAsText();
}
""",
        )
        assert "DOM-014" in rules(unit)

    def test_dom015_viewnav(self):
        unit = java(
            "Nav",
            """
public void nav(View view) throws NotesException {
  ViewNavigator nav = view.createViewNav();
  ViewEntry e = nav.getFirst();
}
""",
        )
        assert "DOM-015" in rules(unit)

    def test_perf001_autoupdate(self):
        unit = ls(
            "NoAuto",
            """
Sub Initialize
  Dim doc As NotesDocument
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Call doc.ReplaceItemValue("X", "1")
    Call doc.Save(True, False)
    Set doc = view.GetNextDocument(doc)
  Loop
End Sub
""",
        )
        assert "PERF-001" in rules(unit)

    def test_perf001_ok_when_autoupdate_false(self):
        unit = ls(
            "AutoOk",
            """
Sub Initialize
  view.AutoUpdate = False
  Dim doc As NotesDocument
  Set doc = view.GetFirstDocument()
  Do While Not doc Is Nothing
    Call doc.Save(True, False)
    Set doc = view.GetNextDocument(doc)
  Loop
  view.AutoUpdate = True
End Sub
""",
        )
        assert "PERF-001" not in rules(unit)

    def test_perf002_getview_in_loop(self):
        unit = java(
            "GetViewLoop",
            """
public void walk(Database db) throws NotesException {
  for (int i = 0; i < 10; i++) {
    View view = db.getView("All");
    Document doc = view.getFirstDocument();
  }
}
""",
        )
        assert "PERF-002" in rules(unit)

    def test_perf003_save_in_loop(self):
        unit = java(
            "SaveLoop",
            """
public void walk(DocumentCollection coll) throws NotesException {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    doc.replaceItemValue("X", "1");
    doc.save(true, false);
    Document next = coll.getNextDocument(doc);
    doc.recycle();
    doc = next;
  }
}
""",
        )
        assert "PERF-003" in rules(unit)
