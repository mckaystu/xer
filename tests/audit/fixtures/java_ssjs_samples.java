// Xer audit fixture — Java / SSJS positive / negative / edge cases
// Annotation format:
//   // @case id=<name>
//   // @expect <RULE>[, RULE...]
//   // @forbid <RULE>[, RULE...]
//   // @lang java
// Bodies between // --- begin --- and // --- end --- are the unit source.

// =============================================================================
// @case id=dom001_chained
// @expect DOM-001
// @lang java
// =============================================================================
// --- begin ---
public void chained(Session session) throws NotesException {
  View view = session.getDatabase("srv", "app.nsf").getView("All");
  Document doc = view.getFirstDocument();
}
// --- end ---

// =============================================================================
// @case id=dom002_loop_no_recycle
// @expect DOM-002
// @lang java
// =============================================================================
// --- begin ---
public void walk(DocumentCollection coll) throws NotesException {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    String id = doc.getNoteID();
    doc = coll.getNextDocument(doc);
  }
}
// --- end ---

// =============================================================================
// @case id=dom002_loop_ok
// @forbid DOM-002
// @lang java
// =============================================================================
// --- begin ---
public void walkOk(DocumentCollection coll) throws NotesException {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    Document next = coll.getNextDocument(doc);
    doc.recycle();
    doc = next;
  }
}
// --- end ---

// =============================================================================
// @case id=dom003_missing_try
// @expect DOM-003
// @lang java
// =============================================================================
// --- begin ---
public void openDoc(Database db) throws NotesException {
  Document doc = db.getDocumentByUNID(unid);
  String s = doc.getItemValueString("Subject");
}
// --- end ---

// =============================================================================
// @case id=dom004_oda_recycle
// @expect DOM-004
// @lang java
// =============================================================================
// --- begin ---
import org.openntf.domino.Database;
public void odaBad(Database db) {
  Document doc = db.getDocumentByUNID(unid);
  doc.recycle();
}
// --- end ---

// =============================================================================
// @case id=dom006_static_handle
// @expect DOM-006
// @lang java
// =============================================================================
// --- begin ---
public class Cache {
  private static Document cachedDoc;
  public void set(Document d) { cachedDoc = d; }
}
// --- end ---

// =============================================================================
// @case id=dom010_missing_finally
// @expect DOM-010
// @lang java
// =============================================================================
// --- begin ---
public void work(Session session) throws NotesException {
  Database db = session.getDatabase(null, "app.nsf");
  Document doc = db.createDocument();
  doc.replaceItemValue("Form", "Memo");
  doc.save();
}
// --- end ---

// =============================================================================
// @case id=dom014_mime_leak
// @expect DOM-014
// @lang java
// =============================================================================
// --- begin ---
public void mime(Document doc) throws NotesException {
  MIMEEntity entity = doc.getMIMEEntity();
  String s = entity.getContentAsText();
}
// --- end ---

// =============================================================================
// @case id=dom014_item_ok
// @forbid DOM-014
// @lang java
// =============================================================================
// --- begin ---
public void itemOk(Document doc) throws NotesException {
  Item item = null;
  try {
    item = doc.getFirstItem("Body");
    String t = item.getText();
  } finally {
    if (item != null) item.recycle();
  }
}
// --- end ---

// =============================================================================
// @case id=dom015_viewnav_leak
// @expect DOM-015
// @lang java
// =============================================================================
// --- begin ---
public void nav(View view) throws NotesException {
  ViewNavigator nav = view.createViewNav();
  ViewEntry e = nav.getFirst();
}
// --- end ---

// =============================================================================
// @case id=dom016_search_in_loop
// @expect DOM-016
// @lang java
// =============================================================================
// --- begin ---
public void searchLoop(Database db) throws NotesException {
  for (int i = 0; i < 5; i++) {
    DocumentCollection coll = db.search("Form = \"Memo\"", null, 0);
    Document d = coll.getFirstDocument();
  }
}
// --- end ---

// =============================================================================
// @case id=perf001_no_autoupdate
// @expect PERF-001
// @lang java
// =============================================================================
// --- begin ---
public void writeLoop(View view) throws NotesException {
  Document doc = view.getFirstDocument();
  while (doc != null) {
    doc.replaceItemValue("X", "1");
    doc.save(true, false);
    Document next = view.getNextDocument(doc);
    doc.recycle();
    doc = next;
  }
}
// --- end ---

// =============================================================================
// @case id=perf001_ok
// @forbid PERF-001
// @lang java
// =============================================================================
// --- begin ---
public void writeLoopOk(View view) throws NotesException {
  view.setAutoUpdate(false);
  Document doc = view.getFirstDocument();
  while (doc != null) {
    doc.save(true, false);
    Document next = view.getNextDocument(doc);
    doc.recycle();
    doc = next;
  }
  view.setAutoUpdate(true);
}
// --- end ---

// =============================================================================
// @case id=perf002_getview_loop
// @expect PERF-002
// @lang java
// =============================================================================
// --- begin ---
public void getViewLoop(Database db) throws NotesException {
  for (int i = 0; i < 10; i++) {
    View view = db.getView("All");
    Document doc = view.getFirstDocument();
  }
}
// --- end ---

// =============================================================================
// @case id=perf003_save_loop
// @expect PERF-003
// @lang java
// =============================================================================
// --- begin ---
public void saveLoop(DocumentCollection coll) throws NotesException {
  Document doc = coll.getFirstDocument();
  while (doc != null) {
    doc.replaceItemValue("X", "1");
    doc.save(true, false);
    Document next = coll.getNextDocument(doc);
    doc.recycle();
    doc = next;
  }
}
// --- end ---

// =============================================================================
// @case id=java_inventory_protected
// @forbid DOM-002
// @lang java
// =============================================================================
// --- begin ---
public void protectedWalk(DocumentCollection coll) throws NotesException {
  Document doc = null;
  try {
    doc = coll.getFirstDocument();
    while (doc != null) {
      Document next = coll.getNextDocument(doc);
      doc.recycle();
      doc = next;
    }
  } finally {
    if (doc != null) doc.recycle();
  }
}
// --- end ---
