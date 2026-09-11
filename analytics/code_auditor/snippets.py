"""Snippet context helpers and language-aware remediation templates."""

from __future__ import annotations

import re
from typing import Any

from analytics.code_auditor.models import CodeUnit

# Plain-English guides keyed by rule id
PROBLEM_BREAKDOWNS: dict[str, str] = {
    "DOM-001": (
        "A Domino object is created and immediately chained (for example "
        "`session.createDateTime(...).getDateOnly()`). The temporary handle is never assigned "
        "to a variable, so it cannot be released and leaks native C-API memory."
    ),
    "DOM-002": (
        "A collection loop advances with `GetNextDocument` / `getNextDocument` but never "
        "releases the previous document handle. Each iteration leaves one native handle open "
        "until the HTTP/agent thread dies."
    ),
    "DOM-003": (
        "Native Domino objects are allocated without a guaranteed cleanup path. If an error "
        "occurs mid-method, handles remain pinned on the thread."
    ),
    "DOM-004": (
        "Code uses OpenNTF Domino API (ODA) and also calls `.recycle()`. ODA *claims* "
        "request-end disposal, but this environment assumes ODA may not run — dual lifecycle "
        "risk (leak if ODA fails; double-free if ODA later disposes). Prefer explicit "
        "lotus.domino + finally recycle, and do not treat ODA as proof of cleanup."
    ),
    "DOM-005": (
        "Raw `lotus.domino` objects are mixed with ODA APIs without `Factory.fromLotus()`, "
        "so lifecycle tracking is inconsistent."
    ),
    "DOM-006": (
        "A Session/Database/Document/View handle is stored in a static or Public module field, "
        "keeping native memory alive across requests and risking use-after-recycle."
    ),
    "DOM-007": (
        "Live Domino handles are cached in session/application scope or static maps instead of "
        "serializable identifiers (UNIDs, strings)."
    ),
    "DOM-008": (
        "The loop repeatedly materializes full documents or column values, allocating extra "
        "handles and CPU on every iteration."
    ),
    "DOM-009": (
        "`createDateTime` runs inside a hot loop, allocating a native DateTime handle per "
        "iteration when a JVM/JS date would suffice."
    ),
    "DOM-010": (
        "A Domino object is created/acquired without `try`/`finally` recycle scaffolding, so "
        "exceptions skip cleanup and leak C-API handles."
    ),
    "DOM-011": (
        "A parent View/Database/Collection is recycled while child Document/ViewEntry handles "
        "from that parent may still be referenced — orphaning those children in native memory."
    ),
    "DOM-012": (
        "`.recycle()` / handle release is inside an `If` inside a loop, so some iterations skip "
        "cleanup and leave handles open."
    ),
    "DOM-013": (
        "The loop variable is re-assigned with `GetNextDocument(doc)` / `getNextDocument(doc)` "
        "without releasing the previous handle first, dropping the only reference to it."
    ),
    "LS-DOM-001": (
        "A LotusScript `Do While` / `Do Until` / `Forall` / `While` loop advances documents or "
        "view entries with `GetNextDocument` / `GetNextEntry` but never `Delete`s the previous "
        "handle. Each iteration leaves a native C-API object pinned until the Sub exits."
    ),
    "LS-DOM-002": (
        "Inside a loop, a secondary `GetDocumentByUNID` / `GetDocumentByKey` / `CreateDocument` "
        "assigns a NotesDocument that is never `Delete`d before the next iteration, leaking "
        "one handle per pass."
    ),
    "LS-DOM-003": (
        "`Public … As NotesDocument|NotesDatabase|NotesView` in (Declarations) pins native "
        "handles in server RAM across agent and library executions."
    ),
    "LS-DOM-004": (
        "`Set doc = Nothing` clears the LotusScript pointer variable but does not explicitly "
        "release the C-API handle the way `Delete doc` does; native memory may linger until "
        "the calling routine terminates."
    ),
    "DOM-BS-001": (
        "AI control-flow analysis found a Domino handle allocation path that static regex rules "
        "missed — typically nested branches, exception paths, or non-standard cleanup gaps."
    ),
    "DOM-014": (
        "An Item, MIMEEntity, or RichTextItem handle is acquired (getFirstItem / getMIMEEntity / "
        "createRichTextItem) without a matching recycle/Delete — native C-API memory leaks."
    ),
    "LS-DOM-005": (
        "LotusScript GetFirstItem / GetMIMEEntity / CreateRichTextItem assigns a handle without Delete."
    ),
    "DOM-015": (
        "A ViewNavigator or ViewEntryCollection is created without recycle — NIF locks and handles linger."
    ),
    "LS-DOM-006": (
        "NotesViewNavigator / NotesViewEntryCollection created without Delete — index locks persist."
    ),
    "LS-DOM-007": (
        "On Error GoTo handler exits without Delete of Notes* temps allocated on the main path."
    ),
    "DOM-016": (
        "db.search / FTSearch inside a loop returns a collection that is never recycled."
    ),
    "DOM-017": (
        "An EmbeddedObject / attachment handle is acquired (getEmbeddedObject / getObjects) "
        "without `.recycle()`. Attachment loops pin C-API slots per file."
    ),
    "DOM-018": (
        "ViewEntry.getDocument() materializes a full Document handle. Without recycling the "
        "Document each iteration (and the entry), navigator walks exhaust the handle table quickly."
    ),
    "DOM-019": (
        "getAllDocumentsByKey / getAllUnreadDocuments / FTSearchRange returns a DocumentCollection "
        "that is never recycled — many child handles stay pinned."
    ),
    "DOM-020": (
        "Code calls `.recycle()` on Session or the current Database. Those are platform-shared "
        "handles; recycling them can crash the HTTP task or invalidate subsequent requests."
    ),
    "DOM-021": (
        "A Stream / NotesStream is created without `.recycle()`. Native I/O handles leak, "
        "especially when streams are opened per document."
    ),
    "DOM-022": (
        "A DocumentCollection / ViewEntryCollection / ViewNavigator / DateTime Vector is walked "
        "with child `.recycle()`, but the parent wrapper is never recycled in finally — native "
        "slots stay pinned after the loop."
    ),
    "DOM-023": (
        "An XPages Managed Bean or sessionScope/viewScope/applicationScope retains a live "
        "lotus.domino.NotesBase (Document/Database/View/…) member across HTTP requests."
    ),
    "DOM-024": (
        "Code calls `.recycle()` on platform-owned globals (session, getCurrentDatabase / XPages "
        "`database`, or dominoNAF). Those must never be recycled; missing recycle on them is NOT a leak."
    ),
    "LS-DOM-008": (
        "Search / FTSearch inside a LotusScript loop without Delete of the returned collection."
    ),
    "PERF-001": (
        "A view write/iteration loop runs without view.AutoUpdate = False, forcing NIF rebuilds "
        "on every document change."
    ),
    "PERF-002": (
        "db.getView / GetView is called inside a loop instead of hoisting the view handle outside."
    ),
    "PERF-003": (
        "doc.save / doc.Save runs on every collection iteration without batching — high I/O and log bloat."
    ),
    "PERF-004": (
        "GetNthDocument / GetNthEntry inside a counted loop re-walks the collection from the start "
        "on every call — O(n²) that can hang agents or exceed HTTP task timeouts."
    ),
    "DOM-BS-002": (
        "AI cross-module analysis found a Document/NotesDocument passed or returned across functions "
        "where neither caller nor callee clearly owns recycle/Delete."
    ),
    "DOM-OWN-001": (
        "Static call-graph analysis found a Domino handle returned or accepted across a function "
        "boundary without Delete/.recycle() on either the callee or the caller after the call."
    ),
    "FORM-001": (
        "Formula repeats @DbLookup/@DbColumn. Each call hits NSF/NIF and can dominate computed-field cost."
    ),
    "FORM-002": (
        "Formula loops (@While/@For) while calling @DbLookup/@DbColumn — lookup cost scales with iterations."
    ),
    "FORM-003": (
        "Formula embeds a credential-like literal or plaintext http:// endpoint."
    ),
    "FORM-004": (
        "Form or code risks exceeding Domino's document summary limit (~32KB): too many "
        "summary-eligible fields, IsSummary=True on large items, or many ReplaceItemValue "
        "writes without clearing the summary flag."
    ),
    "EXT-001": (
        "JDBC/DB2 Connection (getConnection / OpenConnection) is opened without .close() "
        "in finally — external pool exhaustion."
    ),
    "EXT-002": (
        "NotesHTTPRequest / HttpURLConnection / response stream acquired without "
        "close/disconnect — socket and stream leaks under load."
    ),
    "LS-EXT-001": (
        "LotusScript JavaSession created without Set … = Nothing / Close — LS→JVM bridge leak."
    ),
    "LS-EXT-002": (
        "LotusScript OpenConnection / SetTheConnection without CloseConnection — DB2/ODBC leak."
    ),
    "SEC-001": (
        "A password or secret is hardcoded in source and used with an http:// endpoint, exposing "
        "credentials in cleartext."
    ),
    "SEC-002": (
        "GetDocumentByUNID is driven by URL/query input without an evident authorization check, "
        "allowing UNID enumeration / unauthorized document access."
    ),
}

REMEDIATION_GUIDES: dict[str, dict[str, str]] = {
    "DOM-001": {
        "lotusscript": "Assign the object to a variable, use it, then `Delete` it when finished.",
        "java": "Assign intermediates to variables and call `.recycle()` in a `finally` block.",
    },
    "DOM-002": {
        "lotusscript": (
            "Capture `nextDoc` first, finish work on `doc`, then `Delete doc` before "
            "`Set doc = nextDoc`."
        ),
        "java": (
            "Capture `next` first, process `doc` inside `try`, always `doc.recycle()` in "
            "`finally`, then `doc = next`."
        ),
    },
    "DOM-003": {
        "lotusscript": "Ensure every Notes* object you create is `Delete`d on all exit paths.",
        "java": "Wrap acquisitions in `try`/`finally` and recycle every allocated handle.",
    },
    "DOM-010": {
        "lotusscript": "Pair every `Set` of a Notes* object with a later `Delete` on all paths.",
        "java": "Use `try`/`finally` and `.recycle()` for every Database/View/Document you open.",
    },
    "DOM-011": {
        "lotusscript": "Always `Delete` child documents/entries before recycling/closing the parent view.",
        "java": "Recycle children first; only recycle the parent View/Database after the loop.",
    },
    "DOM-012": {
        "lotusscript": "Put `Delete doc` after the business `If`, so every loop iteration releases the handle.",
        "java": "Move `.recycle()` into a `finally` that runs whether or not the business `if` matched.",
    },
    "DOM-013": {
        "lotusscript": "Use a temp `nextDoc`, `Delete doc`, then `Set doc = nextDoc`.",
        "java": "Use a temp `next`, `doc.recycle()`, then `doc = next`.",
    },
    "LS-DOM-001": {
        "lotusscript": (
            "Capture `nextDoc` first, finish work on `doc`, then `Delete doc` before "
            "`Set doc = nextDoc`."
        ),
    },
    "LS-DOM-002": {
        "lotusscript": (
            "After each in-loop lookup/create, `Delete lookupDoc` (or set to a fresh handle "
            "only after Delete) before the next iteration."
        ),
    },
    "LS-DOM-003": {
        "lotusscript": (
            "Do not declare Public NotesDocument/Database/View in (Declarations). Dim them "
            "inside the Sub and Delete before Exit; persist UniversalIDs if needed."
        ),
    },
    "LS-DOM-004": {
        "lotusscript": "Call `Delete doc` before (or instead of) `Set doc = Nothing`.",
    },
    "DOM-BS-001": {
        "lotusscript": (
            "Trace every Notes* allocation through all branches; `Delete` on every exit path "
            "(including error handlers) before the Sub ends."
        ),
        "java": (
            "Wrap every Domino acquisition in `try`/`finally` and `.recycle()` on all paths, "
            "including early returns and catch blocks."
        ),
    },
    "DOM-014": {
        "lotusscript": "After GetFirstItem/GetMIMEEntity/CreateRichTextItem, `Delete` the item/MIME object.",
        "java": "Recycle Item/MIMEEntity/RichTextItem in finally after use.",
    },
    "LS-DOM-005": {
        "lotusscript": "Delete Item/MIME/RichText handles after use, especially inside loops.",
    },
    "DOM-015": {
        "lotusscript": "Delete ViewEntry children then Delete the ViewNavigator / ViewEntryCollection.",
        "java": "Recycle entries then navigator/collection.recycle() after the loop.",
    },
    "LS-DOM-006": {
        "lotusscript": "Delete NotesViewNavigator / NotesViewEntryCollection after iteration.",
    },
    "LS-DOM-007": {
        "lotusscript": "In the On Error handler, Delete temporary Notes* objects before Exit Sub / Resume.",
    },
    "DOM-016": {
        "lotusscript": "Delete the DocumentCollection from Search/FTSearch before the next iteration.",
        "java": "collection.recycle() after processing each in-loop search result.",
    },
    "DOM-017": {
        "java": "Recycle each EmbeddedObject in finally after reading; do not leave attachments open across loop iterations.",
    },
    "DOM-018": {
        "java": "After entry.getDocument(), process then doc.recycle() every iteration; recycle the ViewEntry before getNextEntry.",
    },
    "DOM-019": {
        "java": "Walk the DocumentCollection with next-doc recycle, then collection.recycle() when finished.",
    },
    "DOM-020": {
        "java": "Never recycle Session or getCurrentDatabase()/XPages database — only recycle Database handles you opened via getDatabase.",
    },
    "DOM-021": {
        "java": "session.createStream() … write/read … stream.recycle() in finally.",
    },
    "DOM-022": {
        "java": (
            "Recycle each child Document/Entry/DateTime in the loop, then recycle the parent "
            "DocumentCollection / ViewEntryCollection / ViewNavigator / Vector in finally."
        ),
    },
    "DOM-023": {
        "java": (
            "Do not store Document/Database/View on bean fields or in sessionScope. "
            "Cache UNIDs / DTOs; open handles per request and recycle in finally."
        ),
    },
    "DOM-024": {
        "java": (
            "Never recycle session, getCurrentDatabase()/XPages database, or dominoNAF. "
            "Only recycle Database handles you opened via getDatabase."
        ),
    },
    "LS-DOM-008": {
        "lotusscript": "Delete the Search/FTSearch collection before continuing the outer loop.",
    },
    "PERF-001": {
        "lotusscript": "Set view.AutoUpdate = False before the write loop; restore True afterward if needed.",
        "java": "view.setAutoUpdate(false) before the loop; restore true after.",
    },
    "PERF-002": {
        "lotusscript": "Call GetView once before the loop; reuse the NotesView handle inside.",
        "java": "Hoist db.getView(...) above the loop; recycle once after.",
    },
    "PERF-003": {
        "lotusscript": "Avoid Save on every iteration when possible; batch updates or checkpoint periodically.",
        "java": "Avoid doc.save() every iteration; batch or throttle writes.",
    },
    "PERF-004": {
        "lotusscript": (
            "Replace `GetNthDocument(i)` / `GetNthEntry(i)` in a For loop with "
            "`GetFirstDocument` / `GetNextDocument` (or Entry equivalents)."
        ),
        "java": (
            "Replace `getNthDocument(i)` / `getNthEntry(i)` in a for-loop with "
            "`getFirstDocument` / `getNextDocument` (or Entry equivalents)."
        ),
    },
    "DOM-BS-002": {
        "lotusscript": "Document ownership: either callee Deletes before return, or caller Deletes after use — never neither.",
        "java": "Clarify ownership: recycle in callee before return, or in caller after use — never neither.",
    },
    "DOM-OWN-001": {
        "lotusscript": "Document ownership: either callee Deletes before return, or caller Deletes after use — never neither.",
        "java": "Clarify ownership: recycle in callee before return, or in caller after use — never neither.",
    },
    "FORM-001": {
        "lotusscript": "Cache @DbLookup results or move batch lookups to LotusScript/Java.",
        "java": "Cache lookups or move batch work out of formula.",
        "formula": "Reduce repeated @DbLookup/@DbColumn; cache results in fields where possible.",
    },
    "FORM-002": {
        "formula": "Hoist @DbLookup outside @While/@For, or precompute in an agent.",
        "lotusscript": "Hoist lookups outside formula loops.",
        "java": "Hoist lookups outside formula loops.",
    },
    "FORM-003": {
        "formula": "Remove hardcoded secrets; use HTTPS endpoints only.",
        "lotusscript": "Remove hardcoded secrets; use HTTPS endpoints only.",
        "java": "Remove hardcoded secrets; use HTTPS endpoints only.",
    },
    "FORM-004": {
        "java": (
            "After writing large text: item.setSummary(false). Prefer RichText for bulky "
            "content; only keep IsSummary on fields used in views/search."
        ),
        "lotusscript": (
            "After ReplaceItemValue on large text: item.IsSummary = False. Prefer Rich Text "
            "items; audit form fields that are not needed in views."
        ),
        "formula": (
            "Reduce summary-eligible fields on the form; move bulky data to Rich Text; "
            "optional server stopgap NSF_LargeSummary=1."
        ),
    },
    "EXT-001": {
        "java": (
            "Connection conn = null;\n"
            "try {\n"
            "  conn = DriverManager.getConnection(url, user, pass);\n"
            "  // work\n"
            "} finally {\n"
            "  if (conn != null) try { conn.close(); } catch (Exception ignore) {}\n"
            "}"
        ),
    },
    "EXT-002": {
        "java": (
            "NotesHTTPRequest http = null;\n"
            "try {\n"
            "  http = session.createHTTPRequest();\n"
            "  // GET / read body\n"
            "} finally {\n"
            "  if (http != null) http.close();\n"
            "}"
        ),
    },
    "LS-EXT-001": {
        "lotusscript": (
            "Dim js As JavaSession\n"
            "Set js = New JavaSession\n"
            "' … Java calls …\n"
            "Set js = Nothing"
        ),
    },
    "LS-EXT-002": {
        "lotusscript": (
            "Call libDB2.OpenConnection(...)\n"
            "On Error GoTo Done\n"
            "' … work …\n"
            "Done:\n"
            "Call libDB2.CloseConnection()\n"
            "Exit Sub"
        ),
    },
    "SEC-001": {
        "lotusscript": "Store credentials outside source (env/secret store); call https:// endpoints only.",
        "java": "Load secrets from configuration/vault; use HTTPS URLs only.",
    },
    "SEC-002": {
        "lotusscript": "Before GetDocumentByUNID from query input, verify the user may open that document (ACL/role).",
        "java": "Authorize the UNID from request parameters before getDocumentByUNID.",
    },
}


def normalize_language(language: str | None) -> str:
    lang = (language or "").strip().lower()
    if lang in {"lotusscript", "ls", "lss", "notes"} or "lotus" in lang:
        return "lotusscript"
    if lang in {"csjs", "client_javascript", "client-javascript"} or "csjs" in lang:
        return "csjs"
    if lang in {"ssjs", "jscript"} or lang.startswith("ssjs"):
        return "ssjs"
    if lang in {"javascript", "js", "jss"}:
        # Ambiguous legacy label — treat as SSJS for remediation templates
        return "ssjs"
    if "xpage" in lang or lang == "xsp":
        return "xpages"
    if lang == "java" or (lang.startswith("java") and "script" not in lang):
        return "java"
    return lang or "java"


def language_label(language: str | None) -> str:
    lang = normalize_language(language)
    return {
        "lotusscript": "LotusScript",
        "java": "Java",
        "ssjs": "SSJS",
        "csjs": "CSJS (client)",
        "xpages": "XPages",
        "javascript": "SSJS",
    }.get(lang, language or "Unknown")


def is_java_like(language: str | None) -> bool:
    return normalize_language(language) in {"java", "javascript", "ssjs", "xpages"}


def remediation_template(
    rule_id: str,
    language: str | None,
    *,
    has_loop: bool | None = None,
) -> str:
    """Return a language-appropriate TO-BE code template for the rule.

    When ``has_loop`` is False, prefer linear Delete / try-finally templates
    instead of GetNextDocument loop-advancement patterns.
    """
    lang = normalize_language(language)
    ls = lang == "lotusscript"
    looped = True if has_loop is None else bool(has_loop)

    # Non-loop linear templates (one-shot helpers like EncodeBase64)
    linear_ls: dict[str, str] = {
        "DOM-002": (
            "Dim doc As NotesDocument\n"
            "Set doc = db.GetDocumentByUNID(unid$)\n"
            "' ... one-shot work ...\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "DOM-003": (
            "Dim doc As NotesDocument\n"
            "Set doc = db.CreateDocument\n"
            "' ... work ...\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "DOM-010": (
            "Dim doc As NotesDocument\n"
            "Dim mime As NotesMIMEEntity\n"
            "Set doc = db.CreateDocument\n"
            "Set mime = doc.CreateMIMEEntity\n"
            "' ... work ...\n"
            "If Not mime Is Nothing Then Delete mime\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "DOM-011": (
            "Dim doc As NotesDocument\n"
            "Set doc = view.GetFirstDocument()\n"
            "' ... one-shot work ...\n"
            "If Not doc Is Nothing Then Delete doc\n"
            "' Delete view only if this routine opened it"
        ),
        "DOM-013": (
            "Dim doc As NotesDocument\n"
            "Set doc = db.GetDocumentByUNID(unid$)\n"
            "' ... work ...\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "LS-DOM-001": (
            "Dim doc As NotesDocument\n"
            "Set doc = db.GetDocumentByUNID(unid$)\n"
            "' One-shot helper — no loop advance required\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "LS-DOM-002": (
            "Dim lookupDoc As NotesDocument\n"
            "Set lookupDoc = db.GetDocumentByUNID(unid$)\n"
            "' ... work ...\n"
            "If Not lookupDoc Is Nothing Then Delete lookupDoc"
        ),
        "LS-DOM-004": (
            "' EncodeBase64-style one-shot helper — Delete then optional Nothing\n"
            "Dim doc As NotesDocument\n"
            "Dim body As NotesMIMEEntity\n"
            "Set doc = db.CreateDocument\n"
            "Set body = doc.CreateMIMEEntity\n"
            "' ... encode ...\n"
            "If Not body Is Nothing Then Delete body\n"
            "If Not doc Is Nothing Then Delete doc\n"
            "Set doc = Nothing"
        ),
        "LS-DOM-005": (
            "Dim body As NotesMIMEEntity\n"
            "Set body = doc.CreateMIMEEntity\n"
            "' ... use MIME ...\n"
            "If Not body Is Nothing Then Delete body\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
        "DOM-014": (
            "Dim body As NotesMIMEEntity\n"
            "Set body = doc.CreateMIMEEntity\n"
            "' ... work ...\n"
            "If Not body Is Nothing Then Delete body"
        ),
        "DOM-BS-001": (
            "Dim doc As NotesDocument\n"
            "Set doc = db.CreateDocument\n"
            "' ... one-shot work ...\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
    }
    linear_java: dict[str, str] = {
        "DOM-002": (
            "Document doc = null;\n"
            "try {\n"
            "  doc = db.getDocumentByUNID(unid);\n"
            "  // ... one-shot work ...\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-003": (
            "Document doc = null;\n"
            "try {\n"
            "  doc = db.createDocument();\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-010": (
            "Document doc = null;\n"
            "MIMEEntity mime = null;\n"
            "try {\n"
            "  doc = db.createDocument();\n"
            "  mime = doc.createMIMEEntity();\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (mime != null) mime.recycle();\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-014": (
            "MIMEEntity entity = null;\n"
            "try {\n"
            "  entity = doc.getMIMEEntity();\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (entity != null) entity.recycle();\n"
            "}"
        ),
        "DOM-BS-001": (
            "Document doc = null;\n"
            "try {\n"
            "  doc = db.createDocument();\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
    }

    if not looped:
        if ls and rule_id in linear_ls:
            return linear_ls[rule_id]
        if not ls and rule_id in linear_java:
            return linear_java[rule_id]

    templates_ls: dict[str, str] = {
        "DOM-001": (
            "' Assign intermediates — never chain Domino constructors\n"
            "Dim dt As NotesDateTime\n"
            "Set dt = session.CreateDateTime(raw)\n"
            "value$ = dt.DateOnly\n"
            "Delete dt   ' release native C-API handle"
        ),
        "DOM-002": (
            "Set doc = view.GetFirstDocument()\n"
            "Do While Not (doc Is Nothing)\n"
            "    Set nextDoc = view.GetNextDocument(doc)\n"
            "\n"
            "    ' Process current document\n"
            "    ' ...\n"
            "\n"
            "    ' Release native C-API handle explicitly\n"
            "    Delete doc\n"
            "    Set doc = nextDoc\n"
            "Loop"
        ),
        "DOM-003": (
            "Dim db As NotesDatabase\n"
            "Dim view As NotesView\n"
            "Dim doc As NotesDocument\n"
            "Set db = session.CurrentDatabase\n"
            "Set view = db.GetView(\"Lookup\")\n"
            "Set doc = view.GetFirstDocument()\n"
            "' ... work ...\n"
            "If Not doc Is Nothing Then Delete doc\n"
            "Delete view\n"
            "' db is CurrentDatabase — do not Delete the current db handle lightly"
        ),
        "DOM-010": (
            "Dim view As NotesView\n"
            "Dim doc As NotesDocument\n"
            "Set view = db.GetView(\"Lookup\")\n"
            "Set doc = view.GetFirstDocument()\n"
            "Do While Not (doc Is Nothing)\n"
            "    Set nextDoc = view.GetNextDocument(doc)\n"
            "    ' ... process ...\n"
            "    Delete doc\n"
            "    Set doc = nextDoc\n"
            "Loop\n"
            "Delete view"
        ),
        "DOM-011": (
            "' Children first, parent last\n"
            "Set doc = view.GetFirstDocument()\n"
            "Do While Not (doc Is Nothing)\n"
            "    Set nextDoc = view.GetNextDocument(doc)\n"
            "    ' ... process ...\n"
            "    Delete doc\n"
            "    Set doc = nextDoc\n"
            "Loop\n"
            "Delete view   ' only after all child docs are gone"
        ),
        "DOM-012": (
            "Set doc = collection.GetFirstDocument()\n"
            "Do While Not (doc Is Nothing)\n"
            "    Set nextDoc = collection.GetNextDocument(doc)\n"
            "    If shouldProcess Then\n"
            "        ' ... business logic ...\n"
            "    End If\n"
            "    Delete doc   ' ALWAYS — outside the business If\n"
            "    Set doc = nextDoc\n"
            "Loop"
        ),
        "DOM-013": (
            "Set nextDoc = view.GetNextDocument(doc)\n"
            "Delete doc            ' release previous handle first\n"
            "Set doc = nextDoc"
        ),
        "DOM-006": (
            "' Do not store NotesSession/NotesDatabase/NotesDocument in Public/Static module fields.\n"
            "' Obtain handles inside the Sub/Function and Delete them before Exit."
        ),
        "DOM-007": (
            "' Cache identifiers, not live handles\n"
            "Call sessionScope.ReplaceItemValue(\"orderUnid\", doc.UniversalID)\n"
            "Delete doc"
        ),
        "DOM-008": (
            "' Prefer view column values over opening every document in a hot loop\n"
            "Set entry = entries.GetFirstEntry()\n"
            "Do While Not (entry Is Nothing)\n"
            "    cols = entry.ColumnValues\n"
            "    Set nextEntry = entries.GetNextEntry(entry)\n"
            "    Delete entry\n"
            "    Set entry = nextEntry\n"
            "Loop"
        ),
        "DOM-009": (
            "' Prefer native date math outside Domino DateTime when formatting in loops\n"
            "formatted$ = Format$(theDate, \"yyyymmdd\")\n"
            "' Create NotesDateTime only when writing an item"
        ),
        "LS-DOM-001": (
            "' REMEDIATED LOTUSSCRIPT LOOP PATTERN\n"
            "Dim doc As NotesDocument\n"
            "Dim nextDoc As NotesDocument\n"
            "\n"
            "Set doc = view.GetFirstDocument()\n"
            "Do While Not (doc Is Nothing)\n"
            "    ' 1. Fetch next handle first\n"
            "    Set nextDoc = view.GetNextDocument(doc)\n"
            "\n"
            "    ' 2. Process current document\n"
            "    ' ...\n"
            "\n"
            "    ' 3. Explicitly release C-API handle\n"
            "    Delete doc\n"
            "\n"
            "    ' 4. Advance pointer\n"
            "    Set doc = nextDoc\n"
            "Loop"
        ),
        "LS-DOM-002": (
            "Do While Not (doc Is Nothing)\n"
            "    Dim lookupDoc As NotesDocument\n"
            "    Set lookupDoc = db.GetDocumentByUNID(unid$)\n"
            "    If Not lookupDoc Is Nothing Then\n"
            "        ' ... use lookupDoc ...\n"
            "        Delete lookupDoc   ' release before next iteration\n"
            "    End If\n"
            "\n"
            "    Set nextDoc = view.GetNextDocument(doc)\n"
            "    Delete doc\n"
            "    Set doc = nextDoc\n"
            "Loop"
        ),
        "LS-DOM-003": (
            "' BAD — pins C-API memory across executions:\n"
            "' Public gDoc As NotesDocument\n"
            "' Public gDb As NotesDatabase\n"
            "' Public gView As NotesView\n"
            "\n"
            "' GOOD — local lifetime + Delete:\n"
            "Sub ProcessOrder(unid As String)\n"
            "    Dim db As NotesDatabase\n"
            "    Dim doc As NotesDocument\n"
            "    Set db = session.CurrentDatabase\n"
            "    Set doc = db.GetDocumentByUNID(unid)\n"
            "    ' ... work ...\n"
            "    If Not doc Is Nothing Then Delete doc\n"
            "End Sub"
        ),
        "LS-DOM-004": (
            "' Prefer explicit Delete — Nothing alone delays native release\n"
            "If Not doc Is Nothing Then\n"
            "    Delete doc\n"
            "End If\n"
            "' Optional: clear the pointer after Delete\n"
            "Set doc = Nothing"
        ),
        "DOM-BS-001": (
            "' AI blind-spot remediation — release on every path\n"
            "Dim doc As NotesDocument\n"
            "On Error GoTo Fail\n"
            "Set doc = db.GetDocumentByUNID(unid$)\n"
            "' ... work ...\n"
            "Delete doc\n"
            "Exit Sub\n"
            "Fail:\n"
            "    If Not doc Is Nothing Then Delete doc\n"
            "    Resume Next"
        ),
        "LS-DOM-005": (
            "Dim item As NotesItem\n"
            "Set item = doc.GetFirstItem(\"Body\")\n"
            "' ... use item ...\n"
            "If Not item Is Nothing Then Delete item"
        ),
        "LS-DOM-006": (
            "Dim nav As NotesViewNavigator\n"
            "Dim entry As NotesViewEntry\n"
            "Set nav = view.CreateViewNav()\n"
            "Set entry = nav.GetFirst()\n"
            "Do While Not entry Is Nothing\n"
            "    Dim nextEntry As NotesViewEntry\n"
            "    Set nextEntry = nav.GetNext(entry)\n"
            "    Delete entry\n"
            "    Set entry = nextEntry\n"
            "Loop\n"
            "Delete nav"
        ),
        "LS-DOM-007": (
            "On Error GoTo Fail\n"
            "Dim doc As NotesDocument\n"
            "Set doc = db.GetDocumentByUNID(unid$)\n"
            "' ... work ...\n"
            "Delete doc\n"
            "Exit Sub\n"
            "Fail:\n"
            "    If Not doc Is Nothing Then Delete doc\n"
            "    Exit Sub"
        ),
        "LS-DOM-008": (
            "Do While Not outer Is Nothing\n"
            "    Dim coll As NotesDocumentCollection\n"
            "    Set coll = db.Search({Form = \"Memo\"}, Nothing, 0)\n"
            "    ' ... process coll ...\n"
            "    Delete coll\n"
            "    Set outer = view.GetNextDocument(outer)\n"
            "Loop"
        ),
        "PERF-001": (
            "view.AutoUpdate = False\n"
            "Set doc = view.GetFirstDocument()\n"
            "Do While Not doc Is Nothing\n"
            "    ' ... modify / save ...\n"
            "    Set doc = view.GetNextDocument(doc)\n"
            "Loop\n"
            "view.AutoUpdate = True"
        ),
        "PERF-002": (
            "Dim view As NotesView\n"
            "Set view = db.GetView(\"All\")   ' hoist outside loop\n"
            "Do While Not doc Is Nothing\n"
            "    ' use view — do not GetView again here\n"
            "    Set doc = view.GetNextDocument(doc)\n"
            "Loop\n"
            "Delete view"
        ),
        "PERF-003": (
            "' Prefer fewer Saves — e.g. update in memory then Save selectively\n"
            "Do While Not doc Is Nothing\n"
            "    Call doc.ReplaceItemValue(\"Flag\", \"1\")\n"
            "    ' Call doc.Save(True, False) only when required, or checkpoint every N docs\n"
            "    Set doc = coll.GetNextDocument(doc)\n"
            "Loop"
        ),
        "PERF-004": (
            "' BAD — O(n²): each GetNthDocument re-walks from the start\n"
            "' For i = 1 To coll.Count\n"
            "'     Set doc = coll.GetNthDocument(i)\n"
            "' Next\n"
            "\n"
            "' GOOD — O(n) sequential walk\n"
            "Dim doc As NotesDocument\n"
            "Dim nextDoc As NotesDocument\n"
            "Set doc = coll.GetFirstDocument()\n"
            "Do While Not doc Is Nothing\n"
            "    Set nextDoc = coll.GetNextDocument(doc)\n"
            "    ' ... process doc ...\n"
            "    Delete doc\n"
            "    Set doc = nextDoc\n"
            "Loop"
        ),
        "DOM-014": (
            "Dim item As NotesItem\n"
            "Set item = doc.GetFirstItem(\"Subject\")\n"
            "If Not item Is Nothing Then Delete item"
        ),
        "DOM-015": (
            "Dim nav As NotesViewNavigator\n"
            "Set nav = view.CreateViewNav()\n"
            "' ... iterate entries with Delete each ...\n"
            "Delete nav"
        ),
        "DOM-016": (
            "Dim coll As NotesDocumentCollection\n"
            "Set coll = db.FTSearch(query$, 0)\n"
            "' ... process ...\n"
            "Delete coll"
        ),
        "SEC-001": (
            "' Do not hardcode passwords; load from secure config\n"
            "Dim password As String\n"
            "password = GetSecureSecret(\"bossrest.password\")\n"
            "url$ = \"https://secure.example.com/api\"   ' never http:// for credentials"
        ),
        "SEC-002": (
            "unid$ = GetQueryParameter(\"unid\")\n"
            "If Not UserMayOpenDocument(unid$) Then\n"
            "    Error 401, \"Unauthorized\"\n"
            "End If\n"
            "Set doc = db.GetDocumentByUNID(unid$)"
        ),
        "DOM-BS-002": (
            "' Callee returns doc — caller owns Delete\n"
            "Set doc = FetchDoc(unid$)\n"
            "' ... work ...\n"
            "If Not doc Is Nothing Then Delete doc"
        ),
    }

    templates_java: dict[str, str] = {
        "DOM-001": (
            "// Assign intermediates and recycle explicitly\n"
            "DateTime dt = null;\n"
            "try {\n"
            "  dt = session.createDateTime(raw);\n"
            "  String value = dt.getDateOnly();\n"
            "} finally {\n"
            "  if (dt != null) dt.recycle(); // Release native C-API handle\n"
            "}"
        ),
        "DOM-002": (
            "Document doc = view.getFirstDocument();\n"
            "while (doc != null) {\n"
            "  Document nextDoc = view.getNextDocument(doc);\n"
            "  try {\n"
            "    // Process current document\n"
            "  } finally {\n"
            "    doc.recycle(); // Release native C-API handle\n"
            "  }\n"
            "  doc = nextDoc;\n"
            "}"
        ),
        "DOM-003": (
            "Database db = null;\n"
            "View view = null;\n"
            "try {\n"
            "  db = session.getDatabase(server, path);\n"
            "  view = db.getView(\"Lookup\");\n"
            "  // work\n"
            "} finally {\n"
            "  if (view != null) view.recycle();\n"
            "  if (db != null) db.recycle();\n"
            "}"
        ),
        "DOM-010": (
            "Database db = null;\n"
            "View view = null;\n"
            "Document doc = null;\n"
            "try {\n"
            "  db = session.getDatabase(server, path);\n"
            "  view = db.getView(\"Lookup\");\n"
            "  doc = view.getFirstDocument();\n"
            "  while (doc != null) {\n"
            "    Document nextDoc = view.getNextDocument(doc);\n"
            "    try {\n"
            "      // Process current document\n"
            "    } finally {\n"
            "      doc.recycle(); // Release native C-API handle\n"
            "    }\n"
            "    doc = nextDoc;\n"
            "  }\n"
            "} finally {\n"
            "  if (view != null) view.recycle();\n"
            "  if (db != null) db.recycle();\n"
            "}"
        ),
        "DOM-011": (
            "// Recycle children first, parent last\n"
            "Document doc = view.getFirstDocument();\n"
            "while (doc != null) {\n"
            "  Document nextDoc = view.getNextDocument(doc);\n"
            "  try { /* work */ } finally { doc.recycle(); }\n"
            "  doc = nextDoc;\n"
            "}\n"
            "view.recycle(); // only after all children are gone\n"
            "db.recycle();"
        ),
        "DOM-012": (
            "Document doc = coll.getFirstDocument();\n"
            "while (doc != null) {\n"
            "  Document nextDoc = coll.getNextDocument(doc);\n"
            "  try {\n"
            "    if (shouldProcess(doc)) {\n"
            "      // business logic\n"
            "    }\n"
            "  } finally {\n"
            "    doc.recycle(); // ALWAYS — outside the business if\n"
            "  }\n"
            "  doc = nextDoc;\n"
            "}"
        ),
        "DOM-013": (
            "Document nextDoc = view.getNextDocument(doc);\n"
            "doc.recycle(); // release previous handle first\n"
            "doc = nextDoc;"
        ),
        "DOM-004": (
            "// Do not trust ODA auto-dispose — use explicit finally recycle:\n"
            "lotus.domino.Document doc = null;\n"
            "try {\n"
            "  doc = database.getDocumentByUNID(unid);\n"
            "  String subject = doc.getItemValueString(\"Subject\");\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-005": (
            "// Prefer lotus.domino + explicit recycle over mixed ODA/lotus boundaries.\n"
            "lotus.domino.Document doc = null;\n"
            "try {\n"
            "  doc = database.getDocumentByUNID(unid);\n"
            "  // work\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-006": (
            "// Do not store Session/Database/Document/View in static fields.\n"
            "// Obtain handles per-request from the current session context."
        ),
        "DOM-007": (
            "// Cache serializable data — not Document/Database handles\n"
            "sessionScope.put(\"orderUnid\", doc.getUniversalID());"
        ),
        "DOM-008": (
            "ViewEntryCollection entries = view.getAllEntries();\n"
            "ViewEntry entry = entries.getFirstEntry();\n"
            "while (entry != null) {\n"
            "  Vector cols = entry.getColumnValues(); // prefer over getDocument()\n"
            "  ViewEntry next = entries.getNextEntry(entry);\n"
            "  entry.recycle();\n"
            "  entry = next;\n"
            "}"
        ),
        "DOM-009": (
            "// Prefer JVM dates inside hot loops\n"
            "java.time.LocalDate d = LocalDate.parse(raw);\n"
            "String iso = d.toString();\n"
            "// Convert to Domino DateTime only when writing Items"
        ),
        "DOM-BS-001": (
            "Document doc = null;\n"
            "try {\n"
            "  doc = db.getDocumentByUNID(unid);\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle(); // every exit path\n"
            "}"
        ),
        "DOM-014": (
            "Item item = null;\n"
            "try {\n"
            "  item = doc.getFirstItem(\"Subject\");\n"
            "  // ...\n"
            "} finally {\n"
            "  if (item != null) item.recycle();\n"
            "}"
        ),
        "DOM-015": (
            "ViewNavigator nav = null;\n"
            "try {\n"
            "  nav = view.createViewNav();\n"
            "  // iterate + recycle entries\n"
            "} finally {\n"
            "  if (nav != null) nav.recycle();\n"
            "}"
        ),
        "DOM-016": (
            "DocumentCollection coll = null;\n"
            "try {\n"
            "  coll = db.FTSearch(query, 0);\n"
            "  // process\n"
            "} finally {\n"
            "  if (coll != null) coll.recycle();\n"
            "}"
        ),
        "DOM-017": (
            "EmbeddedObject emb = null;\n"
            "try {\n"
            "  emb = rtitem.getEmbeddedObject(name);\n"
            "  // read bytes / extract\n"
            "} finally {\n"
            "  if (emb != null) emb.recycle();\n"
            "}"
        ),
        "DOM-018": (
            "ViewEntry entry = nav.getFirst();\n"
            "while (entry != null) {\n"
            "  ViewEntry next = nav.getNext(entry);\n"
            "  Document doc = null;\n"
            "  try {\n"
            "    doc = entry.getDocument();\n"
            "    // process doc\n"
            "  } finally {\n"
            "    if (doc != null) doc.recycle();\n"
            "    entry.recycle();\n"
            "  }\n"
            "  entry = next;\n"
            "}"
        ),
        "DOM-019": (
            "DocumentCollection coll = null;\n"
            "try {\n"
            "  coll = view.getAllDocumentsByKey(key, true);\n"
            "  Document doc = coll.getFirstDocument();\n"
            "  while (doc != null) {\n"
            "    Document next = coll.getNextDocument(doc);\n"
            "    try { /* work */ } finally { doc.recycle(); }\n"
            "    doc = next;\n"
            "  }\n"
            "} finally {\n"
            "  if (coll != null) coll.recycle();\n"
            "}"
        ),
        "DOM-020": (
            "// DO NOT recycle platform handles:\n"
            "// session.recycle();              // BAD\n"
            "// database.recycle();             // BAD in XPages (current NSF)\n"
            "// getCurrentDatabase().recycle(); // BAD\n"
            "\n"
            "// Only recycle databases you opened:\n"
            "Database other = null;\n"
            "try {\n"
            "  other = session.getDatabase(server, path);\n"
            "  // work\n"
            "} finally {\n"
            "  if (other != null) other.recycle();\n"
            "}"
        ),
        "DOM-021": (
            "Stream stream = null;\n"
            "try {\n"
            "  stream = session.createStream();\n"
            "  // write / read\n"
            "} finally {\n"
            "  if (stream != null) stream.recycle();\n"
            "}"
        ),
        "DOM-022": (
            "DocumentCollection coll = null;\n"
            "try {\n"
            "  coll = db.FTSearch(query, 0);\n"
            "  Document doc = coll.getFirstDocument();\n"
            "  while (doc != null) {\n"
            "    Document next = coll.getNextDocument(doc);\n"
            "    try { /* work */ } finally { doc.recycle(); }\n"
            "    doc = next;\n"
            "  }\n"
            "} finally {\n"
            "  if (coll != null) coll.recycle(); // parent wrapper\n"
            "}"
        ),
        "DOM-023": (
            "// BAD — bean field / scope holds live handle:\n"
            "// private Document orderDoc;\n"
            "// sessionScope.put(\"order\", doc);\n"
            "\n"
            "// GOOD — persist identifiers only:\n"
            "sessionScope.put(\"orderUnid\", doc.getUniversalID());\n"
            "Document doc = null;\n"
            "try {\n"
            "  doc = database.getDocumentByUNID((String) sessionScope.get(\"orderUnid\"));\n"
            "  // work\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
        "DOM-024": (
            "// DO NOT recycle platform handles:\n"
            "// session.recycle();\n"
            "// database.recycle();             // XPages current NSF\n"
            "// getCurrentDatabase().recycle();\n"
            "// dominoNAF.recycle();\n"
            "\n"
            "// Only recycle databases you opened:\n"
            "Database other = null;\n"
            "try {\n"
            "  other = session.getDatabase(server, path);\n"
            "} finally {\n"
            "  if (other != null) other.recycle();\n"
            "}"
        ),
        "PERF-001": (
            "view.setAutoUpdate(false);\n"
            "try {\n"
            "  Document doc = view.getFirstDocument();\n"
            "  while (doc != null) {\n"
            "    Document next = view.getNextDocument(doc);\n"
            "    try { /* modify */ } finally { doc.recycle(); }\n"
            "    doc = next;\n"
            "  }\n"
            "} finally {\n"
            "  view.setAutoUpdate(true);\n"
            "}"
        ),
        "PERF-002": (
            "View view = db.getView(\"All\"); // hoist outside loop\n"
            "try {\n"
            "  for (...) {\n"
            "    // reuse view — do not getView again\n"
            "  }\n"
            "} finally {\n"
            "  if (view != null) view.recycle();\n"
            "}"
        ),
        "PERF-003": (
            "// Avoid save() every iteration — batch or checkpoint\n"
            "int n = 0;\n"
            "while (doc != null) {\n"
            "  // mutate\n"
            "  if (++n % 50 == 0) doc.save(true, false); // example throttle\n"
            "  Document next = coll.getNextDocument(doc);\n"
            "  doc.recycle();\n"
            "  doc = next;\n"
            "}"
        ),
        "PERF-004": (
            "// BAD — O(n²): getNthDocument re-walks from index 0 each time\n"
            "// for (int i = 1; i <= coll.getCount(); i++) {\n"
            "//   Document doc = coll.getNthDocument(i);\n"
            "// }\n"
            "\n"
            "// GOOD — O(n) sequential walk\n"
            "Document doc = coll.getFirstDocument();\n"
            "while (doc != null) {\n"
            "  Document next = coll.getNextDocument(doc);\n"
            "  try {\n"
            "    // ... process doc ...\n"
            "  } finally {\n"
            "    doc.recycle();\n"
            "  }\n"
            "  doc = next;\n"
            "}"
        ),
        "SEC-001": (
            "// Load secrets from vault/config — never hardcode; use HTTPS\n"
            "String password = Secrets.get(\"bossrest.password\");\n"
            "String url = \"https://secure.example.com/api\";"
        ),
        "SEC-002": (
            "String unid = request.getParameter(\"unid\");\n"
            "if (!accessControl.canOpen(unid, user)) {\n"
            "  throw new SecurityException(\"Unauthorized document access\");\n"
            "}\n"
            "Document doc = db.getDocumentByUNID(unid);"
        ),
        "DOM-BS-002": (
            "// Caller owns recycle after helper returns Document\n"
            "Document doc = null;\n"
            "try {\n"
            "  doc = fetchDoc(unid);\n"
            "  // ... work ...\n"
            "} finally {\n"
            "  if (doc != null) doc.recycle();\n"
            "}"
        ),
    }

    if ls:
        return templates_ls.get(rule_id) or templates_ls["DOM-002"]
    return templates_java.get(rule_id) or templates_java["DOM-002"]


_RE_NEXT_DOC = re.compile(
    r"(?i)\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*(?:get|Get)NextDocument\s*\(\s*([A-Za-z_]\w*)\s*\)"
)
_RE_FIRST_DOC = re.compile(
    r"(?i)\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*(?:get|Get)FirstDocument\s*\("
)
_RE_LS_NEXT_DOC = re.compile(
    r"(?i)\bSet\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*GetNextDocument\s*\(\s*([A-Za-z_]\w*)\s*\)"
)
_RE_LS_FIRST_DOC = re.compile(
    r"(?i)\bSet\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*GetFirstDocument\s*\("
)
def _unique_vars(*groups: list[str] | None, limit: int = 8) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        for name in group or []:
            key = (name or "").strip()
            if not key or key in seen:
                continue
            # Skip obvious non-handles
            if key.lower() in {"i", "j", "n", "x", "y", "tmp", "temp", "s", "str", "msg"}:
                continue
            seen.add(key)
            out.append(key)
            if len(out) >= limit:
                return out
    return out


def _detect_doc_walk(body: str, *, lotusscript: bool) -> tuple[str, str, str] | None:
    """Return (doc_var, collection_var, next_var) when a GetNextDocument walk is present."""
    text = body or ""
    if lotusscript:
        nxt = _RE_LS_NEXT_DOC.search(text)
        first = _RE_LS_FIRST_DOC.search(text)
    else:
        nxt = _RE_NEXT_DOC.search(text)
        first = _RE_FIRST_DOC.search(text)
    if nxt:
        next_var, coll, doc_var = nxt.group(1), nxt.group(2), nxt.group(3)
        return doc_var, coll, next_var
    if first:
        doc_var, coll = first.group(1), first.group(2)
        next_var = "nextDoc" if doc_var.lower() == "doc" else f"next{doc_var[:1].upper()}{doc_var[1:]}"
        return doc_var, coll, next_var
    return None


def _format_var_list(names: list[str]) -> str:
    if not names:
        return "allocated Domino handles"
    if len(names) == 1:
        return f"`{names[0]}`"
    if len(names) == 2:
        return f"`{names[0]}` and `{names[1]}`"
    return ", ".join(f"`{n}`" for n in names[:-1]) + f", and `{names[-1]}`"


def _java_like_recycle_block(vars_: list[str], *, indent: str = "  ") -> list[str]:
    lines: list[str] = []
    # Children before parents when names suggest nesting — reverse declaration order as heuristic
    for name in reversed(vars_):
        lines.append(f"{indent}if ({name} != null) {{ try {{ {name}.recycle(); }} catch (e) {{}} }}")
    return lines


def _ls_delete_block(vars_: list[str], *, indent: str = "    ") -> list[str]:
    lines: list[str] = []
    for name in reversed(vars_):
        lines.append(f"{indent}If Not {name} Is Nothing Then Delete {name}")
    return lines


def contextual_remediation(
    *,
    language: str | None,
    function_name: str = "",
    body: str = "",
    allocated_vars: list[str] | None = None,
    unclean_vars: list[str] | None = None,
    has_loop: bool | None = None,
    rule_id: str | None = None,
) -> str:
    """Build a To-Be sketch using this function's handle names / loop shape.

    Not a full rewrite — keeps business logic as a placeholder and shows where
    recycle/Delete should land. Falls back to the canned rule template when
    context is too thin to be useful.
    """
    from analytics.code_auditor.context import body_has_loop

    lang = normalize_language(language)
    ls = lang == "lotusscript"
    ssjs = lang in {"ssjs", "javascript", "xpages"}
    looped = body_has_loop(body) if has_loop is None else bool(has_loop)
    vars_ = _unique_vars(unclean_vars, allocated_vars)
    fname = (function_name or "").strip() or "thisRoutine"
    label = language_label(language)
    rid = rule_id or ("LS-DOM-001" if ls and looped else "DOM-002" if looped else "DOM-010")

    # Too little signal → canned template
    if not vars_ and not _detect_doc_walk(body, lotusscript=ls):
        return remediation_template(rid, language, has_loop=looped)

    header_java = (
        f"// Contextual sketch for {fname} ({label}) — adapt; not a full rewrite\n"
        f"// Release on every exit path: {', '.join(vars_) if vars_ else 'Domino handles'}\n"
    )
    header_ls = (
        f"' Contextual sketch for {fname} ({label}) — adapt; not a full rewrite\n"
        f"' Release on every exit path: {', '.join(vars_) if vars_ else 'Notes* handles'}\n"
    )

    walk = _detect_doc_walk(body, lotusscript=ls)
    if walk and looped:
        doc_var, coll, next_var = walk
        if ls:
            lines = [
                header_ls.rstrip(),
                f"Set {doc_var} = {coll}.GetFirstDocument()",
                f"Do While Not ({doc_var} Is Nothing)",
                f"    Set {next_var} = {coll}.GetNextDocument({doc_var})",
                f"    ' Keep existing per-document work from {fname}",
                f"    If Not {doc_var} Is Nothing Then Delete {doc_var}",
                f"    Set {doc_var} = {next_var}",
                "Loop",
            ]
            extras = [v for v in vars_ if v not in {doc_var, next_var, coll}]
            if extras:
                lines.append("' Also release other locals allocated in this routine:")
                lines.extend(_ls_delete_block(extras, indent=""))
            return "\n".join(lines)

        decl = "var " if ssjs else ""
        nullish = "null"
        lines = [
            header_java.rstrip(),
            f"{decl}{doc_var} = {coll}.getFirstDocument();",
            f"while ({doc_var} != {nullish}) {{",
            f"  {decl}{next_var} = {coll}.getNextDocument({doc_var});",
            "  try {",
            f"    // Keep existing per-document work from {fname}",
            "  } finally {",
            f"    if ({doc_var} != null) {{ try {{ {doc_var}.recycle(); }} catch (e) {{}} }}",
            "  }",
            f"  {doc_var} = {next_var};",
            "}",
        ]
        extras = [v for v in vars_ if v not in {doc_var, next_var, coll}]
        if extras:
            lines.append("// Also release other locals allocated in this routine:")
            lines.extend(_java_like_recycle_block(extras, indent=""))
        return "\n".join(lines)

    # Generic try/finally (or LS Delete) using this function's real handle names
    if ls:
        lines = [
            header_ls.rstrip(),
            f"' Keep existing work from {fname}, then release before Exit / Loop advance",
        ]
        if vars_:
            lines.extend(_ls_delete_block(vars_, indent=""))
        else:
            lines.append("If Not doc Is Nothing Then Delete doc")
        if looped:
            lines.append("' Inside loops: Delete the current handle before advancing to the next")
        return "\n".join(lines)

    # Prefer unclean vars for recycle list; fall back to allocated
    recycle_vars = vars_ or ["doc"]
    decl_lines: list[str] = []
    if ssjs:
        for v in recycle_vars:
            decl_lines.append(f"// {v} — already declared in {fname}; ensure it is null-initialized")
    else:
        for v in recycle_vars:
            decl_lines.append(f"// Ensure {v} is assigned null before try if not already")

    work_hint = (
        f"  // Keep existing logic from {fname} (see As-Is)\n"
        if not looped
        else (
            f"  // Keep existing loop body from {fname} (see As-Is)\n"
            "  // Capture next handle first if walking documents/collections\n"
        )
    )
    lines = [header_java.rstrip()]
    lines.extend(decl_lines)
    lines.append("try {")
    lines.append(work_hint.rstrip())
    lines.append("} finally {")
    lines.extend(_java_like_recycle_block(recycle_vars))
    lines.append("}")
    return "\n".join(lines)


def contextual_remediation_guide(
    *,
    language: str | None,
    function_name: str = "",
    allocated_vars: list[str] | None = None,
    unclean_vars: list[str] | None = None,
    has_loop: bool = False,
    rule_id: str | None = None,
    fallback: str = "",
) -> str:
    """Short fix guidance that names this function and its handle variables."""
    lang = normalize_language(language)
    ls = lang == "lotusscript"
    vars_ = _unique_vars(unclean_vars, allocated_vars, limit=6)
    fname = (function_name or "").strip()
    var_text = _format_var_list(vars_)
    cleanup = "`Delete`" if ls else "`.recycle()`"
    finally_bit = (
        "before Exit / Loop advance"
        if ls
        else "in a `finally` (or equivalent) before the loop advances / the method returns"
    )

    if fname and vars_:
        if has_loop:
            return (
                f"In `{fname}`, release {var_text} with {cleanup} {finally_bit}. "
                "If this is a document walk, capture the next handle first, then release the current one."
            )
        return (
            f"In `{fname}`, wrap use of {var_text} so every exit path calls {cleanup} "
            f"{finally_bit}."
        )
    if fname:
        if has_loop:
            return (
                f"In `{fname}`, release each Domino handle with {cleanup} before advancing the loop "
                f"({finally_bit})."
            )
        return f"In `{fname}`, ensure every allocated Domino handle is released with {cleanup} on all paths."
    if fallback:
        return fallback
    return remediation_guide(rule_id or "DOM-010", language)


# Back-compat alias used by older imports
def default_try_finally_remediation(language: str = "java") -> str:
    return remediation_template("DOM-010", language)


def problem_breakdown(rule_id: str, language: str | None = None) -> str:
    base = PROBLEM_BREAKDOWNS.get(rule_id) or (
        "This pattern risks leaking or mismanaging Domino C-API handles."
    )
    return f"{base} Detected language: {language_label(language)}."


def remediation_guide(rule_id: str, language: str | None = None) -> str:
    lang = normalize_language(language)
    key = "lotusscript" if lang == "lotusscript" else "java"
    guides = REMEDIATION_GUIDES.get(rule_id) or {}
    if key in guides:
        return guides[key]
    if lang == "lotusscript":
        return (
            "Release Notes* handles with `Delete` (or `Call obj.Recycle()` where supported) "
            "on every exit path before re-assigning the variable."
        )
    return (
        "Wrap Domino object lifetimes in `try`/`finally` and call `.recycle()` on every "
        "allocated handle before the method returns."
    )


def extract_line_window(
    body: str,
    *,
    focus_line: int,
    base_line: int = 1,
    radius: int = 10,
    before: int | None = None,
    after: int | None = None,
    expand_cleanup_context: bool = True,
    max_span: int = 120,
) -> tuple[str, int, int, int, list[dict[str, Any]]]:
    """
    Return (snippet_text, line_start, line_end, highlight_offset, structured_lines).

    Structured lines are friendly for UI highlighting:
      { "line": 3372, "text": "...", "highlight": true }

    Uses a larger window *after* the hit line by default so callers can see
    ``finally`` / ``.recycle()`` that may clear the finding. When
    ``expand_cleanup_context`` is set, the window grows downward (within
    ``max_span``) to include nearby cleanup markers.
    """
    lines = body.splitlines() or [""]
    rel = max(0, min(len(lines) - 1, focus_line - base_line))
    before_n = radius if before is None else max(0, before)
    after_n = radius if after is None else max(0, after)
    # Prefer more context after the allocation so finally/recycle is visible.
    if after is None and before is None:
        before_n = max(before_n, 12)
        after_n = max(after_n, 35)

    start_idx = max(0, rel - before_n)
    end_idx = min(len(lines), rel + after_n + 1)

    if expand_cleanup_context:
        cleanup_re = re.compile(
            r"\bfinally\b|\.recycle\s*\(|\brecycle\s*\(|\bDelete\b",
            re.I,
        )
        # Include every cleanup marker near the focus (not only the last one below).
        search_start = max(0, rel - max_span)
        search_end = min(len(lines), rel + max_span + 1)
        for i in range(search_start, search_end):
            if cleanup_re.search(lines[i] or ""):
                start_idx = min(start_idx, i)
                end_idx = max(end_idx, min(len(lines), i + 1))
        # Also peek a bit upward for an opening try {
        first_try = -1
        for i in range(rel, search_start - 1, -1):
            if re.search(r"\btry\s*\{", lines[i] or "", re.I):
                first_try = i
                break
        if first_try >= 0:
            start_idx = min(start_idx, first_try)

        # Cap total span
        if end_idx - start_idx > max_span:
            # Keep focus in view; prefer keeping more below.
            start_idx = max(0, min(rel - before_n, end_idx - max_span))
            if end_idx - start_idx > max_span:
                end_idx = start_idx + max_span

    window = lines[start_idx:end_idx]

    numbered: list[str] = []
    structured: list[dict[str, Any]] = []
    for i, text in enumerate(window):
        abs_line = base_line + start_idx + i
        is_hit = (start_idx + i) == rel
        marker = "▶" if is_hit else " "
        numbered.append(f"{abs_line:>6}{marker}| {text}")
        structured.append({"line": abs_line, "text": text, "highlight": is_hit})

    structured = annotate_cleanup_highlights(structured)
    # Keep focus marker for numbered text even when recycle lines are also flagged
    snippet = "\n".join(numbered)
    line_start = base_line + start_idx
    line_end = base_line + end_idx - 1
    highlight = rel - start_idx
    return snippet, line_start, line_end, highlight, structured


_RE_CLEANUP_LINE = re.compile(
    r"(?i)(?:\.\s*recycle\s*\(|\brecycle\s*\(|\bDelete\s+[A-Za-z_]\w*|\bCall\s+\w+\.Recycle\s*\()",
)


def annotate_cleanup_highlights(
    structured: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Flag every .recycle() / Delete line so misplaced cleanups stay visible.

    Problem hit lines keep ``kind=problem``; cleanup-only lines use ``kind=cleanup``.
    Both set ``highlight=True`` for Word / UI consumers.
    """
    if not structured:
        return []
    out: list[dict[str, Any]] = []
    for row in structured:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        text = str(copy.get("text") or "")
        is_cleanup = bool(_RE_CLEANUP_LINE.search(text))
        is_problem = bool(copy.get("highlight")) and copy.get("kind") != "cleanup"
        if is_problem and is_cleanup:
            copy["highlight"] = True
            copy["kind"] = "problem"
        elif is_problem:
            copy["highlight"] = True
            copy["kind"] = copy.get("kind") or "problem"
        elif is_cleanup:
            copy["highlight"] = True
            copy["kind"] = "cleanup"
        out.append(copy)
    return out


def attach_snippet_fields(
    *,
    unit: CodeUnit,
    focus_line: int,
    evidence: str,
    remediation: str,
    handle_lifecycle_warning: str,
    rule_id: str | None = None,
    has_loop: bool | None = None,
    function_name: str | None = None,
) -> dict[str, Any]:
    from analytics.code_auditor.api_catalog import analyze_handle_cleanup
    from analytics.code_auditor.context import body_has_loop

    snippet, line_start, line_end, _hl, structured = extract_line_window(
        unit.body,
        focus_line=focus_line,
        base_line=unit.start_line,
        before=15,
        after=45,
        expand_cleanup_context=True,
        max_span=100,
    )
    as_is = snippet if snippet.strip() else evidence
    looped = body_has_loop(unit.body) if has_loop is None else bool(has_loop)
    analysis = analyze_handle_cleanup(unit.body, unit.language)
    fname = (function_name or unit.element_name or "").strip()

    rid = rule_id or "DOM-010"
    # Prefer contextual sketch from this unit's handles; fall back to canned rule template
    to_be = contextual_remediation(
        language=unit.language,
        function_name=fname,
        body=unit.body,
        allocated_vars=analysis.allocated_vars,
        unclean_vars=analysis.unclean_vars,
        has_loop=looped,
        rule_id=rid,
    )
    if not to_be.strip():
        rem = (remediation or "").strip()
        if rule_id:
            to_be = remediation_template(rule_id, unit.language, has_loop=looped)
        elif normalize_language(unit.language) == "lotusscript" and (
            "try {" in rem or ".recycle()" in rem or rem.startswith("//")
        ):
            to_be = remediation_template("DOM-002", unit.language, has_loop=looped)
        else:
            to_be = rem or remediation_template("DOM-010", unit.language, has_loop=looped)

    guide = contextual_remediation_guide(
        language=unit.language,
        function_name=fname,
        allocated_vars=analysis.allocated_vars,
        unclean_vars=analysis.unclean_vars,
        has_loop=looped,
        rule_id=rid,
        fallback=remediation_guide(rid, unit.language),
    )
    return {
        "code_snippet_as_is": as_is,
        "code_snippet_to_be": to_be,
        "code_snippet_lines": structured,
        "line_number_start": line_start,
        "line_number_end": line_end,
        "highlight_line": focus_line,
        "handle_lifecycle_warning": handle_lifecycle_warning,
        "problem_breakdown": problem_breakdown(rid, unit.language),
        "remediation_guide": guide,
        "language_label": language_label(unit.language),
    }
