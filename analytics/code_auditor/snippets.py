"""Snippet context helpers and language-aware remediation templates."""

from __future__ import annotations

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
        "Code using the OpenNTF Domino API still calls `.recycle()` manually. ODA owns the "
        "lifecycle — manual recycle can destroy shared handles and stall threads."
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
}


def normalize_language(language: str | None) -> str:
    lang = (language or "").strip().lower()
    if lang in {"lotusscript", "ls", "lss", "notes"}:
        return "lotusscript"
    if lang in {"javascript", "js", "ssjs", "jscript", "xpages", "jss"}:
        return "javascript"
    if lang in {"java"}:
        return "java"
    return lang or "java"


def language_label(language: str | None) -> str:
    lang = normalize_language(language)
    return {
        "lotusscript": "LotusScript",
        "java": "Java",
        "javascript": "SSJS / JavaScript",
    }.get(lang, language or "Unknown")


def is_java_like(language: str | None) -> bool:
    return normalize_language(language) in {"java", "javascript"}


def remediation_template(rule_id: str, language: str | None) -> str:
    """Return a language-appropriate TO-BE code template for the rule."""
    lang = normalize_language(language)
    ls = lang == "lotusscript"

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
            "// Remove manual recycle when using org.openntf.domino.*\n"
            "Document doc = db.getDocumentByUNID(unid);\n"
            "String subject = doc.getItemValueString(\"Subject\");\n"
            "// ODA disposes handles at end of request — do not call doc.recycle()"
        ),
        "DOM-005": (
            "org.openntf.domino.Document doc =\n"
            "    Factory.fromLotus(lotusDoc, Document.class, database);"
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
    }

    if ls:
        return templates_ls.get(rule_id) or templates_ls["DOM-002"]
    return templates_java.get(rule_id) or templates_java["DOM-002"]


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
) -> tuple[str, int, int, int, list[dict[str, Any]]]:
    """
    Return (snippet_text, line_start, line_end, highlight_offset, structured_lines).

    Structured lines are friendly for UI highlighting:
      { "line": 3372, "text": "...", "highlight": true }
    """
    lines = body.splitlines() or [""]
    rel = max(0, min(len(lines) - 1, focus_line - base_line))
    start_idx = max(0, rel - radius)
    end_idx = min(len(lines), rel + radius + 1)
    window = lines[start_idx:end_idx]

    numbered: list[str] = []
    structured: list[dict[str, Any]] = []
    for i, text in enumerate(window):
        abs_line = base_line + start_idx + i
        is_hit = (start_idx + i) == rel
        marker = "▶" if is_hit else " "
        numbered.append(f"{abs_line:>6}{marker}| {text}")
        structured.append({"line": abs_line, "text": text, "highlight": is_hit})

    snippet = "\n".join(numbered)
    line_start = base_line + start_idx
    line_end = base_line + end_idx - 1
    highlight = rel - start_idx
    return snippet, line_start, line_end, highlight, structured


def attach_snippet_fields(
    *,
    unit: CodeUnit,
    focus_line: int,
    evidence: str,
    remediation: str,
    handle_lifecycle_warning: str,
    rule_id: str | None = None,
) -> dict[str, Any]:
    snippet, line_start, line_end, _hl, structured = extract_line_window(
        unit.body,
        focus_line=focus_line,
        base_line=unit.start_line,
        radius=10,
    )
    as_is = snippet if snippet.strip() else evidence

    # Always prefer language-aware template when we know the rule
    if rule_id:
        to_be = remediation_template(rule_id, unit.language)
    else:
        # If caller passed a Java template but unit is LotusScript, replace it
        rem = (remediation or "").strip()
        if normalize_language(unit.language) == "lotusscript" and (
            "try {" in rem or ".recycle()" in rem or rem.startswith("//")
        ):
            to_be = remediation_template("DOM-002", unit.language)
        else:
            to_be = rem or remediation_template("DOM-010", unit.language)

    rid = rule_id or "DOM-010"
    return {
        "code_snippet_as_is": as_is,
        "code_snippet_to_be": to_be,
        "code_snippet_lines": structured,
        "line_number_start": line_start,
        "line_number_end": line_end,
        "highlight_line": focus_line,
        "handle_lifecycle_warning": handle_lifecycle_warning,
        "problem_breakdown": problem_breakdown(rid, unit.language),
        "remediation_guide": remediation_guide(rid, unit.language),
        "language_label": language_label(unit.language),
    }
