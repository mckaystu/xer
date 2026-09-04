"""Snippet context helpers for Domino code-audit findings."""

from __future__ import annotations

from analytics.code_auditor.models import CodeUnit


def extract_line_window(
    body: str,
    *,
    focus_line: int,
    base_line: int = 1,
    radius: int = 10,
) -> tuple[str, int, int, int]:
    """
    Return (snippet, line_number_start, line_number_end, highlight_offset).

    ``focus_line`` and returned bounds are 1-based absolute file/block lines.
    ``highlight_offset`` is 0-based index within the snippet lines for the focus line.
    """
    lines = body.splitlines() or [""]
    # Convert absolute focus to 0-based index within body
    rel = max(0, min(len(lines) - 1, focus_line - base_line))
    start_idx = max(0, rel - radius)
    end_idx = min(len(lines), rel + radius + 1)
    window = lines[start_idx:end_idx]
    # Prefix with absolute line numbers for readability
    numbered: list[str] = []
    for i, text in enumerate(window):
        abs_line = base_line + start_idx + i
        marker = "▶" if (start_idx + i) == rel else " "
        numbered.append(f"{abs_line:>6}{marker}| {text}")
    snippet = "\n".join(numbered)
    line_start = base_line + start_idx
    line_end = base_line + end_idx - 1
    highlight = rel - start_idx
    return snippet, line_start, line_end, highlight


def default_try_finally_remediation(language: str = "java") -> str:
    if language == "lotusscript":
        return (
            "' LotusScript: keep one live handle; recycle before advancing\n"
            "Dim doc As NotesDocument\n"
            "Dim nextDoc As NotesDocument\n"
            "Set doc = collection.GetFirstDocument()\n"
            "Do Until doc Is Nothing\n"
            "    Set nextDoc = collection.GetNextDocument(doc)\n"
            "    ' --- process doc ---\n"
            "    Call doc.Remove(True)  ' or just finish using it\n"
            "    Delete doc            ' releases the handle\n"
            "    Set doc = nextDoc\n"
            "Loop"
        )
    return (
        "// Safe try-finally scaffolding for Domino C-API handles\n"
        "Database db = null;\n"
        "View view = null;\n"
        "Document doc = null;\n"
        "try {\n"
        "  db = session.getDatabase(server, path);\n"
        "  view = db.getView(\"Lookup\");\n"
        "  doc = view.getFirstDocument();\n"
        "  while (doc != null) {\n"
        "    Document next = view.getNextDocument(doc);\n"
        "    try {\n"
        "      // process doc\n"
        "    } finally {\n"
        "      doc.recycle();  // always release child before advancing\n"
        "    }\n"
        "    doc = next;\n"
        "  }\n"
        "} finally {\n"
        "  if (view != null) view.recycle();\n"
        "  if (db != null) db.recycle();\n"
        "  // never recycle parent while a live child handle remains\n"
        "}"
    )


def attach_snippet_fields(
    *,
    unit: CodeUnit,
    focus_line: int,
    evidence: str,
    remediation: str,
    handle_lifecycle_warning: str,
) -> dict:
    snippet, line_start, line_end, _hl = extract_line_window(
        unit.body,
        focus_line=focus_line,
        base_line=unit.start_line,
        radius=10,
    )
    # Prefer windowed context; fall back to short evidence if body empty
    as_is = snippet if snippet.strip() else evidence
    to_be = remediation.strip() or default_try_finally_remediation(unit.language)
    return {
        "code_snippet_as_is": as_is,
        "code_snippet_to_be": to_be,
        "line_number_start": line_start,
        "line_number_end": line_end,
        "handle_lifecycle_warning": handle_lifecycle_warning,
    }
