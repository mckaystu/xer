"""LotusScript-native Domino handle lifecycle detectors (LS-DOM-001..004).

These rules evaluate LotusScript using ``Delete`` / variable-scope semantics
rather than Java ``.recycle()`` / try-finally mechanics.
"""

from __future__ import annotations

import re
from typing import Callable

from analytics.code_auditor.models import CodeUnit, Finding
from analytics.code_auditor.snippets import remediation_template

# Imported from rules to reuse finding factory — set by rules module to avoid cycle
_finding_fn: Callable[..., Finding] | None = None
_line_of_fn: Callable[[str, int, int], int] | None = None
_snippet_fn: Callable[..., str] | None = None


def bind_helpers(
    *,
    finding: Callable[..., Finding],
    line_of: Callable[[str, int, int], int],
    snippet: Callable[..., str],
) -> None:
    global _finding_fn, _line_of_fn, _snippet_fn
    _finding_fn = finding
    _line_of_fn = line_of
    _snippet_fn = snippet


def _is_lotusscript(unit: CodeUnit) -> bool:
    lang = (unit.language or "").lower()
    return "lotus" in lang or lang in {"ls", "lss", "notes"}


def _finding(*args, **kwargs) -> Finding:
    assert _finding_fn is not None
    return _finding_fn(*args, **kwargs)


def _line_of(body: str, index: int, start_line: int) -> int:
    assert _line_of_fn is not None
    return _line_of_fn(body, index, start_line)


def _snippet(body: str, index: int, width: int = 200) -> str:
    assert _snippet_fn is not None
    return _snippet_fn(body, index, width)


RE_LS_LOOP_START = re.compile(
    r"(?im)\b(?:Do\s+While|Do\s+Until|Forall|(?<![\w.])While)\b"
)
RE_LS_LOOP_END = re.compile(r"(?im)\b(?:Loop|End\s+Forall|Wend)\b")

# Set doc = view.GetNextDocument(doc)  /  Set entry = nav.GetNextEntry(entry)
RE_LS_GET_NEXT = re.compile(
    r"(?i)Set\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<coll>\w+)\.(?P<meth>GetNextDocument|GetNextEntry)\s*\(\s*(?P=var)\s*\)"
)

# Secondary lookups / creates inside loops
RE_LS_LOOKUP = re.compile(
    r"(?i)Set\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"\w+\.(?P<meth>GetDocumentByUNID|GetDocumentByKey|CreateDocument)\s*\("
)

# Public module-level Notes handles
RE_LS_PUBLIC_NOTES = re.compile(
    r"(?im)^[ \t]*Public\s+(?P<var>[A-Za-z_]\w*)\s+As\s+"
    r"Notes(?P<type>Document|Database|View)\b"
)

# Set doc = Nothing without Delete
RE_LS_SET_NOTHING = re.compile(
    r"(?i)Set\s+(?P<var>[A-Za-z_]\w*)\s*=\s*Nothing\b"
)

RE_LS_DELETE_VAR = re.compile(r"(?i)\bDelete\s+(?P<var>[A-Za-z_]\w*)\b")
RE_LS_RECYCLE_VAR = re.compile(
    r"(?i)\b(?:Call\s+)?(?P<var>[A-Za-z_]\w*)\.Recycle\s*\("
)


def _has_ls_cleanup(region: str, var: str) -> bool:
    if re.search(rf"(?i)\bDelete\s+{re.escape(var)}\b", region):
        return True
    if re.search(rf"(?i)\b(?:Call\s+)?{re.escape(var)}\.Recycle\s*\(", region):
        return True
    return False


def _loop_region_containing(body: str, pos: int) -> tuple[int, int, str] | None:
    """Return (start, end, text) for the innermost LS loop containing ``pos``."""
    starts = [m for m in RE_LS_LOOP_START.finditer(body) if m.start() <= pos]
    if not starts:
        return None
    start = starts[-1].start()
    end_m = RE_LS_LOOP_END.search(body, pos)
    if not end_m:
        # Unclosed loop — take through end of body
        end = len(body)
    else:
        end = end_m.end()
    if end <= start:
        return None
    return start, end, body[start:end]


def detect_ls_dom001(unit: CodeUnit) -> list[Finding]:
    """Loop iteration with GetNext* but no Delete before pointer advances."""
    if not _is_lotusscript(unit):
        return []
    findings: list[Finding] = []
    seen_lines: set[int] = set()
    for match in RE_LS_GET_NEXT.finditer(unit.body):
        var = match.group("var")
        region = _loop_region_containing(unit.body, match.start())
        if not region:
            continue
        _start, _end, loop_text = region
        if _has_ls_cleanup(loop_text, var):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        if line in seen_lines:
            continue
        seen_lines.add(line)
        meth = match.group("meth")
        findings.append(
            _finding(
                "LS-DOM-001",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start(), 260),
                confidence=95,
                impact=(
                    f"LotusScript loop advances with `{meth}({var})` without `Delete {var}` "
                    f"(or `{var}.Recycle`) before the pointer resets. Each iteration leaves a "
                    "native C-API handle pinned until the Sub/agent exits — large collections "
                    "exhaust the Notes handle table."
                ),
                remediation=remediation_template("LS-DOM-001", unit.language),
                action=(
                    f"Fetch next into a temp, process `{var}`, `Delete {var}`, then advance "
                    f"`Set {var} = next…`."
                ),
                handle_lifecycle_warning=(
                    f"Line {line}: `{var}` advanced via {meth} inside a loop without Delete."
                ),
            )
        )
    return findings


def detect_ls_dom002(unit: CodeUnit) -> list[Finding]:
    """Secondary GetDocumentByUNID/Key or CreateDocument inside a loop without Delete."""
    if not _is_lotusscript(unit):
        return []
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for match in RE_LS_LOOKUP.finditer(unit.body):
        var = match.group("var")
        region = _loop_region_containing(unit.body, match.start())
        if not region:
            continue
        _start, _end, loop_text = region
        if _has_ls_cleanup(loop_text, var):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        key = (line, var)
        if key in seen:
            continue
        seen.add(key)
        meth = match.group("meth")
        findings.append(
            _finding(
                "LS-DOM-002",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start(), 240),
                confidence=90,
                impact=(
                    f"In-loop `{meth}` assigns `{var}` without `Delete {var}` before the next "
                    "iteration. Secondary lookup/create documents accumulate native handles "
                    "across the loop."
                ),
                remediation=remediation_template("LS-DOM-002", unit.language),
                action=f"After using `{var}` inside the loop, call `Delete {var}` before the next iteration.",
                handle_lifecycle_warning=(
                    f"Line {line}: in-loop `{var}` from {meth} is never Deleted."
                ),
            )
        )
    return findings


def detect_ls_dom003(unit: CodeUnit) -> list[Finding]:
    """Public NotesDocument / NotesDatabase / NotesView at module (Declarations) scope."""
    if not _is_lotusscript(unit):
        return []
    findings: list[Finding] = []
    for match in RE_LS_PUBLIC_NOTES.finditer(unit.body):
        var = match.group("var")
        notes_type = match.group("type")
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "LS-DOM-003",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=98,
                impact=(
                    f"`Public {var} As Notes{notes_type}` pins a C-API handle in server RAM across "
                    "agent/library executions. Module-level Public Notes objects survive Sub exit "
                    "and accumulate under concurrent HTTP/agent load."
                ),
                remediation=remediation_template("LS-DOM-003", unit.language),
                action=(
                    f"Move `Notes{notes_type}` `{var}` to Dim inside the Sub/Function; "
                    f"`Delete {var}` before Exit. Prefer UniversalIDs for cross-call state."
                ),
                handle_lifecycle_warning=(
                    f"Line {line}: Public Notes{notes_type} `{var}` survives routine exit."
                ),
            )
        )
    return findings


def detect_ls_dom004(unit: CodeUnit) -> list[Finding]:
    """Set var = Nothing without a preceding Delete var."""
    if not _is_lotusscript(unit):
        return []
    # Only meaningful when the unit deals with Notes* handles
    if not re.search(r"\bNotes(?:Document|Database|View|ViewEntry|DateTime|Session)\b", unit.body, re.I):
        return []

    findings: list[Finding] = []
    # Track Deletes/Recycles as we scan so "preceding" is chronological
    events: list[tuple[int, str, str]] = []  # pos, kind, var
    for m in RE_LS_DELETE_VAR.finditer(unit.body):
        events.append((m.start(), "delete", m.group("var")))
    for m in RE_LS_RECYCLE_VAR.finditer(unit.body):
        events.append((m.start(), "recycle", m.group("var")))
    for m in RE_LS_SET_NOTHING.finditer(unit.body):
        events.append((m.start(), "nothing", m.group("var")))
    events.sort(key=lambda t: t[0])

    cleaned: set[str] = set()
    for pos, kind, var in events:
        if kind in {"delete", "recycle"}:
            cleaned.add(var.lower())
            continue
        # nothing
        if var.lower() in cleaned:
            continue
        # Ignore clearing non-Notes-looking scalars when no Dim As Notes* for this var
        dim_notes = re.search(
            rf"(?i)\b(?:Dim|Private|Public|Static)\s+{re.escape(var)}\s+As\s+Notes\w+",
            unit.body,
        )
        name_hint = bool(re.search(r"(?i)(?:doc|view|db|database|entry|nav|coll)", var))
        if not dim_notes and not name_hint:
            continue
        line = _line_of(unit.body, pos, unit.start_line)
        findings.append(
            _finding(
                "LS-DOM-004",
                unit,
                line=line,
                evidence=_snippet(unit.body, pos),
                confidence=85,
                impact=(
                    f"`Set {var} = Nothing` clears the LotusScript pointer but does not reliably "
                    "release the native C-API handle. Prefer `Delete {var}` first; native memory "
                    "may otherwise linger until the calling routine terminates."
                ),
                remediation=remediation_template("LS-DOM-004", unit.language),
                action=f"Call `Delete {var}` before (or instead of) `Set {var} = Nothing`.",
                handle_lifecycle_warning=(
                    f"Line {line}: `{var}` set to Nothing without a preceding Delete."
                ),
            )
        )
    return findings


LS_DETECTORS = [
    detect_ls_dom001,
    detect_ls_dom002,
    detect_ls_dom003,
    detect_ls_dom004,
]
