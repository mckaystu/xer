"""Function & Recycle Inventory Engine.

Scans extracted Java / SSJS / XPages / LotusScript blocks, inventories every
declared subroutine/method, and classifies recycle coverage for Domino handles.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Literal

from analytics.code_auditor.extractor import (
    apply_prefilter,
    extract_units_from_graph,
    extract_units_from_path,
)
from analytics.code_auditor.models import CodeUnit

FunctionStatus = Literal["SAFE_NO_HANDLES", "PROTECTED", "UNPROTECTED_ALLOCATION"]

# Domino handle allocation heuristics (Java / SSJS — word matches)
ALLOCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bNotesDocument\b", re.I),
    re.compile(r"\bNotesView\b", re.I),
    re.compile(r"\bNotesDatabase\b", re.I),
    re.compile(r"\bNotesViewEntry\b", re.I),
    re.compile(r"\bNotesViewNavigator\b", re.I),
    re.compile(r"\bNotesViewNav\b", re.I),
    re.compile(r"\bNotesDateTime\b", re.I),
    re.compile(r"\bDocument\b"),
    re.compile(r"\bView\b"),
    re.compile(r"\bDatabase\b"),
    re.compile(r"\bcreateDateTime\b", re.I),
    re.compile(r"\bcreateViewNav\b", re.I),
    re.compile(r"\bGetDocumentByUNID\b", re.I),
    re.compile(r"\bGetFirstDocument\b", re.I),
    re.compile(r"\bGetNextDocument\b", re.I),
    re.compile(r"\bGetEntryByKey\b", re.I),
    re.compile(r"\bgetDocumentByUNID\b"),
    re.compile(r"\bgetFirstDocument\b"),
    re.compile(r"\bgetNextDocument\b"),
    re.compile(r"\bgetEntryByKey\b"),
    re.compile(r"\bgetAllDocumentsByKey\b", re.I),
    re.compile(r"\bgetView\b", re.I),
    re.compile(r"\bgetDatabase\b", re.I),
]

# LotusScript-specific allocation (Delete / Notes* semantics — no bare Document/View)
LS_ALLOCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bNotesDocument\b", re.I),
    re.compile(r"\bNotesView\b", re.I),
    re.compile(r"\bNotesDatabase\b", re.I),
    re.compile(r"\bNotesViewEntry\b", re.I),
    re.compile(r"\bNotesViewNav(?:igator)?\b", re.I),
    re.compile(r"\bGetDocumentByUNID\b", re.I),
    re.compile(r"\bGetFirstDocument\b", re.I),
    re.compile(r"\bGetNextDocument\b", re.I),
    re.compile(r"\bGetEntryByKey\b", re.I),
    re.compile(r"\bGetNextEntry\b", re.I),
    re.compile(r"\bCreateDocument\b", re.I),
]

# LotusScript: Sub / Function (skip Declare …)
_LS_DECL = re.compile(
    r"(?im)^[ \t]*(?:Public |Private |Friend )?"
    r"(Sub|Function)\s+([A-Za-z_][\w.]*)"
    r"[^\n]*\n"
    r"(.*?)"
    r"^[ \t]*End\s+(?:Sub|Function)\b",
    re.S,
)
_LS_DECLARE = re.compile(r"(?im)^\s*Declare\s+(?:Function|Sub)\b")

# JavaScript / SSJS: function name(...) { ... }
_JS_FUNCTION = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?:export\s+)?(?:async\s+)?function\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*\{",
)

# Java / typed methods: modifiers returnType name(...) {
_JAVA_METHOD = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<mods>(?:public|private|protected|static|final|synchronized|native|abstract|\s)+)"
    r"(?P<ret>[\w.<>,\[\]?][\w.<>,\[\]?\s]*)\s+"
    r"(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^;{]*)\)\s*(?:throws\s+[^{]+)?\{",
)

# Skip Java-ish constructs that aren't Domino methods we care about
_JAVA_SKIP_NAMES = {"if", "for", "while", "switch", "catch", "synchronized", "new"}
_JAVA_SKIP_RET = {"if", "for", "while", "switch", "catch", "return", "else", "new", "throw"}


@dataclass
class FunctionRecord:
    id: str
    design_element: str
    function_name: str
    language: str
    allocates_handles: bool
    recycle_call_count: int
    status: FunctionStatus
    loc: int
    source_file: str = ""
    start_line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _language_label(lang: str) -> str:
    low = (lang or "").lower()
    if "lotus" in low:
        return "LotusScript"
    if low in {"ssjs", "jscript"} or "javascript" in low or low == "js":
        return "SSJS / JavaScript"
    if "xpage" in low or low == "xsp":
        return "XPages"
    if "java" in low:
        return "Java"
    return lang or "unknown"


def _design_element(unit: CodeUnit) -> str:
    return f"{unit.element_type}:{unit.element_name}"


def _is_lotusscript_lang(lang: str) -> bool:
    low = (lang or "").lower()
    return "lotus" in low or low in {"ls", "lss", "notes"}


def _count_allocates(body: str, language: str = "") -> bool:
    patterns = LS_ALLOCATION_PATTERNS if _is_lotusscript_lang(language) else ALLOCATION_PATTERNS
    return any(p.search(body) for p in patterns)


def _count_cleanup(body: str, language: str = "") -> int:
    """Count explicit cleanup statements without double-counting Call x.recycle()."""
    if _is_lotusscript_lang(language):
        # LotusScript: Delete <var> and Call <var>.Recycle() / <var>.Recycle()
        patterns = [
            re.compile(r"\bCall\s+\w+\.Recycle\s*\([^)]*\)", re.I),
            re.compile(r"\b\w+\.Recycle\s*\([^)]*\)", re.I),
            re.compile(r"\bDelete\s+\w+", re.I),
        ]
    else:
        patterns = [
            re.compile(r"\bCall\s+\w+\.recycle\s*\([^)]*\)", re.I),
            re.compile(r"\.recycle\s*\([^)]*\)", re.I),
            re.compile(r"\bDelete\s+\w+", re.I),
            re.compile(r"\brecycleLotuses\s*\([^)]*\)", re.I),
        ]
    occupied: list[tuple[int, int]] = []
    total = 0
    for pattern in patterns:
        for m in pattern.finditer(body):
            start, end = m.start(), m.end()
            if any(not (end <= a or start >= b) for a, b in occupied):
                continue
            occupied.append((start, end))
            total += 1
    return total


def _classify(allocates: bool, recycle_count: int) -> FunctionStatus:
    if not allocates:
        return "SAFE_NO_HANDLES"
    if recycle_count >= 1:
        return "PROTECTED"
    return "UNPROTECTED_ALLOCATION"


def _loc(body: str) -> int:
    text = body.strip("\n")
    if not text.strip():
        return 0
    return text.count("\n") + 1


def _match_brace_block(text: str, open_brace_index: int) -> str | None:
    """Return body inside `{...}` starting at open_brace_index, or None if unbalanced."""
    if open_brace_index < 0 or open_brace_index >= len(text) or text[open_brace_index] != "{":
        return None
    depth = 0
    in_str: str | None = None
    escape = False
    for i in range(open_brace_index, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in {'"', "'", "`"}:
            in_str = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_index + 1 : i]
    return None


def _extract_lotusscript(unit: CodeUnit) -> list[tuple[str, str, int]]:
    """Return list of (name, body, start_line) for LotusScript Subs/Functions."""
    body = unit.body
    results: list[tuple[str, str, int]] = []

    for m in _LS_DECL.finditer(body):
        line_start = body.rfind("\n", 0, m.start()) + 1
        nl = body.find("\n", m.start())
        decl_line = body[line_start : nl if nl >= 0 else len(body)]
        if _LS_DECLARE.search(decl_line) or decl_line.lstrip().lower().startswith("declare "):
            continue
        name = m.group(2)
        fn_body = m.group(3) or ""
        start_line = unit.start_line + body.count("\n", 0, m.start())
        results.append((name, fn_body, start_line))

    # Header without End Sub (truncated DXL slice)
    if not results and re.search(r"(?im)^\s*(?:Public |Private )?(?:Sub|Function)\s+", body):
        first = re.search(
            r"(?im)^\s*(?:Public |Private |Friend )?(?:Sub|Function)\s+([A-Za-z_][\w.]*)",
            body,
        )
        if first and not _LS_DECLARE.search(body[max(0, first.start() - 20) : first.end()]):
            results.append((first.group(1), body[first.end() :], unit.start_line))
    elif not results and unit.event:
        # Event-scoped block (Initialize, QueryOpen, …) without nested Subs
        results.append((unit.event, body, unit.start_line))

    return results


def _extract_brace_functions(unit: CodeUnit) -> list[tuple[str, str, int]]:
    """Extract JS `function` and Java-style method declarations with brace bodies."""
    body = unit.body
    results: list[tuple[str, str, int]] = []
    occupied: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(not (end <= a or start >= b) for a, b in occupied)

    for m in _JS_FUNCTION.finditer(body):
        brace_at = m.end() - 1
        inner = _match_brace_block(body, brace_at)
        if inner is None:
            continue
        end = brace_at + 1 + len(inner) + 1
        if overlaps(m.start(), end):
            continue
        occupied.append((m.start(), end))
        start_line = unit.start_line + body.count("\n", 0, m.start())
        results.append((m.group("name"), inner, start_line))

    lang = (unit.language or "").lower()
    if "java" in lang or "xpage" in lang or lang in {"source", "script"}:
        for m in _JAVA_METHOD.finditer(body):
            name = m.group("name")
            ret = (m.group("ret") or "").strip().split()[-1] if m.group("ret") else ""
            if name.lower() in _JAVA_SKIP_NAMES:
                continue
            if ret.lower() in _JAVA_SKIP_RET:
                continue
            # Avoid matching constructors named like class with void-ish false positives:
            # require at least one modifier keyword
            mods = (m.group("mods") or "").lower()
            if not any(k in mods for k in ("public", "private", "protected", "static")):
                continue
            brace_at = m.end() - 1
            inner = _match_brace_block(body, brace_at)
            if inner is None:
                continue
            end = brace_at + 1 + len(inner) + 1
            if overlaps(m.start(), end):
                continue
            occupied.append((m.start(), end))
            start_line = unit.start_line + body.count("\n", 0, m.start())
            results.append((name, inner, start_line))

    # SSJS event / scriptlet with no function wrappers — treat whole unit
    if not results and unit.event:
        results.append((unit.event, body, unit.start_line))

    return results


def extract_functions_from_unit(unit: CodeUnit) -> list[tuple[str, str, int]]:
    lang = (unit.language or "").lower()
    if "lotus" in lang:
        return _extract_lotusscript(unit)
    if lang in {"javascript", "jscript", "ssjs", "js", "java", "xpages", "xsp", "source", "script"}:
        return _extract_brace_functions(unit)
    # Unknown but has Sub/Function markers
    if re.search(r"(?im)^\s*(?:Sub|Function)\s+", unit.body):
        return _extract_lotusscript(unit)
    return _extract_brace_functions(unit)


def build_inventory(units: Iterable[CodeUnit]) -> list[FunctionRecord]:
    records: list[FunctionRecord] = []
    seq = 0
    for unit in units:
        for name, fn_body, start_line in extract_functions_from_unit(unit):
            seq += 1
            allocates = _count_allocates(fn_body, unit.language)
            recycle_count = _count_cleanup(fn_body, unit.language)
            status = _classify(allocates, recycle_count)
            records.append(
                FunctionRecord(
                    id=f"FUNC-{seq:03d}",
                    design_element=_design_element(unit),
                    function_name=name,
                    language=_language_label(unit.language),
                    allocates_handles=allocates,
                    recycle_call_count=recycle_count,
                    status=status,
                    loc=_loc(fn_body),
                    source_file=unit.source_file,
                    start_line=start_line,
                )
            )
    return records


def summarize_inventory(records: list[FunctionRecord]) -> dict[str, Any]:
    total = len(records)
    allocating = [r for r in records if r.allocates_handles]
    with_cleanup = [r for r in allocating if r.recycle_call_count >= 1]
    unprotected = [r for r in allocating if r.recycle_call_count == 0]
    rate = round((len(with_cleanup) / len(allocating)) * 100.0, 1) if allocating else 100.0
    return {
        "total_functions_scanned": total,
        "functions_allocating_handles": len(allocating),
        "functions_with_cleanup": len(with_cleanup),
        "unprotected_functions": len(unprotected),
        "recycle_coverage_rate": rate,
    }


def run_function_inventory(
    source: str | None = None,
    *,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build function inventory + recycle coverage summary from a path or graph."""
    if graph is not None:
        units = extract_units_from_graph(graph)
    elif source is not None:
        units = extract_units_from_path(Path(source))
    else:
        raise ValueError("Provide source path or graph=")

    # Inventory all language-interesting units (not only keyword-prefiltered)
    interesting = apply_prefilter(units, require_keywords=False)
    records = build_inventory(interesting)
    # Surface unprotected first, then protected, then safe
    order = {"UNPROTECTED_ALLOCATION": 0, "PROTECTED": 1, "SAFE_NO_HANDLES": 2}
    records.sort(key=lambda r: (order.get(r.status, 9), r.design_element, r.function_name))

    summary = summarize_inventory(records)
    return {
        "summary": summary,
        "inventory": [r.to_dict() for r in records],
    }


__all__ = [
    "FunctionRecord",
    "build_inventory",
    "run_function_inventory",
    "summarize_inventory",
]
