"""Function & Recycle Inventory Engine.

Scans extracted Java / SSJS / XPages / LotusScript blocks, inventories every
declared subroutine/method, and classifies recycle coverage for Domino handles.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

from analytics.code_auditor.api_catalog import (
    ALLOCATION_PATTERNS,
    LS_ALLOCATION_PATTERNS,
    analyze_handle_cleanup,
    body_allocates,
    count_cleanup_statements,
)
from analytics.code_auditor.context import (
    NON_LOOP_HYGIENE_NOTE,
    body_has_loop,
    inventory_risk_severity,
)
from analytics.code_auditor.extractor import (
    apply_prefilter,
    extract_units_from_graph,
    extract_units_from_path,
)
from analytics.code_auditor.models import CodeUnit
from analytics.code_auditor.snippets import (
    extract_line_window,
    language_label,
    remediation_template,
)
FunctionStatus = Literal[
    "SAFE_NO_HANDLES",
    "PROTECTED",
    "PARTIAL_CLEANUP",
    "CONDITIONAL_CLEANUP",
    "ESCAPE_PATH_GAP",
    "UNPROTECTED_ALLOCATION",
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
    # Deep-dive fields (same shape as Handle & Memory Findings)
    code_snippet_as_is: str = ""
    code_snippet_to_be: str = ""
    code_snippet_lines: list = field(default_factory=list)
    line_number_start: int = 0
    line_number_end: int = 0
    highlight_line: int = 0
    problem_breakdown: str = ""
    remediation_guide: str = ""
    handle_lifecycle_warning: str = ""
    language_label: str = ""
    in_loop: bool = False
    risk_severity: str = "MEDIUM"
    allocated_vars: list[str] = field(default_factory=list)
    cleaned_vars: list[str] = field(default_factory=list)
    unclean_vars: list[str] = field(default_factory=list)
    cleanup_conditional: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["finding_id"] = self.id
        data["issue"] = f"{self.function_name} — {self.status.replace('_', ' ').title()}"
        data["location"] = f"{self.design_element} L{self.start_line}"
        data["line_number"] = self.highlight_line or self.start_line
        data["severity"] = self.risk_severity
        return data


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
    return body_allocates(body, language)


def _count_cleanup(body: str, language: str = "") -> int:
    return count_cleanup_statements(body, language)


def _classify(allocates: bool, recycle_count: int) -> FunctionStatus:
    """Legacy binary classify — prefer analyze_handle_cleanup for path-aware status."""
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


def _extract_lotusscript(unit: CodeUnit) -> list[tuple[str, str, int, str]]:
    """Return list of (name, analysis_body, start_line, display_body)."""
    body = unit.body
    results: list[tuple[str, str, int, str]] = []

    for m in _LS_DECL.finditer(body):
        line_start = body.rfind("\n", 0, m.start()) + 1
        nl = body.find("\n", m.start())
        decl_line = body[line_start : nl if nl >= 0 else len(body)]
        if _LS_DECLARE.search(decl_line) or decl_line.lstrip().lower().startswith("declare "):
            continue
        name = m.group(2)
        fn_body = m.group(3) or ""
        display = m.group(0)
        start_line = unit.start_line + body.count("\n", 0, m.start())
        results.append((name, fn_body, start_line, display))

    if not results and re.search(r"(?im)^\s*(?:Public |Private )?(?:Sub|Function)\s+", body):
        first = re.search(
            r"(?im)^\s*(?:Public |Private |Friend )?(?:Sub|Function)\s+([A-Za-z_][\w.]*)",
            body,
        )
        if first and not _LS_DECLARE.search(body[max(0, first.start() - 20) : first.end()]):
            name = first.group(1)
            rest = body[first.end() :]
            results.append((name, rest, unit.start_line, body))
    elif not results and unit.event:
        results.append((unit.event, body, unit.start_line, body))

    return results


def _extract_brace_functions(unit: CodeUnit) -> list[tuple[str, str, int, str]]:
    """Extract JS/Java methods as (name, analysis_body, start_line, display_body)."""
    body = unit.body
    results: list[tuple[str, str, int, str]] = []
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
        results.append((m.group("name"), inner, start_line, body[m.start() : end]))

    lang = (unit.language or "").lower()
    if "java" in lang or "xpage" in lang or lang in {"source", "script"}:
        for m in _JAVA_METHOD.finditer(body):
            name = m.group("name")
            ret = (m.group("ret") or "").strip().split()[-1] if m.group("ret") else ""
            if name.lower() in _JAVA_SKIP_NAMES:
                continue
            if ret.lower() in _JAVA_SKIP_RET:
                continue
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
            results.append((name, inner, start_line, body[m.start() : end]))

    if not results and unit.event:
        results.append((unit.event, body, unit.start_line, body))

    return results


def extract_functions_from_unit(unit: CodeUnit) -> list[tuple[str, str, int, str]]:
    lang = (unit.language or "").lower()
    if "lotus" in lang:
        return _extract_lotusscript(unit)
    if lang in {"javascript", "jscript", "ssjs", "js", "java", "xpages", "xsp", "source", "script"}:
        return _extract_brace_functions(unit)
    if re.search(r"(?im)^\s*(?:Sub|Function)\s+", unit.body):
        return _extract_lotusscript(unit)
    return _extract_brace_functions(unit)


def _focus_offset(analysis_body: str, status: FunctionStatus, language: str) -> int:
    """Byte offset inside analysis_body to highlight."""
    if status in {"PROTECTED", "PARTIAL_CLEANUP", "CONDITIONAL_CLEANUP"}:
        patterns = [
            re.compile(r"\bDelete\s+\w+", re.I),
            re.compile(r"\b(?:Call\s+)?\w+\.Recycle\s*\(", re.I),
            re.compile(r"\.recycle\s*\(", re.I),
        ]
        for p in patterns:
            m = p.search(analysis_body)
            if m:
                return m.start()
    if status in {
        "UNPROTECTED_ALLOCATION",
        "PARTIAL_CLEANUP",
        "CONDITIONAL_CLEANUP",
        "PROTECTED",
        "SAFE_NO_HANDLES",
    }:
        patterns = LS_ALLOCATION_PATTERNS if _is_lotusscript_lang(language) else ALLOCATION_PATTERNS
        for p in patterns:
            m = p.search(analysis_body)
            if m:
                return m.start()
    return 0


def _inventory_guides(
    status: FunctionStatus, language: str, function_name: str, *, in_loop: bool,
    unclean_vars: list[str] | None = None,
) -> tuple[str, str, str, str]:
    """problem, guide, warning, to_be_template."""
    is_ls = _is_lotusscript_lang(language) or language == "LotusScript"
    unclean = unclean_vars or []
    if status == "UNPROTECTED_ALLOCATION":
        if in_loop:
            problem = (
                f"`{function_name}` allocates Domino handles inside a loop but never releases "
                f"them with {'`Delete`' if is_ls else '`.recycle()`'} before advancing. "
                "Each iteration can exhaust the C-API handle table."
            )
            guide = (
                "Capture the next handle first, finish work, then "
                + (
                    "`Delete` the current Notes* object before advancing."
                    if is_ls
                    else "`.recycle()` in a `finally` before advancing."
                )
            )
            warning = (
                "CRITICAL handle exhaustion risk — unprotected allocation inside a collection loop."
            )
            to_be = remediation_template(
                "LS-DOM-001" if is_ls else "DOM-002",
                "lotusscript" if is_ls else "java",
                has_loop=True,
            )
        else:
            problem = (
                f"`{function_name}` is a one-shot helper that allocates Domino handles without "
                f"explicit {'`Delete`' if is_ls else '`.recycle()`'}. This is routine memory "
                "hygiene — not a hot-path handle exhaustion loop."
            )
            guide = (
                "Add a linear cleanup before Exit: "
                + ("`Delete doc` / `Delete mime`." if is_ls else "`try/finally` + `.recycle()`.")
            )
            warning = "Routine memory hygiene (non-loop). " + NON_LOOP_HYGIENE_NOTE
            to_be = remediation_template(
                "LS-DOM-004" if is_ls else "DOM-010",
                "lotusscript" if is_ls else "java",
                has_loop=False,
            )
    elif status == "PARTIAL_CLEANUP":
        missing = ", ".join(f"`{v}`" for v in unclean) if unclean else "one or more allocated handles"
        problem = (
            f"`{function_name}` cleans up some Domino handles but leaves {missing} without "
            f"{'`Delete`' if is_ls else '`.recycle()`'}."
        )
        guide = (
            "Pair every allocated Notes*/Document variable with a matching cleanup on all exit paths."
        )
        warning = "Partial cleanup — presence of Delete/recycle is not enough when names don't match."
        to_be = remediation_template(
            "LS-DOM-004" if is_ls else "DOM-010",
            "lotusscript" if is_ls else "java",
            has_loop=in_loop,
        )
    elif status == "CONDITIONAL_CLEANUP":
        problem = (
            f"`{function_name}` only releases handles inside conditional branches "
            f"(no unconditional {'`Delete`' if is_ls else '`.recycle()`'} / `finally`)."
        )
        guide = (
            "Move cleanup into a `finally` (Java/SSJS) or after the business If (LotusScript) "
            "so every path releases the handle."
        )
        warning = "Conditional cleanup — skip/fail paths can leak C-API handles."
        to_be = remediation_template(
            "DOM-012" if not is_ls else "LS-DOM-007",
            "lotusscript" if is_ls else "java",
            has_loop=in_loop,
        )
    elif status == "ESCAPE_PATH_GAP":
        problem = (
            f"`{function_name}` allocates Domino handles then hits `Exit Sub` / `GoTo` / early "
            f"`return` before {'`Delete`' if is_ls else '`.recycle()`'} runs on that path."
        )
        guide = (
            "Delete/recycle before every Exit/return, or centralize cleanup in an error-handler "
            "label / `finally` that all exits share."
        )
        warning = "Escape-path gap — early exit can leave C-API handles open."
        to_be = remediation_template(
            "LS-DOM-007" if is_ls else "DOM-010",
            "lotusscript" if is_ls else "java",
            has_loop=in_loop,
        )
    elif status == "PROTECTED":
        problem = (
            f"`{function_name}` allocates Domino handles and contains explicit cleanup "
            f"({'`Delete` / `.Recycle()`' if is_ls else '`.recycle()`'})."
        )
        guide = "Keep cleanup on every exit path (including error handlers / early returns)."
        warning = "Protected — verify cleanup still runs on exception / early-exit branches."
        to_be = (
            "' Already protected pattern — retain Delete / Recycle on all paths\n"
            if is_ls
            else "// Already protected — keep recycle() in finally on all paths\n"
        ) + remediation_template(
            "LS-DOM-001" if is_ls else "DOM-002",
            "lotusscript" if is_ls else "java",
            has_loop=in_loop,
        )
    else:
        problem = (
            f"`{function_name}` does not appear to allocate Domino native handles "
            "(no Notes*/GetDocument*/createDateTime signals in the body)."
        )
        guide = "No recycle action required for this routine based on static heuristics."
        warning = "Safe (no handles) — re-check if this helper is called with live handles passed in."
        to_be = (
            "' No Domino handle allocation detected — no recycle changes required."
            if is_ls
            else "// No Domino handle allocation detected."
        )
    return problem, guide, warning, to_be


def _attach_inventory_snippets(
    *,
    display_body: str,
    analysis_body: str,
    start_line: int,
    status: FunctionStatus,
    language: str,
    function_name: str,
    in_loop: bool,
    unclean_vars: list[str] | None = None,
) -> dict[str, Any]:
    # Map analysis offset → absolute line in display_body
    # Prefer highlighting inside display text by searching the same token
    offset = _focus_offset(analysis_body, status, language)
    # Find corresponding position in display_body
    needle = analysis_body[offset : offset + 48] if analysis_body else ""
    disp_idx = display_body.find(needle) if needle.strip() else 0
    if disp_idx < 0:
        disp_idx = 0
    highlight_line = start_line + display_body.count("\n", 0, disp_idx)

    # Prefer a generous window so the full function is readable; fall back to ±25
    line_count = max(1, display_body.count("\n") + 1)
    radius = 40 if line_count <= 90 else 25
    snippet, line_start, line_end, _hl, structured = extract_line_window(
        display_body,
        focus_line=highlight_line,
        base_line=start_line,
        radius=radius,
    )
    problem, guide, warning, to_be = _inventory_guides(
        status, language, function_name, in_loop=in_loop, unclean_vars=unclean_vars
    )
    return {
        "code_snippet_as_is": snippet,
        "code_snippet_to_be": to_be,
        "code_snippet_lines": structured,
        "line_number_start": line_start,
        "line_number_end": line_end,
        "highlight_line": highlight_line,
        "problem_breakdown": problem,
        "remediation_guide": guide,
        "handle_lifecycle_warning": warning,
        "language_label": language if language in {"LotusScript", "Java", "SSJS / JavaScript", "XPages"} else language_label(language),
    }


def build_inventory(units: Iterable[CodeUnit]) -> list[FunctionRecord]:
    records: list[FunctionRecord] = []
    seq = 0
    for unit in units:
        for name, fn_body, start_line, display_body in extract_functions_from_unit(unit):
            seq += 1
            analysis = analyze_handle_cleanup(fn_body, unit.language)
            status = analysis.status  # type: ignore[assignment]
            lang_label = _language_label(unit.language)
            looped = body_has_loop(fn_body)
            risk = inventory_risk_severity(status=status, in_loop=looped)
            snippets = _attach_inventory_snippets(
                display_body=display_body or fn_body,
                analysis_body=fn_body,
                start_line=start_line,
                status=status,
                language=unit.language,
                function_name=name,
                in_loop=looped,
                unclean_vars=analysis.unclean_vars,
            )
            records.append(
                FunctionRecord(
                    id=f"FUNC-{seq:03d}",
                    design_element=_design_element(unit),
                    function_name=name,
                    language=lang_label,
                    allocates_handles=analysis.allocates,
                    recycle_call_count=analysis.recycle_call_count,
                    status=status,
                    loc=_loc(fn_body),
                    source_file=unit.source_file,
                    start_line=start_line,
                    in_loop=looped,
                    risk_severity=risk,
                    allocated_vars=analysis.allocated_vars,
                    cleaned_vars=analysis.cleaned_vars,
                    unclean_vars=analysis.unclean_vars,
                    cleanup_conditional=analysis.cleanup_conditional,
                    **snippets,
                )
            )
    return records


def summarize_inventory(records: list[FunctionRecord]) -> dict[str, Any]:
    total = len(records)
    allocating = [r for r in records if r.allocates_handles]
    fully_protected = [r for r in allocating if r.status == "PROTECTED"]
    partial = [r for r in allocating if r.status == "PARTIAL_CLEANUP"]
    conditional = [r for r in allocating if r.status == "CONDITIONAL_CLEANUP"]
    escape_gaps = [r for r in allocating if r.status == "ESCAPE_PATH_GAP"]
    unprotected = [r for r in allocating if r.status == "UNPROTECTED_ALLOCATION"]
    # Legacy "with cleanup" = any presence of cleanup (not fully unprotected)
    with_cleanup = [r for r in allocating if r.status != "UNPROTECTED_ALLOCATION"]
    safe = [r for r in records if not r.allocates_handles]
    # Among allocators: only fully protected count toward recycle coverage honesty
    recycle_among_allocators = (
        round((len(fully_protected) / len(allocating)) * 100.0, 1) if allocating else 100.0
    )
    # Overall: only SAFE + fully PROTECTED count as "safe" for the ring
    handle_safety_rate = (
        round(((len(safe) + len(fully_protected)) / total) * 100.0, 1) if total else 100.0
    )
    return {
        "total_functions_scanned": total,
        "functions_safe_no_handles": len(safe),
        "functions_allocating_handles": len(allocating),
        "functions_with_cleanup": len(fully_protected),
        "functions_partial_cleanup": len(partial),
        "functions_conditional_cleanup": len(conditional),
        "functions_escape_path_gap": len(escape_gaps),
        "unprotected_functions": len(unprotected),
        "functions_incomplete_cleanup": len(partial) + len(conditional) + len(escape_gaps),
        # Primary UX metric (ring) — incomplete cleanup does NOT inflate safety
        "handle_safety_rate": handle_safety_rate,
        # Secondary: full cleanup rate among allocators only
        "recycle_coverage_rate": recycle_among_allocators,
        # Compatibility: any cleanup signal (partial/conditional/protected)
        "functions_any_cleanup_signal": len(with_cleanup),
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
    # Exclude pure formula from handle inventory (separate FORM-* track)
    interesting = [u for u in interesting if (u.language or "").lower() != "formula"]
    records = build_inventory(interesting)
    order = {
        "UNPROTECTED_ALLOCATION": 0,
        "ESCAPE_PATH_GAP": 1,
        "PARTIAL_CLEANUP": 2,
        "CONDITIONAL_CLEANUP": 3,
        "PROTECTED": 4,
        "SAFE_NO_HANDLES": 5,
    }
    records.sort(key=lambda r: (order.get(r.status, 9), r.design_element, r.function_name))

    summary = summarize_inventory(records)
    return {
        "summary": summary,
        "inventory": [r.to_dict() for r in records],
    }


__all__ = [
    "FunctionRecord",
    "FunctionStatus",
    "build_inventory",
    "run_function_inventory",
    "summarize_inventory",
    "ALLOCATION_PATTERNS",
    "LS_ALLOCATION_PATTERNS",
]
