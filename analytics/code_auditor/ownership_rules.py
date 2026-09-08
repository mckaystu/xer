"""Deterministic cross-function Domino handle ownership (DOM-OWN-001).

Builds a light call graph within extracted units and, when graph edges are provided,
restricts cross-element callees to USES_SCRIPT_LIBRARY targets (plus Use \"Lib\" in body).
LLM Pass 3 (DOM-BS-002) remains for ambiguous enrichment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from analytics.code_auditor.api_catalog import (
    HANDLE_TYPES_LS,
    analyze_handle_cleanup,
    handle_params,
    is_lotusscript,
)
from analytics.code_auditor.models import CodeUnit, Finding

_finding_fn: Callable[..., Finding] | None = None
_line_of_fn: Callable[[str, int, int], int] | None = None
_snippet_fn: Callable[..., str] | None = None

RE_USE_LIB = re.compile(r'(?im)^\s*Use\s+"([^"]+)"')


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


def _finding(*args, **kwargs) -> Finding:
    assert _finding_fn is not None
    return _finding_fn(*args, **kwargs)


def _line_of(body: str, index: int, start_line: int) -> int:
    assert _line_of_fn is not None
    return _line_of_fn(body, index, start_line)


def _snippet(body: str, index: int, width: int = 220) -> str:
    assert _snippet_fn is not None
    return _snippet_fn(body, index, width)


_LS_TYPE_ALT = "|".join(re.escape(t) for t in HANDLE_TYPES_LS)

_LS_FN = re.compile(
    r"(?im)^[ \t]*(?:Public |Private |Friend )?"
    r"(Sub|Function)\s+([A-Za-z_][\w.]*)\s*(\([^)]*\))?"
    r"(?:\s+As\s+(\w+))?"
    r"[^\n]*\n"
    r"(.*?)"
    r"^[ \t]*End\s+(?:Sub|Function)\b",
    re.S,
)

_JAVA_FN = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<mods>(?:public|private|protected|static|final|synchronized|\s)+)?"
    r"(?P<ret>[\w.<>,\[\]?][\w.<>,\[\]?\s]*)\s+"
    r"(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^;{]*)\)\s*(?:throws\s+[^{]+)?\{",
)


@dataclass
class FnInfo:
    name: str
    body: str
    signature: str
    returns_handle: bool
    handle_params: list[str]
    cleans_self: bool
    unit: CodeUnit
    start_offset: int


def _match_brace(text: str, open_idx: int) -> str:
    depth = 0
    in_str: str | None = None
    escape = False
    for i in range(open_idx, len(text)):
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
                return text[open_idx + 1 : i]
    return text[open_idx + 1 :]


def _norm_type(t: str) -> str:
    low = (t or "").lower().replace("_", "")
    if low in {"scriptlibrary", "scriptlib"}:
        return "scriptlibrary"
    return (t or "").lower()


def _element_key(element_type: str, name: str) -> str:
    return f"{_norm_type(element_type)}:{(name or '').lower()}"


def _build_library_uses(edges: Iterable[dict[str, Any]] | None) -> dict[str, set[str]]:
    """Map owner element_key → set of script library names (lower)."""
    uses: dict[str, set[str]] = {}
    for edge in edges or []:
        if (edge.get("type") or "") != "USES_SCRIPT_LIBRARY":
            continue
        src = edge.get("source") or {}
        tgt = edge.get("target") or {}
        if _norm_type(tgt.get("element_type", "")) != "scriptlibrary":
            continue
        key = _element_key(src.get("element_type", ""), src.get("name", ""))
        uses.setdefault(key, set()).add((tgt.get("name") or "").lower())
    return uses


def _uses_from_body(body: str) -> set[str]:
    return {m.group(1).lower() for m in RE_USE_LIB.finditer(body or "")}


def _extract_fns(unit: CodeUnit) -> list[FnInfo]:
    body = unit.body or ""
    out: list[FnInfo] = []
    if is_lotusscript(unit.language):
        for m in _LS_FN.finditer(body):
            kind, name, params, as_type, fn_body = (
                m.group(1),
                m.group(2),
                m.group(3) or "()",
                m.group(4) or "",
                m.group(5) or "",
            )
            sig = f"{kind} {name}{params}" + (f" As {as_type}" if as_type else "")
            returns = bool(as_type and re.search(rf"(?i)^(?:{_LS_TYPE_ALT})$", as_type))
            params_list = handle_params(params, unit.language)
            analysis = analyze_handle_cleanup(fn_body, unit.language)
            out.append(
                FnInfo(
                    name=name,
                    body=fn_body,
                    signature=sig,
                    returns_handle=returns,
                    handle_params=params_list,
                    cleans_self=analysis.recycle_call_count > 0
                    and analysis.status in {"PROTECTED", "PARTIAL_CLEANUP"},
                    unit=unit,
                    start_offset=m.start(),
                )
            )
    else:
        for m in _JAVA_FN.finditer(body):
            name = m.group("name")
            if name in {"if", "for", "while", "switch", "catch"}:
                continue
            ret = (m.group("ret") or "").strip()
            params = m.group("params") or ""
            open_brace = body.find("{", m.end() - 1)
            if open_brace < 0:
                continue
            fn_body = _match_brace(body, open_brace)
            returns = bool(
                re.search(
                    r"(?i)\b(?:Document|NotesDocument|View|NotesView|Database|NotesDatabase|"
                    r"ViewEntry|DocumentCollection|ViewEntryCollection|MIMEEntity|Item)\b",
                    ret,
                )
            )
            params_list = handle_params(params, unit.language)
            analysis = analyze_handle_cleanup(fn_body, unit.language)
            out.append(
                FnInfo(
                    name=name,
                    body=fn_body,
                    signature=f"{ret} {name}({params})",
                    returns_handle=returns,
                    handle_params=params_list,
                    cleans_self=analysis.recycle_call_count > 0
                    and analysis.status in {"PROTECTED", "PARTIAL_CLEANUP"},
                    unit=unit,
                    start_offset=m.start(),
                )
            )
    return out


def _caller_cleans_after(call_body: str, call_end: int, language: str, result_var: str | None) -> bool:
    window = call_body[call_end : call_end + 400]
    analysis = analyze_handle_cleanup(window, language)
    if analysis.recycle_call_count > 0:
        return True
    if result_var:
        if is_lotusscript(language):
            if re.search(rf"(?i)\bDelete\s+{re.escape(result_var)}\b", window):
                return True
            if re.search(rf"(?i)\b{re.escape(result_var)}\s*\.\s*Recycle\s*\(", window):
                return True
        else:
            if re.search(rf"(?i)\b{re.escape(result_var)}\s*\.\s*recycle\s*\(", window):
                return True
    return False


def _callee_in_scope(
    caller: FnInfo,
    callee: FnInfo,
    *,
    library_uses: dict[str, set[str]],
    edges_provided: bool,
) -> tuple[bool, bool]:
    """Return (allowed, cross_library)."""
    if caller.unit.element_name == callee.unit.element_name and (
        _norm_type(caller.unit.element_type) == _norm_type(callee.unit.element_type)
    ):
        return True, False

    callee_is_lib = _norm_type(callee.unit.element_type) == "scriptlibrary"
    if not edges_provided:
        # No graph: keep global name match (legacy), mark cross-lib when types differ
        return True, callee.unit.element_name != caller.unit.element_name

    if not callee_is_lib:
        # Different design element that isn't a linked library — skip
        return False, False

    owner_key = _element_key(caller.unit.element_type, caller.unit.element_name)
    libs = set(library_uses.get(owner_key) or ())
    libs |= _uses_from_body(caller.unit.body or "")
    lib_name = (callee.unit.element_name or "").lower()
    if lib_name in libs:
        return True, True
    return False, False


def detect_dom_own001(
    units: Iterable[CodeUnit],
    *,
    edges: Iterable[dict[str, Any]] | None = None,
) -> list[Finding]:
    """Static ownership gaps across call sites, optionally scoped by USES_SCRIPT_LIBRARY."""
    edge_list = list(edges) if edges is not None else None
    library_uses = _build_library_uses(edge_list)
    edges_provided = edge_list is not None

    fns: dict[str, list[FnInfo]] = {}
    all_fns: list[FnInfo] = []
    for unit in units:
        if (unit.language or "").lower() == "formula":
            continue
        for info in _extract_fns(unit):
            fns.setdefault(info.name.lower(), []).append(info)
            all_fns.append(info)

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for caller in all_fns:
        body = caller.body
        lang = caller.unit.language
        unit_body = caller.unit.body or ""
        if is_lotusscript(lang):
            call_pat = re.compile(
                r"(?i)(?:\bCall\s+([A-Za-z_][\w.]*)\s*\(|\bSet\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*\()"
            )
        else:
            call_pat = re.compile(
                r"(?i)(?:([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*\(|\b([A-Za-z_][\w.]*)\s*\()"
            )

        for m in call_pat.finditer(body):
            if is_lotusscript(lang):
                result_var = m.group(2)
                callee_name = (m.group(1) or m.group(3) or "").split(".")[-1]
            else:
                result_var = m.group(1)
                callee_name = (m.group(2) or m.group(3) or "").split(".")[-1]
            if not callee_name or callee_name.lower() == caller.name.lower():
                continue
            callees = fns.get(callee_name.lower()) or []
            for callee in callees:
                allowed, cross_lib = _callee_in_scope(
                    caller, callee, library_uses=library_uses, edges_provided=edges_provided
                )
                if not allowed:
                    continue
                if not (callee.returns_handle or callee.handle_params):
                    continue
                callee_cleans = callee.cleans_self
                abs_index = caller.start_offset + m.start()
                if caller.body and caller.body in unit_body:
                    abs_index = unit_body.find(caller.body) + m.start()
                line = _line_of(unit_body, max(0, abs_index), caller.unit.start_line)
                conf = 72 if cross_lib else 82
                scope_note = (
                    f" (via Use / USES_SCRIPT_LIBRARY → `{callee.unit.element_name}`)"
                    if cross_lib
                    else ""
                )

                if callee.handle_params and not callee.returns_handle:
                    if callee_cleans:
                        continue
                    if _caller_cleans_after(body, m.end(), lang, callee.handle_params[0]):
                        continue
                    key = (caller.unit.element_name, caller.name, callee.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        _finding(
                            "DOM-OWN-001",
                            caller.unit,
                            line=line,
                            evidence=_snippet(unit_body, max(0, abs_index)),
                            confidence=max(70, conf - 4),
                            impact=(
                                f"`{callee.name}` accepts handle parameter(s) "
                                f"({', '.join(callee.handle_params)}) but neither callee nor caller "
                                f"clearly Deletes/recycles after the call{scope_note}."
                            ),
                            remediation=(
                                "Assign ownership: either Delete/recycle inside the callee before return, "
                                "or in the caller immediately after the call — never neither."
                            ),
                            action=f"Clarify Delete/.recycle ownership for `{callee.name}` parameters.",
                            handle_lifecycle_warning=(
                                f"Unassigned ownership: `{caller.name}` → `{callee.name}` (parameter)"
                                f"{scope_note}."
                            ),
                        )
                    )
                    continue

                if callee.returns_handle:
                    if result_var and _caller_cleans_after(body, m.end(), lang, result_var):
                        continue
                    if not result_var and callee_cleans:
                        continue
                    key = (caller.unit.element_name, caller.name, callee.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        _finding(
                            "DOM-OWN-001",
                            caller.unit,
                            line=line,
                            evidence=_snippet(unit_body, max(0, abs_index)),
                            confidence=conf,
                            impact=(
                                f"`{callee.name}` returns a Domino handle and neither the callee "
                                f"nor `{caller.name}` shows Delete/.recycle after the call"
                                + (f" into `{result_var}`" if result_var else "")
                                + f"{scope_note}."
                            ),
                            remediation=(
                                "Document ownership: recycle in callee before return, or in caller "
                                "after use — never neither. Prefer try/finally at the owning site."
                            ),
                            action=f"Assign Delete/.recycle ownership for return of `{callee.name}`.",
                            handle_lifecycle_warning=(
                                f"Unassigned ownership: `{caller.name}` ← `{callee.name}` (return)"
                                f"{scope_note}."
                            ),
                        )
                    )
    return findings


def run_ownership_detectors(
    units: Iterable[CodeUnit],
    *,
    edges: Iterable[dict[str, Any]] | None = None,
    graph: dict[str, Any] | None = None,
) -> list[Finding]:
    edge_list = edges
    if edge_list is None and graph is not None:
        edge_list = graph.get("edges") or []
    return detect_dom_own001(list(units), edges=edge_list)


__all__ = [
    "bind_helpers",
    "detect_dom_own001",
    "run_ownership_detectors",
]
