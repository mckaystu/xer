"""Narrow LotusScript external-resource detectors (not C-API LS-DOM-*).

LotusScript remains out of scope for Domino C-API handle-table exhaustion, but
assessments routinely find JavaSession bridge leaks and DB2 OpenConnection gaps.
These rules are the only LS detectors wired into the auditor.
"""

from __future__ import annotations

import re
from typing import Callable

from analytics.code_auditor.models import CodeUnit, Finding
from analytics.code_auditor.snippets import remediation_template

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


def _finding(*args, **kwargs) -> Finding:
    assert _finding_fn is not None
    return _finding_fn(*args, **kwargs)


def _line_of(body: str, index: int, start_line: int) -> int:
    assert _line_of_fn is not None
    return _line_of_fn(body, index, start_line)


def _snippet(body: str, index: int, width: int = 220) -> str:
    assert _snippet_fn is not None
    return _snippet_fn(body, index, width)


def _is_lotusscript(unit: CodeUnit) -> bool:
    lang = (unit.language or "").lower()
    return "lotus" in lang or lang in {"ls", "lss", "notes"}


RE_JAVA_SESSION = re.compile(
    r"""(?:\b(?:Dim|Set)\s+(?P<var>\w+)\s+As\s+JavaSession\b)"""
    r"""|(?:\bSet\s+(?P<var2>\w+)\s*=\s*(?:New\s+)?JavaSession\b)"""
    r"""|(?:\b(?P<var3>\w+)\s*=\s*(?:CreateObject|CreateJavaSession)\s*\([^)]*JavaSession)""",
    re.I | re.X,
)
RE_JAVA_SESSION_RELEASE = re.compile(
    r"""(?:\bSet\s+(?P<var>\w+)\s*=\s*Nothing\b)"""
    r"""|(?:\b(?P<var2>\w+)\s*\.\s*(?:Close|close)\s*\()""",
    re.I | re.X,
)

RE_OPEN_CONNECTION = re.compile(
    r"""(?:\b(?:Call\s+)?(?P<obj>\w+)\s*\.\s*OpenConnection\s*\()"""
    r"""|(?:\bSet\s+(?P<var>\w+)\s*=\s*.*\bOpenConnection\b)"""
    r"""|(?:\bCall\s+OpenConnection\s*\()"""
    r"""|(?:\b(?P<fn>SetTheConnection|OpenConnection)\s*\()""",
    re.I | re.X,
)
RE_CLOSE_CONNECTION = re.compile(
    r"""(?:\b(?:Call\s+)?(?P<obj>\w+)\s*\.\s*(?:CloseConnection|Close|Disconnect)\s*\()"""
    r"""|(?:\bCall\s+(?:CloseConnection|CloseTheConnection)\s*\()"""
    r"""|(?:\bSet\s+(?P<var>\w+)\s*=\s*Nothing\b)""",
    re.I | re.X,
)


def detect_ls_ext001(unit: CodeUnit) -> list[Finding]:
    """JavaSession created in LotusScript without Set … = Nothing / Close."""
    if not _is_lotusscript(unit):
        return []
    body = unit.body or ""
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in RE_JAVA_SESSION.finditer(body):
        var = match.group("var") or match.group("var2") or match.group("var3")
        if not var or var in seen:
            continue
        released = bool(
            re.search(rf"\bSet\s+{re.escape(var)}\s*=\s*Nothing\b", body, re.I)
            or re.search(rf"\b{re.escape(var)}\s*\.\s*(?:Close|close)\s*\(", body, re.I)
        )
        if released:
            continue
        seen.add(var)
        line = _line_of(body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "LS-EXT-001",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=90,
                impact=(
                    f"LotusScript `JavaSession` `{var}` is created without `Set {var} = Nothing` "
                    "(or Close). Resources bound to the LS→JVM bridge stay pinned for the agent "
                    "run and can leak across scheduled executions."
                ),
                remediation=remediation_template("LS-EXT-001", unit.language),
                action=f"After Java calls finish: Set {var} = Nothing (and related JavaObject vars).",
                handle_lifecycle_warning=f"Line {line}: JavaSession `{var}` never released.",
            )
        )
    return findings


def detect_ls_ext002(unit: CodeUnit) -> list[Finding]:
    """DB2 / ODBC OpenConnection without CloseConnection / Nothing."""
    if not _is_lotusscript(unit):
        return []
    body = unit.body or ""
    if not re.search(r"OpenConnection|SetTheConnection|DB2|ODBC|Connection", body, re.I):
        return []
    findings: list[Finding] = []
    for match in RE_OPEN_CONNECTION.finditer(body):
        # Any CloseConnection / Disconnect later in the body clears the finding for this unit
        if RE_CLOSE_CONNECTION.search(body):
            # Still flag if OpenConnection is inside a loop and close is only once outside —
            # keep v1 simple: presence of any close is enough.
            return []
        line = _line_of(body, match.start(), unit.start_line)
        label = match.group("fn") or match.group("obj") or match.group("var") or "OpenConnection"
        findings.append(
            _finding(
                "LS-EXT-002",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=86,
                impact=(
                    f"Database connection opened via `{label}` with no CloseConnection / "
                    "Disconnect / Set … = Nothing in this routine. Unreleased DB2/ODBC sessions "
                    "exhaust external pools (classic Domino agent assessment finding)."
                ),
                remediation=remediation_template("LS-EXT-002", unit.language),
                action="Pair every OpenConnection with CloseConnection (or equivalent) on all exit paths.",
                handle_lifecycle_warning=f"Line {line}: OpenConnection without matching close.",
            )
        )
        break  # one finding per unit is enough
    return findings


LS_EXT_DETECTORS = [detect_ls_ext001, detect_ls_ext002]

__all__ = [
    "LS_EXT_DETECTORS",
    "bind_helpers",
    "detect_ls_ext001",
    "detect_ls_ext002",
]
