"""Performance & NIF indexing anti-pattern detectors (PERF-001..003)."""

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


RE_LOOP = re.compile(r"\b(?:For|While|Do\s+While|Do\s+Until|for|while)\b", re.I)
RE_AUTOUPDATE_FALSE = re.compile(
    r"""(?:\.AutoUpdate\s*=\s*(?:False|false|FALSE)
        |\.setAutoUpdate\s*\(\s*false\s*\)
        |AutoUpdate\s*=\s*False)""",
    re.I | re.X,
)
RE_VIEW_WRITE_HINT = re.compile(
    r"""(?:\.Save\s*\(|\.save\s*\(|ReplaceItemValue|replaceItemValue
        |ComputeWithForm|computeWithForm|GetNextDocument|getNextDocument)""",
    re.I | re.X,
)
RE_GETVIEW_IN_LOOP = re.compile(
    r"""(?:for|while|Do\s+While|Do\s+Until|For\s+)[\s\S]{0,40}
        (?:[\s\S](?!\b(?:Next|Wend|Loop|End\s+For)\b)){0,900}?
        \.\s*(?:[Gg]et[Vv]iew)\s*\(""",
    re.I | re.X,
)
RE_GETVIEW_CALL = re.compile(r"\.\s*(?:[Gg]et[Vv]iew)\s*\(", re.I)
RE_SAVE_IN_LOOP = re.compile(
    r"""(?:for|while|Do\s+While|Do\s+Until|For\s+)[\s\S]{0,40}
        (?:[\s\S](?!\b(?:Next|Wend|Loop|End\s+For)\b)){0,1200}?
        \.\s*(?:[Ss]ave)\s*\(""",
    re.I | re.X,
)
RE_SAVE_CALL = re.compile(r"\.\s*(?:[Ss]ave)\s*\(", re.I)
RE_VIEW_REF = re.compile(r"\b(?:NotesView|View)\b|\.GetView\b|\.getView\b", re.I)


def detect_perf001(unit: CodeUnit) -> list[Finding]:
    """Missing view.AutoUpdate = False before write/iteration loops on a view."""
    if not RE_LOOP.search(unit.body):
        return []
    if not RE_VIEW_REF.search(unit.body):
        return []
    if not RE_VIEW_WRITE_HINT.search(unit.body):
        return []
    if RE_AUTOUPDATE_FALSE.search(unit.body):
        return []
    # Prefer pointing at first loop
    match = RE_LOOP.search(unit.body)
    assert match is not None
    line = _line_of(unit.body, match.start(), unit.start_line)
    return [
        _finding(
            "PERF-001",
            unit,
            line=line,
            evidence=_snippet(unit.body, match.start()),
            confidence=86,
            impact=(
                "PERF-001: Missing view.AutoUpdate = False triggers view index (NIF) recalculation "
                "on every document write/advance inside the loop — severe CPU and lock overhead."
            ),
            remediation=remediation_template("PERF-001", unit.language),
            action="Set view.AutoUpdate = False before the loop; restore True afterward if needed.",
            handle_lifecycle_warning=(
                f"Line {line}: view write/iteration loop without AutoUpdate=False — NIF thrash risk."
            ),
        )
    ]


def detect_perf002(unit: CodeUnit) -> list[Finding]:
    """db.getView(...) / GetView inside a loop body."""
    match = RE_GETVIEW_IN_LOOP.search(unit.body)
    if not match:
        # Fallback: multiple GetView calls + a loop
        if not RE_LOOP.search(unit.body):
            return []
        calls = list(RE_GETVIEW_CALL.finditer(unit.body))
        if len(calls) < 2:
            return []
        match = calls[0]
    line = _line_of(unit.body, match.start(), unit.start_line)
    # If AutoUpdate false alone isn't enough — still flag hoist issue
    return [
        _finding(
            "PERF-002",
            unit,
            line=line,
            evidence=_snippet(unit.body, match.start()),
            confidence=84,
            impact=(
                "PERF-002: Instantiating a view handle with getView/GetView inside a loop causes "
                "repeated NIF open/lock contention. Hoist the view outside the loop and recycle/Delete once."
            ),
            remediation=remediation_template("PERF-002", unit.language),
            action="Call getView/GetView once before the loop; reuse the view handle inside.",
            handle_lifecycle_warning=(
                f"Line {line}: getView/GetView appears inside an iteration — hoist outside the loop."
            ),
        )
    ]


def detect_perf003(unit: CodeUnit) -> list[Finding]:
    """doc.save / doc.Save inside collection loops without batching cues."""
    match = RE_SAVE_IN_LOOP.search(unit.body)
    if not match:
        if not (RE_LOOP.search(unit.body) and RE_SAVE_CALL.search(unit.body)):
            return []
        match = RE_SAVE_CALL.search(unit.body)
        assert match is not None
        # Require collection-style iteration OR repeated write hints in a loop
        if not re.search(
            r"GetNextDocument|getNextDocument|GetNextEntry|getNextEntry|Forall|replaceItemValue|ReplaceItemValue",
            unit.body,
            re.I,
        ):
            return []
    # Skip tiny agents that save once after a single doc fetch
    if unit.body.count("\n") < 12 and unit.body.lower().count("save") == 1:
        if not re.search(r"GetNextDocument|getNextDocument|for\s*\(|While|Do\s+While", unit.body, re.I):
            return []
    line = _line_of(unit.body, match.start(), unit.start_line)
    return [
        _finding(
            "PERF-003",
            unit,
            line=line,
            evidence=_snippet(unit.body, match.start()),
            confidence=78,
            impact=(
                "PERF-003: Saving every document on each loop iteration drives high disk I/O and "
                "transaction log bloat. Prefer batching, deferred saves, or throttled checkpoints."
            ),
            remediation=remediation_template("PERF-003", unit.language),
            action="Avoid per-iteration Save when possible; batch updates or checkpoint periodically.",
            handle_lifecycle_warning=(
                f"Line {line}: document Save inside a collection loop — unbatched write path."
            ),
        )
    ]


PERF_DETECTORS = [
    detect_perf001,
    detect_perf002,
    detect_perf003,
]
