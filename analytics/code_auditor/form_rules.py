"""Formula-language quality rules (FORM-*) — separate from C-API recycle.

@Formula does not own Notes C-API handles the same way LS/Java do. These rules
flag lookup/perf and secrets patterns in formula units.
"""

from __future__ import annotations

import re
from typing import Callable

from analytics.code_auditor.models import CodeUnit, Finding

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


RE_DBLOOKUP = re.compile(r"@Db(?:Lookup|Column)\s*\(", re.I)
RE_WHILE_FOR = re.compile(r"@(?:While|For)\s*\(", re.I)
RE_SECRET = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|apikey|api_key|token)\s*(?::=|=|:)\s*[\"'][^\"']{3,}",
)
RE_HTTP = re.compile(r"(?i)https?://[^\s\"']+")


def _is_formula(unit: CodeUnit) -> bool:
    return (unit.language or "").lower() == "formula"


def detect_form001(unit: CodeUnit) -> list[Finding]:
    """Repeated or dense @DbLookup/@DbColumn — expensive NSF lookups."""
    if not _is_formula(unit):
        return []
    hits = list(RE_DBLOOKUP.finditer(unit.body or ""))
    if len(hits) < 2:
        return []
    line = _line_of(unit.body, hits[0].start(), unit.start_line)
    return [
        _finding(
            "FORM-001",
            unit,
            line=line,
            evidence=_snippet(unit.body, hits[0].start()),
            confidence=75,
            impact=(
                f"Formula contains {len(hits)} @DbLookup/@DbColumn calls. Repeated NSF lookups "
                "are expensive on hot paths (computed fields, hide-when, view selection)."
            ),
            remediation=(
                "Cache lookup results in fields, use a single multi-value lookup where possible, "
                "or move batch work to LotusScript/Java with proper handle lifecycle."
            ),
            action="Reduce or cache @DbLookup/@DbColumn calls in this formula.",
        )
    ]


def detect_form002(unit: CodeUnit) -> list[Finding]:
    """@While/@For with nested @DbLookup — looped NSF access."""
    if not _is_formula(unit):
        return []
    body = unit.body or ""
    m_loop = RE_WHILE_FOR.search(body)
    m_lookup = RE_DBLOOKUP.search(body)
    if not m_loop or not m_lookup or m_lookup.start() < m_loop.start():
        return []
    line = _line_of(body, m_lookup.start(), unit.start_line)
    return [
        _finding(
            "FORM-002",
            unit,
            line=line,
            evidence=_snippet(body, m_lookup.start()),
            confidence=80,
            impact=(
                "@While/@For formula appears to call @DbLookup/@DbColumn inside a loop — "
                "NIF/NSF pressure scales with iterations."
            ),
            remediation=(
                "Hoist lookups outside the formula loop, precompute values in an agent, "
                "or redesign the view/column so formula does not query per iteration."
            ),
            action="Remove in-loop @DbLookup/@DbColumn from formula.",
        )
    ]


def detect_form003(unit: CodeUnit) -> list[Finding]:
    """Hardcoded secrets or plaintext HTTP endpoints in formula."""
    if not _is_formula(unit):
        return []
    findings: list[Finding] = []
    body = unit.body or ""
    for m in RE_SECRET.finditer(body):
        line = _line_of(body, m.start(), unit.start_line)
        findings.append(
            _finding(
                "FORM-003",
                unit,
                line=line,
                evidence=_snippet(body, m.start()),
                confidence=85,
                impact="Formula embeds a credential-like literal — risk of NSF export leakage.",
                remediation="Move secrets to environment/config documents; never hardcode in formula.",
                action="Remove hardcoded secret from formula.",
            )
        )
    for m in RE_HTTP.finditer(body):
        url = m.group(0)
        if url.lower().startswith("http://"):
            line = _line_of(body, m.start(), unit.start_line)
            findings.append(
                _finding(
                    "FORM-003",
                    unit,
                    line=line,
                    evidence=_snippet(body, m.start()),
                    confidence=70,
                    impact=f"Plaintext HTTP endpoint in formula: {url[:80]}",
                    remediation="Use HTTPS and avoid embedding credentials in the URL.",
                    action="Replace http:// with https:// and remove embedded credentials.",
                )
            )
    return findings


FORM_DETECTORS = [detect_form001, detect_form002, detect_form003]

__all__ = ["FORM_DETECTORS", "bind_helpers", "detect_form001", "detect_form002", "detect_form003"]
