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

# Forms with this many non-richtext fields risk the 32KB summary limit.
SUMMARY_FIELD_WARN_THRESHOLD = 45

RE_ISSUMMARY_TRUE = re.compile(
    r"""(?:\b(?:IsSummary|issummary)\s*(?:=|:=)\s*(?:True|true|TRUE)\b)"""
    r"""|(?:\.\s*setSummary\s*\(\s*true\s*\))""",
    re.I | re.X,
)
RE_REPLACE_LARGE = re.compile(
    r"""\.(?:ReplaceItemValue|replaceItemValue|AppendItemValue)\s*\(\s*[\"'][^\"']+[\"']\s*,""",
    re.I,
)


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


def detect_form004(unit: CodeUnit) -> list[Finding]:
    """Code that forces items to stay summary (32KB summary-limit risk)."""
    lang = (unit.language or "").lower()
    if lang == "formula":
        return []
    body = unit.body or ""
    findings: list[Finding] = []
    for match in RE_ISSUMMARY_TRUE.finditer(body):
        line = _line_of(body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "FORM-004",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=82,
                impact=(
                    "Code sets IsSummary = True. Summary fields count toward the Domino "
                    "document summary limit (~32KB, or larger with NSF_LargeSummary). "
                    "Oversized summary data prevents documents from opening or updating views."
                ),
                remediation=(
                    "Only mark fields summary when they appear in views/search. "
                    "For large text, set IsSummary = False (or use Rich Text / attachments)."
                ),
                action="Avoid forcing IsSummary=True on large or multi-value text items.",
            )
        )
    # Heuristic: many ReplaceItemValue calls without any IsSummary = False nearby
    replaces = list(RE_REPLACE_LARGE.finditer(body))
    if len(replaces) >= 8 and not re.search(r"IsSummary\s*(?:=|:=)\s*False", body, re.I):
        line = _line_of(body, replaces[0].start(), unit.start_line)
        findings.append(
            _finding(
                "FORM-004",
                unit,
                line=line,
                evidence=_snippet(body, replaces[0].start()),
                confidence=70,
                impact=(
                    f"Routine writes {len(replaces)} items via ReplaceItemValue/AppendItemValue "
                    "without setting IsSummary = False. Default summary flags can push documents "
                    "over the 32KB summary limit (Dealer Lookup / IDM-style failures)."
                ),
                remediation=(
                    "After writing large text items: item.IsSummary = False (LS) or "
                    "item.setSummary(false) (Java). Prefer Rich Text for bulky content."
                ),
                action="Clear summary flag on large items that are not needed in views.",
            )
        )
    return findings


def detect_form004_from_graph(graph: dict | None) -> list[Finding]:
    """Flag forms whose field inventory suggests summary-budget pressure."""
    if not graph:
        return []
    from analytics.code_auditor.models import CodeUnit

    de = graph.get("design_elements") or {}
    forms = list(de.get("forms") or []) + list(de.get("subforms") or [])
    out: list[Finding] = []
    for form in forms:
        if not isinstance(form, dict):
            continue
        name = form.get("name") or "unknown"
        fields = form.get("fields") or []
        if not isinstance(fields, list):
            continue
        summary_eligible = []
        for fld in fields:
            if not isinstance(fld, dict):
                continue
            ftype = (fld.get("type") or "").lower()
            fname = fld.get("name") or ""
            if not fname or fname.startswith("$"):
                continue
            if ftype in {"richtext", "rich text", "authors", "readers", "password"}:
                continue
            summary_eligible.append(fname)
        if len(summary_eligible) < SUMMARY_FIELD_WARN_THRESHOLD:
            continue
        # Synthetic unit so _finding / snippets still work
        unit = CodeUnit(
            source_file=form.get("source_file") or "graph",
            element_name=name,
            element_type="subform" if form.get("is_subform") else "form",
            language="formula",
            event="form_design",
            body=(
                f"' Form {name} has {len(summary_eligible)} non-richtext fields "
                f"(threshold {SUMMARY_FIELD_WARN_THRESHOLD}). "
                f"Sample: {', '.join(summary_eligible[:12])}"
            ),
            start_line=1,
        )
        out.append(
            _finding(
                "FORM-004",
                unit,
                line=1,
                evidence=unit.body,
                confidence=78,
                impact=(
                    f"Form `{name}` defines {len(summary_eligible)} non-richtext fields. "
                    "Notes marks most of these summary by default; dense summary payloads "
                    "trigger the classic 32KB summary error (open/save/view failures)."
                ),
                remediation=(
                    "Audit which fields are required in views/search; set IsSummary=False "
                    "(agent) or move bulky data to Rich Text/attachments; consider "
                    "NSF_LargeSummary=1 only as a server-side stopgap."
                ),
                action=f"Reduce summary footprint on form `{name}` (target < {SUMMARY_FIELD_WARN_THRESHOLD} summary fields).",
            )
        )
    return out


FORM_DETECTORS = [detect_form001, detect_form002, detect_form003, detect_form004]

__all__ = [
    "FORM_DETECTORS",
    "SUMMARY_FIELD_WARN_THRESHOLD",
    "bind_helpers",
    "detect_form001",
    "detect_form002",
    "detect_form003",
    "detect_form004",
    "detect_form004_from_graph",
]