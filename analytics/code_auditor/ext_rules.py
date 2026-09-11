"""External resource leak detectors (JDBC, HTTP) — Java / SSJS / XPages.

Complement C-API handle rules: connection pools and HTTP clients exhaust
differently but show up the same way in Domino agent assessments.
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


def _java_like(unit: CodeUnit) -> bool:
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes", "formula"}:
        return False
    return True


RE_JDBC_ASSIGN = re.compile(
    r"""(?:\b(?:Connection|javax\.sql\.DataSource)\b\s+(?P<var>\w+)\s*=)"""
    r"""|(?P<var2>\w+)\s*=\s*(?:\(\s*Connection\s*\))?\s*
        (?:\w+\s*\.\s*)?
        (?P<meth>getConnection|OpenConnection|openConnection|DriverManager\.getConnection)\s*\("""
    r"""|(?P<var3>\w+)\s*=\s*DriverManager\s*\.\s*getConnection\s*\(""",
    re.I | re.X,
)
RE_CONN_CLOSE = re.compile(
    r"""\b(?P<var>\w+)\s*\.\s*(?:close|Close)\s*\(|\btry\s*\(\s*[^)]*\bConnection\b""",
    re.I | re.X,
)

RE_HTTP_ASSIGN = re.compile(
    r"""(?:\b(?:NotesHTTPRequest|HttpURLConnection|URLConnection|HttpClient|
        CloseableHttpClient|HttpResponse|InputStream)\b\s+(?P<var>\w+)\s*=)"""
    r"""|(?P<var2>\w+)\s*=\s*(?:\w+\s*\.\s*)?
        (?P<meth>createHTTPRequest|CreateHTTPRequest|openConnection|getInputStream|
            execute|send|GetResponse|getResponse)\s*\("""
    r"""|(?P<var3>\w+)\s*=\s*new\s+(?:URL|URLConnection|HttpURLConnection)\b""",
    re.I | re.X,
)
RE_HTTP_CLOSE = re.compile(
    r"""\b(?P<var>\w+)\s*\.\s*(?:close|Close|disconnect|Disconnect|abort|Abort)\s*\(""",
    re.I | re.X,
)


def _var_closed(body: str, var: str) -> bool:
    return bool(
        re.search(rf"\b{re.escape(var)}\s*\.\s*(?:close|Close|disconnect|Disconnect)\s*\(", body, re.I)
    )


def detect_ext001(unit: CodeUnit) -> list[Finding]:
    """JDBC / DB2 connection opened without close in finally."""
    if not _java_like(unit):
        return []
    body = unit.body or ""
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in RE_JDBC_ASSIGN.finditer(body):
        var = match.group("var") or match.group("var2") or match.group("var3")
        if not var or var in seen:
            continue
        meth = match.groupdict().get("meth") or "getConnection"
        if _var_closed(body, var):
            continue
        # try-with-resources covering Connection
        if re.search(r"try\s*\([^)]*\bConnection\b", body, re.I):
            continue
        seen.add(var)
        line = _line_of(body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "EXT-001",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=88,
                impact=(
                    f"JDBC/DB2 connection `{var}` from `{meth}` is never `.close()`d. "
                    "Unclosed connections exhaust the Domino/JVM pool and can stall agents "
                    "and web threads (same failure mode seen in Domino application assessments)."
                ),
                remediation=remediation_template("EXT-001", unit.language),
                action=f"Close `{var}` in a finally block (or use try-with-resources).",
                handle_lifecycle_warning=f"Line {line}: connection `{var}` opened without close.",
            )
        )
    return findings


def detect_ext002(unit: CodeUnit) -> list[Finding]:
    """HTTP / URL connection or response stream without close/disconnect."""
    if not _java_like(unit):
        return []
    body = unit.body or ""
    # Need an HTTP-ish signal so we don't flag every InputStream
    if not re.search(
        r"NotesHTTPRequest|HttpURLConnection|URLConnection|createHTTPRequest|"
        r"CreateHTTPRequest|java\.net\.URL|HttpClient|getInputStream",
        body,
        re.I,
    ):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in RE_HTTP_ASSIGN.finditer(body):
        var = match.group("var") or match.group("var2") or match.group("var3")
        if not var or var in seen:
            continue
        meth = match.groupdict().get("meth") or "HTTP"
        if _var_closed(body, var):
            continue
        # NotesHTTPRequest often uses .Close() capital C — covered by _var_closed
        seen.add(var)
        line = _line_of(body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "EXT-002",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=84,
                impact=(
                    f"HTTP/URL resource `{var}` ({meth}) is acquired without close/disconnect. "
                    "Leaked sockets and response streams accumulate under agent / XPage load "
                    "(e.g. PDF-from-URL and outbound API patterns)."
                ),
                remediation=remediation_template("EXT-002", unit.language),
                action=f"Close/disconnect `{var}` in finally after reading the response body.",
                handle_lifecycle_warning=f"Line {line}: HTTP resource `{var}` never closed.",
            )
        )
    return findings


EXT_DETECTORS = [detect_ext001, detect_ext002]

__all__ = ["EXT_DETECTORS", "bind_helpers", "detect_ext001", "detect_ext002"]
