"""Basic Domino application security detectors (SEC-001 / SEC-002)."""

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


def _snippet(body: str, index: int, width: int = 200) -> str:
    assert _snippet_fn is not None
    return _snippet_fn(body, index, width)


RE_PASSWORD_ASSIGN = re.compile(
    r"""(?ix)
    \b(?:password|passwd|pwd|pass|secret|api[_-]?key|client[_-]?secret)\b
    \s*(?:=|:=)\s*
    (?:["']([^"']{3,})["'])
    """,
)
RE_HTTP_URL = re.compile(r"""(?i)\bhttps?://[^\s\"']+|\b["']http://[^"']+["']""")
RE_PLAIN_HTTP = re.compile(r"""(?i)["']http://[^"']+["']|\bhttp://[A-Za-z0-9._/-]+""")

RE_QUERY_UNID = re.compile(
    r"""(?ix)
    (?:
      # LotusScript / SSJS: query / param → GetDocumentByUNID
      (?:Query_String|QueryString|CGI|param|params|request\.parameter|
         facesContext|context\.getUrlParameter|getUrlParameter|
         \@UrlQueryString|UrlQueryString)
      [\s\S]{0,400}?
      \.?GetDocumentByUNID\s*\(
    |
      GetDocumentByUNID\s*\(\s*
      (?:Query_String|QueryString|CGI|param|unid\s*&|Request\.|
         context\.getUrlParameter|getUrlParameter|facesContext)
    |
      # Java
      getDocumentByUNID\s*\(\s*
      (?:request\.getParameter|param\.get|params\.get|query\.get)
    )
    """,
)
RE_AUTH_HINT = re.compile(
    r"(?i)\b(?:IsValid|Validate|Authorize|CheckAccess|ACL|CanOpen|"
    r"getEffectiveUserName|NotesACL|isReader|hasRole|assertAccess)\b"
)


def detect_sec001(unit: CodeUnit) -> list[Finding]:
    """Hardcoded credentials combined with plaintext http:// endpoints."""
    body = unit.body or ""
    pw = RE_PASSWORD_ASSIGN.search(body)
    http = RE_PLAIN_HTTP.search(body)
    if not (pw and http):
        return []
    # Prefer pointing at password assignment
    idx = pw.start()
    line = _line_of(body, idx, unit.start_line)
    return [
        _finding(
            "SEC-001",
            unit,
            line=line,
            evidence=_snippet(body, idx, 280),
            confidence=90,
            severity="HIGH",
            impact=(
                "SEC-001: Hardcoded password/secret assignment appears alongside an http:// "
                "endpoint. Credentials in source and cleartext transport risk account takeover "
                "and network sniffing."
            ),
            remediation=remediation_template("SEC-001", unit.language),
            action="Move secrets to secure config/vault; use https:// and never commit plaintext passwords.",
            handle_lifecycle_warning=(
                f"Line {line}: hardcoded credential + plaintext HTTP — rotate secrets and force TLS."
            ),
            in_loop=False,
        )
    ]


def detect_sec002(unit: CodeUnit) -> list[Finding]:
    """GetDocumentByUNID fed from URL/query string without auth checks."""
    body = unit.body or ""
    match = RE_QUERY_UNID.search(body)
    if not match:
        return []
    # Soften if nearby authorization heuristics exist in the same unit
    has_auth = RE_AUTH_HINT.search(body) is not None
    line = _line_of(body, match.start(), unit.start_line)
    severity = "MEDIUM" if has_auth else "HIGH"
    return [
        _finding(
            "SEC-002",
            unit,
            line=line,
            evidence=_snippet(body, match.start(), 280),
            confidence=82 if has_auth else 90,
            severity=severity,
            impact=(
                "SEC-002: Document lookup via GetDocumentByUNID appears driven by URL/query "
                "parameters without a clear authorization gate. Attackers can enumerate UNIDs "
                "and open documents outside intended ACL/UI constraints."
            ),
            remediation=remediation_template("SEC-002", unit.language),
            action="Validate the caller may open the UNID (ACL/role check) before GetDocumentByUNID.",
            handle_lifecycle_warning=(
                f"Line {line}: query-string UNID → GetDocumentByUNID without evident auth check."
            ),
            in_loop=False,
        )
    ]


SEC_DETECTORS = [detect_sec001, detect_sec002]
