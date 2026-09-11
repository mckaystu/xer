"""Deterministic Domino memory / handle anti-pattern detectors."""

from __future__ import annotations

import re
from typing import Iterable

from analytics.code_auditor.context import (
    LOOP_SENSITIVE_HANDLE_RULES,
    NON_LOOP_HYGIENE_NOTE,
    body_has_loop,
    calibrate_handle_severity,
    is_client_javascript,
    is_lotusscript_language,
)
from analytics.code_auditor.models import RULE_CATALOG, CodeUnit, Finding
from analytics.code_auditor.snippets import (
    attach_snippet_fields,
    remediation_template,
)

RE_CHAINED_CREATE = re.compile(
    r"""(?P<ev>\b\w+\s*\.\s*
        (?:createDateTime|createName|createDateRange|getDatabase)\s*\([^;]*?\)\s*\.\s*\w+)""",
    re.I | re.X | re.S,
)
RE_CHAINED_VIEW_DOC = re.compile(
    r"""(?P<ev>(?:db|database|Database|notesDatabase|NotesDatabase|[\w]+)\s*\.\s*
        getView\s*\([^;]*?\)\s*\.\s*
        (?:getFirstDocument|getLastDocument|getAllDocumentsByKey|getDocumentByKey)\s*\()""",
    re.I | re.X | re.S,
)
RE_LOOP = re.compile(r"\b(while|for)\b", re.I)
RE_GET_NEXT = re.compile(r"\bgetNext(?:Document|Entry)\s*\(", re.I)
RE_RECYCLE = re.compile(r"\.recycle\s*\(", re.I)
RE_TRY = re.compile(r"\btry\b", re.I)
RE_FINALLY = re.compile(r"\bfinally\b", re.I)
RE_LOTUS_NEW = re.compile(
    r"(?m)^(?!\s*import\b).{0,120}?"
    r"(?:"
    r"\b(?:lotus\.domino\.)?(?:Database|Document|View|ViewEntry|DocumentCollection|DateTime|Name)\b\s+\w+\s*="
    r"|\bNotes(?:Database|Document|View|ViewEntry|DateTime|Name)\b\s+\w+\s*="
    r"|\.\s*get(?:Database|View|Document|FirstDocument|NextDocument|DocumentByUNID)\s*\("
    r"|\.\s*create(?:Document|DateTime|ViewNav|MIMEEntity|Stream)\s*\("
    r")",
    re.I,
)
RE_ODA_IMPORT = re.compile(r"import\s+org\.openntf\.domino", re.I)
RE_ODA_TYPE = re.compile(r"\borg\.openntf\.domino\.\w+\b")
RE_RECYCLE_CALL = re.compile(r"(\w+)\s*\.\s*recycle\s*\(\s*\)")
RE_STATIC_HANDLE = re.compile(
    r"\bstatic\s+(?:final\s+)?(?:lotus\.domino\.)?(?:Session|Database|Document|View|ViewEntry|"
    r"DocumentCollection|DateTime|Name|AgentContext)\b",
    re.I,
)
# LotusScript module-level Static handle fields (Public NotesDocument/Database/View → LS-DOM-003)
RE_LS_STATIC = re.compile(
    r"^\s*Static\s+\w+\s+As\s+Notes(?:Session|Database|Document|View|DateTime|Name)\b"
    r"|^\s*Public\s+\w+\s+As\s+Notes(?:Session|DateTime|Name)\b",
    re.I | re.M,
)
RE_SCOPE_CACHE = re.compile(
    r"(?:sessionScope|applicationScope|viewScope)\s*(?:\.|\[)\s*[\"']?\w*[\"']?\s*\]?\s*=\s*[^\n;]+"
    r"(?:Document|Database|View|Session|NotesDocument|NotesDatabase)",
    re.I,
)
RE_STATIC_MAP = re.compile(
    r"\bstatic\s+(?:Map|HashMap|ConcurrentHashMap|WeakHashMap)\s*<[^>]*(?:Document|Database|View|Session)",
    re.I,
)
RE_COLUMN_IN_LOOP = re.compile(
    r"(?:for|while)[^{\n]*[\{\n](?:(?!\b(?:for|while)\b).){0,800}?getColumnValues?\s*\(",
    re.I | re.S,
)
RE_DOC_IN_LOOP = re.compile(
    r"(?:for|while)[^{\n]*[\{\n](?:(?!\b(?:for|while)\b).){0,800}?\.getDocument\s*\(",
    re.I | re.S,
)
RE_CREATEDATETIME_HOT = re.compile(
    r"(?:for|while)[^{\n]*[\{\n](?:(?!\b(?:for|while)\b).){0,600}?createDateTime\s*\(",
    re.I | re.S,
)
RE_FROM_LOTUS = re.compile(r"Factory\.fromLotus\s*\(", re.I)
RE_PASS_LOTUS_HINT = re.compile(
    r"\b(?:lotus\.domino\.(?:Document|Database|View|Session))\b[^\n;]{0,80}\)",
    re.I,
)

# DOM-010: object creation / acquisition assignments
RE_OBJECT_CREATE = re.compile(
    r"""(?P<lhs>\b(?:Database|View|Document|ViewEntry|DocumentCollection|DateTime|Name|
        NotesDatabase|NotesDocument|NotesView|NotesViewEntry|NotesDateTime|Stream|MIMEEntity)\b
        \s+(?P<var>\w+)\s*=\s*(?!null\b|undefined\b)
        |(?P<var2>\w+)\s*=\s*(?:\(\s*)?(?:Database|View|Document|Session)
        |\b(?:Set\s+)?(?P<var3>\w+)\s*=\s*.*\.(?:getDatabase|getView|getFirstDocument|getDocumentByKey|
            getDocumentByUNID|createDocument|getAllDocumentsByKey|getAllEntries|createDateTime|
            createName|createViewNav|createMIMEEntity|createStream|getMIMEEntity)\s*\()""",
    re.I | re.X,
)

# DOM-011: parent.recycle()
RE_PARENT_RECYCLE = re.compile(
    r"\b(?P<parent>view|db|database|coll|collection|dc|vec|entries|vw)\s*\.\s*recycle\s*\(\s*\)",
    re.I,
)
RE_CHILD_USE = re.compile(
    r"\b(?P<child>doc|document|entry|ve|viewEntry|notesDoc)\b(?:\s*\.|\s*=)",
    re.I,
)

# Null-guard recycle is correct Domino hygiene — not DOM-012
RE_NULL_GUARD_RECYCLE = re.compile(
    r"""(?is)if\s*\(\s*([A-Za-z_]\w*)\s*(?:!=|!==|<>)\s*(?:null|undefined|Nothing)\s*\)\s*
        \{.{0,160}?\1\s*\.\s*recycle\s*\(\s*\)""",
    re.X,
)

# DOM-012: recycle inside business if within a loop (exclude null guards)
RE_CONDITIONAL_RECYCLE = re.compile(
    r"""(?is)(?:for|while)\s*\([^;{]{0,120}\)\s*\{.{0,500}?
        \bif\s*\(\s*(?![A-Za-z_]\w*\s*(?:!=|!==)\s*(?:null|undefined))
        [^;{]{0,120}\)\s*\{.{0,200}?\.\s*recycle\s*\(\s*\)""",
    re.X,
)

# DOM-013: doc = coll.getNextDocument(doc) without prior recycle of doc
RE_UNSAFE_REASSIGN = re.compile(
    r"""(?P<var>\w+)\s*=\s*[\w\.]+\.getNext(?:Document|Entry)\s*\(\s*(?P=var)\s*\)
        |Set\s+(?P<var2>\w+)\s*=\s*[\w\.]+\.GetNext(?:Document|Entry)\s*\(\s*(?P=var2)\s*\)""",
    re.I | re.X,
)
# Safer structural form that still leaks without recycle:
#   next = coll.getNextDocument(doc); ...; doc = next;
RE_TEMP_NEXT_REASSIGN = re.compile(
    r"""(?P<next>\w+)\s*=\s*(?P<coll>\w+)\s*\.\s*getNext(?:Document|Entry)\s*\(\s*(?P<doc>\w+)\s*\)\s*;
        [\s\S]{0,400}?
        (?P=doc)\s*=\s*(?P=next)\s*;""",
    re.I | re.X,
)


def _line_of(body: str, index: int, base: int = 1) -> int:
    return base + body.count("\n", 0, max(0, index))


def _snippet(body: str, index: int, radius: int = 180) -> str:
    start = max(0, index - 40)
    end = min(len(body), index + radius)
    text = body[start:end].strip()
    return text if len(text) <= 400 else text[:397] + "..."


def _finding(
    rule_id: str,
    unit: CodeUnit,
    *,
    line: int,
    evidence: str,
    confidence: int,
    severity: str | None = None,
    impact: str,
    remediation: str,
    action: str,
    engine: str = "rules",
    handle_lifecycle_warning: str | None = None,
    in_loop: bool | None = None,
) -> Finding:
    meta = RULE_CATALOG[rule_id]
    looped = body_has_loop(unit.body) if in_loop is None else in_loop
    base_sev = severity or meta["default_severity"]
    calibrated = calibrate_handle_severity(
        rule_id, base_sev, in_loop=looped, body=unit.body
    )
    warning = handle_lifecycle_warning or impact
    impact_text = impact
    if rule_id in LOOP_SENSITIVE_HANDLE_RULES and not looped:
        if NON_LOOP_HYGIENE_NOTE not in impact_text:
            impact_text = f"{impact_text} {NON_LOOP_HYGIENE_NOTE}"
        if warning and NON_LOOP_HYGIENE_NOTE not in warning:
            warning = f"{warning} {NON_LOOP_HYGIENE_NOTE}"
    # Language-aware TO-BE — linear Delete/try-finally when no loop
    rem = remediation_template(rule_id, unit.language, has_loop=looped)
    snippet_fields = attach_snippet_fields(
        unit=unit,
        focus_line=line,
        evidence=evidence,
        remediation=rem,
        handle_lifecycle_warning=warning,
        rule_id=rule_id,
        has_loop=looped,
    )
    return Finding(
        id="",  # assigned later
        rule_id=rule_id,
        title=meta["title"],
        severity=calibrated,  # type: ignore[arg-type]
        confidence=confidence,
        source_file=unit.source_file,
        element_name=unit.element_name,
        element_type=unit.element_type,
        language=unit.language,
        line=line,
        evidence=evidence,
        technical_impact=impact_text,
        remediation=rem,
        action_required=action,
        category=meta["category"],
        engine=engine,
        **snippet_fields,
    )


def detect_dom001(unit: CodeUnit) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in (RE_CHAINED_CREATE, RE_CHAINED_VIEW_DOC):
        for match in pattern.finditer(unit.body):
            findings.append(
                _finding(
                    "DOM-001",
                    unit,
                    line=_line_of(unit.body, match.start(), unit.start_line),
                    evidence=_snippet(unit.body, match.start()),
                    confidence=95,
                    impact=(
                        "Inline chained Domino object creation produces a temporary C-API handle that "
                        "cannot be recycled. Repeated calls exhaust the Notes/HTTP thread handle table "
                        "and can crash the server with panic 'Out of Handles'."
                    ),
                    remediation=(
                        "// Assign intermediates and recycle explicitly\n"
                        "DateTime dt = null;\n"
                        "try {\n"
                        "  dt = session.createDateTime(raw);\n"
                        "  String value = dt.getDateOnly();\n"
                        "} finally {\n"
                        "  if (dt != null) dt.recycle();\n"
                        "}"
                    ),
                    action="Break the chain into named variables and recycle in finally.",
                )
            )
    return findings


def detect_dom002(unit: CodeUnit) -> list[Finding]:
    # LotusScript loops are owned by LS-DOM-001 (Delete semantics, not .recycle())
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return []
    if not RE_LOOP.search(unit.body) or not RE_GET_NEXT.search(unit.body):
        return []

    # Require recycle of iteration vars — not merely any .recycle() (e.g. only coll.recycle()).
    iter_vars: set[str] = set()
    for m in re.finditer(
        r"(?i)\b(?:Document|ViewEntry|NotesDocument|NotesViewEntry)?\s*"
        r"([A-Za-z_]\w*)\s*=\s*\w+\s*\.\s*get(?:First|Next)(?:Document|Entry)\s*\(",
        unit.body,
    ):
        iter_vars.add(m.group(1))
    for m in re.finditer(
        r"(?i)\bgetNext(?:Document|Entry)\s*\(\s*([A-Za-z_]\w*)\s*\)",
        unit.body,
    ):
        iter_vars.add(m.group(1))
    if not iter_vars:
        iter_vars = {"doc", "entry", "document"}

    def _iter_recycled() -> bool:
        for var in iter_vars:
            if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", unit.body, re.I):
                return True
        if RE_FINALLY.search(unit.body) and any(
            re.search(
                rf"\bfinally\b[\s\S]{{0,400}}?\b{re.escape(v)}\s*\.\s*recycle\s*\(",
                unit.body,
                re.I,
            )
            for v in iter_vars
        ):
            return True
        return False

    if _iter_recycled():
        return []
    match = RE_GET_NEXT.search(unit.body)
    assert match is not None
    return [
        _finding(
            "DOM-002",
            unit,
            line=_line_of(unit.body, match.start(), unit.start_line),
            evidence=_snippet(unit.body, match.start(), 260),
            confidence=92,
            severity="CRITICAL",
            impact=(
                "Document/entry iteration without recycling the previous handle leaks one native object "
                "per loop iteration. Large collections amplify handle exhaustion and JVM/native memory growth."
            ),
            remediation=(
                "Document doc = coll.getFirstDocument();\n"
                "while (doc != null) {\n"
                "  Document next = coll.getNextDocument(doc);\n"
                "  try {\n"
                "    // process doc\n"
                "  } finally {\n"
                "    doc.recycle();\n"
                "  }\n"
                "  doc = next;\n"
                "}"
            ),
            action="Recycle the previous Document/ViewEntry before advancing the iterator.",
        )
    ]


def detect_dom003(unit: CodeUnit) -> list[Finding]:
    # Server-side Java is the primary target; SSJS only with strong Domino API signals.
    if unit.language == "java":
        pass
    elif unit.language in {"javascript", "ssjs", "jscript"}:
        strong = bool(
            re.search(r"lotus\.domino|createDateTime|\.recycle\s*\(|getCurrentSession", unit.body, re.I)
        )
        if not strong:
            return []
        # Skip obvious client CSJS libraries
        name = (unit.element_name or "").lower()
        if name.startswith("csjs") or "/csjs" in name:
            return []
    else:
        return []
    # Prefer DOM-010 for typed create assignments — avoid double-fire
    if RE_OBJECT_CREATE.search(unit.body):
        return []
    if not RE_LOTUS_NEW.search(unit.body):
        return []
    has_try = bool(RE_TRY.search(unit.body))
    has_finally = bool(RE_FINALLY.search(unit.body))
    has_recycle = bool(RE_RECYCLE.search(unit.body))
    if has_try and has_finally and has_recycle:
        return []
    match = RE_LOTUS_NEW.search(unit.body)
    assert match is not None
    confidence = 78 if not has_recycle else 70
    return [
        _finding(
            "DOM-003",
            unit,
            line=_line_of(unit.body, match.start(), unit.start_line),
            evidence=_snippet(unit.body, match.start()),
            confidence=confidence,
            impact=(
                "Native lotus.domino objects allocated without try/finally recycle scaffolding are often "
                "orphaned on exceptions, leaving C-API handles pinned until the HTTP thread dies."
            ),
            remediation=(
                "Database db = null;\n"
                "View view = null;\n"
                "try {\n"
                "  db = session.getDatabase(server, path);\n"
                "  view = db.getView(\"Lookup\");\n"
                "  // work\n"
                "} finally {\n"
                "  if (view != null) view.recycle();\n"
                "  if (db != null) db.recycle();\n"
                "}"
            ),
            action="Wrap Domino object lifetimes in try/finally and recycle every allocated handle.",
        )
    ]


def detect_dom004(unit: CodeUnit) -> list[Finding]:
    if not (RE_ODA_IMPORT.search(unit.body) or RE_ODA_TYPE.search(unit.body)):
        return []
    findings: list[Finding] = []
    for match in RE_RECYCLE_CALL.finditer(unit.body):
        findings.append(
            _finding(
                "DOM-004",
                unit,
                line=_line_of(unit.body, match.start(), unit.start_line),
                evidence=_snippet(unit.body, match.start()),
                confidence=96,
                impact=(
                    "OpenNTF Domino API *may* dispose wrappers at request end, but this auditor "
                    "assumes ODA auto-lifecycle is unreliable. Manual .recycle() on ODA objects "
                    "can still double-free if an outer ODA session later disposes the same native. "
                    "Prefer explicit try/finally recycle on lotus.domino handles, or verify ODA "
                    "session disposal is actually configured — never assume cleanup."
                ),
                remediation=(
                    "// Prefer explicit lifecycle (ODA auto-dispose is not trusted here):\n"
                    "lotus.domino.Document doc = null;\n"
                    "try {\n"
                    "  doc = database.getDocumentByUNID(unid);\n"
                    "  String subject = doc.getItemValueString(\"Subject\");\n"
                    "} finally {\n"
                    "  if (doc != null) doc.recycle();\n"
                    "}"
                ),
                action="Do not rely on ODA auto-dispose; use explicit finally recycle (or verified cleanup).",
            )
        )
    return findings


def detect_dom005(unit: CodeUnit) -> list[Finding]:
    uses_oda = bool(RE_ODA_IMPORT.search(unit.body) or RE_ODA_TYPE.search(unit.body))
    if not uses_oda:
        return []
    if RE_FROM_LOTUS.search(unit.body):
        return []
    if not RE_PASS_LOTUS_HINT.search(unit.body):
        # Softer signal: both APIs mentioned
        if "lotus.domino" in unit.body and "org.openntf.domino" in unit.body:
            match = re.search(r"lotus\.domino", unit.body)
            if not match:
                return []
            return [
                _finding(
                    "DOM-005",
                    unit,
                    line=_line_of(unit.body, match.start(), unit.start_line),
                    evidence=_snippet(unit.body, match.start()),
                    confidence=74,
                    impact=(
                        "Passing raw lotus.domino objects into ODA APIs without Factory.fromLotus() can "
                        "bypass wrapper lifecycle tracking and produce inconsistent recycle behavior."
                    ),
                    remediation="org.openntf.domino.Document doc = Factory.fromLotus(lotusDoc, Document.class, database);",
                    action="Wrap lotus.domino instances with Factory.fromLotus() before ODA use.",
                )
            ]
        return []
    match = RE_PASS_LOTUS_HINT.search(unit.body)
    assert match is not None
    return [
        _finding(
            "DOM-005",
            unit,
            line=_line_of(unit.body, match.start(), unit.start_line),
            evidence=_snippet(unit.body, match.start()),
            confidence=88,
            impact=(
                "Mixing unwrapped lotus.domino handles with ODA methods can double-wrap or skip lifecycle "
                "registration, leading to premature recycle or leaked natives."
            ),
            remediation="var odaDoc = Factory.fromLotus(lotusDoc, Document.class, database);",
            action="Convert lotus.domino objects with Factory.fromLotus() at the API boundary.",
        )
    ]


def detect_dom006(unit: CodeUnit) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in (RE_STATIC_HANDLE, RE_LS_STATIC):
        for match in pattern.finditer(unit.body):
            findings.append(
                _finding(
                    "DOM-006",
                    unit,
                    line=_line_of(unit.body, match.start(), unit.start_line),
                    evidence=_snippet(unit.body, match.start()),
                    confidence=94,
                    impact=(
                        "Static/module-level fields holding Domino handles pin native memory across "
                        "HTTP threads/classloaders. Handles become invalid after recycle on another "
                        "thread and cause crashes or silent corruption."
                    ),
                    remediation=(
                        "// Do not store Session/Database/Document/View in static or Public module fields.\n"
                        "// Obtain handles per-request from the current session context instead."
                    ),
                    action="Remove static/module Domino handle fields; fetch per request/thread.",
                )
            )
    return findings


def detect_dom007(unit: CodeUnit) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in (RE_SCOPE_CACHE, RE_STATIC_MAP):
        for match in pattern.finditer(unit.body):
            findings.append(
                _finding(
                    "DOM-007",
                    unit,
                    line=_line_of(unit.body, match.start(), unit.start_line),
                    evidence=_snippet(unit.body, match.start()),
                    confidence=86,
                    impact=(
                        "Caching native Domino handles in sessionScope/applicationScope or static maps retains "
                        "C-API memory for the lifetime of the scope and shares unsafe state across requests."
                    ),
                    remediation=(
                        "// Cache serializable data (UNIDs, strings, DTOs) — not Document/Database handles.\n"
                        "sessionScope.put(\"orderUnid\", doc.getUniversalID());"
                    ),
                    action="Cache identifiers/values only; never cache live Domino handles in scopes.",
                )
            )
    return findings


def detect_dom008(unit: CodeUnit) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, label in (
        (RE_COLUMN_IN_LOOP, "getColumnValue(s)"),
        (RE_DOC_IN_LOOP, "getDocument"),
    ):
        match = pattern.search(unit.body)
        if not match:
            continue
        findings.append(
            _finding(
                "DOM-008",
                unit,
                line=_line_of(unit.body, match.start(), unit.start_line),
                evidence=_snippet(unit.body, match.start(), 240),
                confidence=80,
                impact=(
                    f"Repeated {label} inside loops forces expensive document/column materialization and "
                    "allocates additional handles. Prefer ViewEntry column arrays or pre-cached maps."
                ),
                remediation=(
                    "ViewEntryCollection entries = view.getAllEntries();\n"
                    "ViewEntry entry = entries.getFirstEntry();\n"
                    "while (entry != null) {\n"
                    "  Vector cols = entry.getColumnValues(); // prefer over getDocument()\n"
                    "  ViewEntry next = entries.getNextEntry(entry);\n"
                    "  entry.recycle();\n"
                    "  entry = next;\n"
                    "}"
                ),
                action=f"Replace per-iteration {label} with ViewEntry column values or cached lookups.",
            )
        )
    return findings


def detect_dom009(unit: CodeUnit) -> list[Finding]:
    findings: list[Finding] = []
    match = RE_CREATEDATETIME_HOT.search(unit.body)
    if match:
        findings.append(
            _finding(
                "DOM-009",
                unit,
                line=_line_of(unit.body, match.start(), unit.start_line),
                evidence=_snippet(unit.body, match.start(), 220),
                confidence=84,
                impact=(
                    "Creating Domino DateTime objects inside loops allocates native handles per iteration. "
                    "Prefer java.util.Date / java.time or SSJS Date for formatting, converting once at boundaries."
                ),
                remediation=(
                    "// Prefer JVM dates inside hot loops\n"
                    "java.time.LocalDate d = LocalDate.parse(raw);\n"
                    "String iso = d.toString();\n"
                    "// Convert to Domino DateTime only when writing Items"
                ),
                action="Move createDateTime out of loops; use native date APIs for formatting.",
            )
        )
    # Also catch non-loop heavy chaining already covered by DOM-001; leave DOM-009 loop-focused
    return findings


def detect_dom010(unit: CodeUnit) -> list[Finding]:
    """Object creation/acquisition without surrounding try/finally recycle scaffolding."""
    # try/finally recycle is a Java/SSJS idiom; LotusScript is covered by DOM-002/013 + Delete.
    if unit.language not in {"java", "javascript", "ssjs", "jscript"}:
        return []

    match = RE_OBJECT_CREATE.search(unit.body)
    if not match:
        return []

    has_try = bool(RE_TRY.search(unit.body))
    has_finally = bool(RE_FINALLY.search(unit.body))
    has_recycle = bool(RE_RECYCLE.search(unit.body))
    if has_try and has_finally and has_recycle:
        return []

    var = match.groupdict().get("var") or match.groupdict().get("var2") or match.groupdict().get("var3") or "handle"
    line = _line_of(unit.body, match.start(), unit.start_line)
    return [
        _finding(
            "DOM-010",
            unit,
            line=line,
            evidence=_snippet(unit.body, match.start()),
            confidence=88,
            impact=(
                "Native Domino object creation without try/finally recycle scaffolding leaves C-API handles "
                "orphaned when exceptions occur mid-method, exhausting the Notes thread handle table."
            ),
            remediation=remediation_template("DOM-010", unit.language),
            action="Wrap Domino object creation in try/finally and recycle every allocated handle.",
            handle_lifecycle_warning=(
                f"Line {line}: Native object `{var}` initialized without guaranteed recycle() in a finally block."
            ),
        )
    ]


def detect_dom011(unit: CodeUnit) -> list[Finding]:
    """Parent recycled while child handles may still be live afterward."""
    findings: list[Finding] = []
    for match in RE_PARENT_RECYCLE.finditer(unit.body):
        parent = match.group("parent")
        after = unit.body[match.end() : match.end() + 400]
        # Only flag when a child handle is still used AFTER the parent recycle
        child_after = RE_CHILD_USE.search(after)
        if not child_after:
            continue
        # Ignore comments / recycle of the child itself right after
        after_snip = after[: child_after.start() + 40]
        if re.search(r"^\s*//", after_snip, re.M) and "recycle" in after_snip.lower():
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-011",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start(), 260),
                confidence=91,
                impact=(
                    "Recycling a parent View/Database/Collection while child Document/ViewEntry handles are still "
                    "referenced orphans those children in the C-API — subsequent use can crash the HTTP thread "
                    "or silently corrupt memory."
                ),
                remediation=(
                    "// Recycle children first, parent last\n"
                    "Document doc = view.getFirstDocument();\n"
                    "while (doc != null) {\n"
                    "  Document next = view.getNextDocument(doc);\n"
                    "  try { /* work */ } finally { doc.recycle(); }\n"
                    "  doc = next;\n"
                    "}\n"
                    "view.recycle();  // only after all children are gone\n"
                    "db.recycle();"
                ),
                action="Recycle child Document/ViewEntry handles before recycling the parent View/Database.",
                handle_lifecycle_warning=(
                    f"Line {line}: Parent `{parent}` recycled while child Document/ViewEntry handles may remain active."
                ),
            )
        )
    return findings


def detect_dom012(unit: CodeUnit) -> list[Finding]:
    """Recycle only on some loop branches — other paths leak."""
    if not RE_LOOP.search(unit.body):
        return []
    # Correct null-guard recycle is not a business-condition leak
    body_wo_null_guards = RE_NULL_GUARD_RECYCLE.sub("/* null-guard recycle */", unit.body)
    match = RE_CONDITIONAL_RECYCLE.search(body_wo_null_guards)
    if not match:
        # Secondary: business if-recycle near getNext (not null-guard)
        if RE_GET_NEXT.search(unit.body) and re.search(
            r"(?is)if\s*\(\s*(?![A-Za-z_]\w*\s*(?:!=|!==)\s*(?:null|undefined))"
            r"[^;{]{0,120}\)\s*\{.{0,200}?\.\s*recycle\s*\(",
            unit.body,
        ):
            match = re.search(
                r"(?is)if\s*\(\s*(?![A-Za-z_]\w*\s*(?:!=|!==)\s*(?:null|undefined))"
                r"[^;{]{0,120}\)\s*\{.{0,200}?\.\s*recycle\s*\(",
                unit.body,
            )
        else:
            return []
    assert match is not None
    # Map match offset back when we searched a substituted body
    line = _line_of(unit.body, min(match.start(), len(unit.body) - 1), unit.start_line)
    return [
        _finding(
            "DOM-012",
            unit,
            line=line,
            evidence=_snippet(unit.body, min(match.start(), len(unit.body) - 1), 280),
            confidence=85,
            impact=(
                "When .recycle() is guarded by an if inside a collection loop, failure/skip paths leave "
                "Document/ViewEntry handles open — a classic intermittent handle leak under real data."
            ),
            remediation=(
                "Document doc = coll.getFirstDocument();\n"
                "while (doc != null) {\n"
                "  Document next = coll.getNextDocument(doc);\n"
                "  try {\n"
                "    if (shouldProcess(doc)) {\n"
                "      // work\n"
                "    }\n"
                "  } finally {\n"
                "    doc.recycle(); // ALWAYS — outside the business if\n"
                "  }\n"
                "  doc = next;\n"
                "}"
            ),
            action="Move .recycle() into a finally block that runs on every loop iteration.",
            handle_lifecycle_warning=(
                f"Line {line}: .recycle() appears inside a conditional — some loop paths leave handles open."
            ),
        )
    ]


def detect_dom013(unit: CodeUnit) -> list[Finding]:
    """Re-assign loop variable via getNext* without recycling first."""
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return []
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for match in RE_UNSAFE_REASSIGN.finditer(unit.body):
        var = match.group("var") or match.group("var2") or "doc"
        prelude = unit.body[max(0, match.start() - 160) : match.start()]
        if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", prelude, re.I):
            continue
        if re.search(rf"\bDelete\s+{re.escape(var)}\b", prelude, re.I):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(
            _finding(
                "DOM-013",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=90,
                impact=(
                    f"Re-assigning `{var} = …getNextDocument({var})` drops the only reference to the previous "
                    "handle without recycle(), leaking one C-API object per iteration."
                ),
                remediation=(
                    f"Document next = collection.getNextDocument({var});\n"
                    f"{var}.recycle();\n"
                    f"{var} = next;"
                ),
                action=f"Capture next handle in a temp, recycle `{var}`, then reassign.",
                handle_lifecycle_warning=(
                    f"Line {line}: `{var}` re-assigned from getNext* without recycling the previous handle."
                ),
            )
        )

    # Temp-next pattern: next = getNext*(doc); …; doc = next; without doc.recycle in between
    for match in RE_TEMP_NEXT_REASSIGN.finditer(unit.body):
        doc_var = match.group("doc")
        next_var = match.group("next")
        if doc_var == next_var:
            continue
        window = match.group(0)
        if re.search(rf"\b{re.escape(doc_var)}\s*\.\s*recycle\s*\(", window, re.I):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(
            _finding(
                "DOM-013",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start(), 280),
                confidence=91,
                impact=(
                    f"`{next_var} = …getNext*({doc_var})` then `{doc_var} = {next_var}` without "
                    f"`{doc_var}.recycle()` leaks the previous Document/ViewEntry each iteration."
                ),
                remediation=(
                    f"Document {next_var} = collection.getNextDocument({doc_var});\n"
                    f"try {{ /* process {doc_var} */ }} finally {{ {doc_var}.recycle(); }}\n"
                    f"{doc_var} = {next_var};"
                ),
                action=f"Recycle `{doc_var}` after capturing `{next_var}`, before reassignment.",
                handle_lifecycle_warning=(
                    f"Line {line}: temp-next advance of `{doc_var}` without recycle."
                ),
            )
        )
    return findings


RE_ITEM_MIME_JAVA = re.compile(
    r"""(?P<type>\b(?:Item|MIMEEntity|RichTextItem)\b)\s+(?P<var>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth>getFirstItem|getMIMEEntity|createMIMEEntity|createRichTextItem|getFirstMIMEEntity)\s*\("""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth2>getFirstItem|getMIMEEntity|createMIMEEntity|createRichTextItem|getFirstMIMEEntity)\s*\(""",
    re.I | re.X,
)
RE_VIEWNAV_JAVA = re.compile(
    r"""(?P<type>\b(?:ViewNavigator|ViewEntryCollection)\b)\s+(?P<var>\w+)\s*="""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth>createViewNav|createViewNavFrom|getAllEntriesByKey|getAllEntries)\s*\(""",
    re.I | re.X,
)
RE_SEARCH_JAVA = re.compile(
    r"""(?P<var>\w+)\s*=\s*\w+\s*\.\s*(?P<meth>search|FTSearch|ftSearch)\s*\(""",
    re.I | re.X,
)


def detect_dom014(unit: CodeUnit) -> list[Finding]:
    """Un-recycled Item / MIME / RichText handles (Java/SSJS)."""
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return []
    findings: list[Finding] = []
    for match in RE_ITEM_MIME_JAVA.finditer(unit.body):
        var = match.group("var") or match.group("var2") or "item"
        meth = match.group("meth") or match.group("meth2") or "getFirstItem"
        after = unit.body[match.end() :]
        if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", after, re.I):
            continue
        if re.search(r"\bfinally\b[\s\S]{0,400}?\.recycle\s*\(", after, re.I) and re.search(
            rf"\b{re.escape(var)}\b", after[:500], re.I
        ):
            # soft: finally exists mentioning var — skip
            if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", after, re.I):
                continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-014",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=88,
                impact=(
                    f"`{meth}` creates Item/MIME handle `{var}` without `.recycle()`. "
                    "These are native C-API objects and leak especially inside loops."
                ),
                remediation=remediation_template("DOM-014", unit.language),
                action=f"Recycle `{var}` in a finally block after use.",
                handle_lifecycle_warning=f"Line {line}: `{var}` from {meth} never recycled.",
            )
        )
    return findings


def detect_dom015(unit: CodeUnit) -> list[Finding]:
    """Un-recycled ViewNavigator / ViewEntryCollection (Java/SSJS)."""
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return []
    findings: list[Finding] = []
    for match in RE_VIEWNAV_JAVA.finditer(unit.body):
        var = match.groupdict().get("var") or match.groupdict().get("var2")
        if not var:
            continue
        if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", unit.body, re.I):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-015",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=92,
                impact=(
                    f"ViewNavigator/ViewEntryCollection `{var}` is created without `.recycle()`. "
                    "Orphaned navigators hold NIF locks and exhaust the handle table."
                ),
                remediation=remediation_template("DOM-015", unit.language),
                action=f"Recycle child entries then `{var}.recycle()` after the loop.",
                handle_lifecycle_warning=f"Line {line}: navigator/collection `{var}` never recycled.",
            )
        )
    return findings


def detect_dom016(unit: CodeUnit) -> list[Finding]:
    """db.search / FTSearch inside loops without recycling the collection."""
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return []
    if not RE_LOOP.search(unit.body):
        return []
    findings: list[Finding] = []
    for match in RE_SEARCH_JAVA.finditer(unit.body):
        var = match.group("var")
        meth = match.group("meth")
        # Rough: search call should be inside loop — require a loop keyword before match
        before = unit.body[max(0, match.start() - 400) : match.start()]
        if not re.search(r"\b(?:for|while)\b", before, re.I):
            continue
        after = unit.body[match.end() : match.end() + 500]
        if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", after, re.I):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-016",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=90,
                impact=(
                    f"In-loop `{meth}` assigns collection `{var}` without `.recycle()`. "
                    "Search collections are heavy native objects and leak per iteration."
                ),
                remediation=remediation_template("DOM-016", unit.language),
                action=f"Recycle `{var}` before the next loop iteration.",
                handle_lifecycle_warning=f"Line {line}: `{var}` from {meth} inside a loop is never recycled.",
            )
        )
    return findings


RE_EMBEDDED_JAVA = re.compile(
    r"""(?:\b(?:EmbeddedObject|NotesEmbeddedObject)\b\s+(?P<var>\w+)\s*=)"""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth>getEmbeddedObject|getObjects|GetEmbeddedObject|GetObjects)\s*\(""",
    re.I | re.X,
)
RE_ENTRY_GET_DOC = re.compile(
    r"""(?P<doc>\w+)\s*=\s*(?P<entry>\w+)\s*\.\s*getDocument\s*\(\s*\)""",
    re.I,
)
RE_ALL_DOCS_BY_KEY = re.compile(
    r"""(?:\bDocumentCollection\b\s+(?P<var>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth>getAllDocumentsByKey|getAllUnreadDocuments|FTSearchRange)\s*\()"""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth2>getAllDocumentsByKey|getAllUnreadDocuments|FTSearchRange)\s*\(""",
    re.I | re.X,
)
RE_BAD_SESSION_DB_RECYCLE = re.compile(
    r"""(?:(?P<sess>\b(?:session|dominoSession|notesSession)\b)\s*\.\s*recycle\s*\()"""
    r"""|(?:getCurrentDatabase\s*\([^)]*\)\s*\.\s*recycle\s*\()"""
    r"""|(?P<cdb>\b(?:currentDatabase|currDb|currentDb)\b)\s*\.\s*recycle\s*\("""
    r"""|(?P<xspDb>\bdatabase\b)\s*\.\s*recycle\s*\("""
    r"""|(?P<naf>\bdominoNAF\b)\s*\.\s*recycle\s*\(""",
    re.I | re.X,
)
RE_STREAM_JAVA = re.compile(
    r"""(?:\b(?:Stream|NotesStream)\b\s+(?P<var>\w+)\s*=)"""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*(?P<meth>createStream|CreateStream)\s*\(""",
    re.I | re.X,
)

# DOM-022: parent collection/vector/stream wrapper after children are recycled
RE_WRAPPER_ALLOC = re.compile(
    r"""(?:\b(?:DocumentCollection|ViewEntryCollection|ViewNavigator|NotesDocumentCollection|
        NotesViewEntryCollection|NotesViewNavigator)\b\s+(?P<var>\w+)\s*=)"""
    r"""|(?P<var2>\w+)\s*=\s*\w+\s*\.\s*
        (?P<meth>search|FTSearch|FTSearchRange|getAllDocumentsByKey|getAllUnreadDocuments|
            getAllEntries|createViewNav|createViewNavFrom|getAllEntriesByKey|
            getItemValueDateTimeArray)\s*\("""
    r"""|(?:\bVector\b\s+(?P<vec>\w+)\s*=\s*\w+\s*\.\s*
        (?P<vmeth>getItemValueDateTimeArray|getItemValue|getColumnValues)\s*\()""",
    re.I | re.X,
)

# DOM-023: bean / scope persistence of live NotesBase handles
RE_BEAN_HANDLE_FIELD = re.compile(
    r"""(?P<mod>private|protected|public)\s+(?:static\s+)?(?:transient\s+)?
        (?:lotus\.domino\.)?
        (?P<type>Session|Database|Document|View|ViewEntry|DocumentCollection|ViewEntryCollection|
            ViewNavigator|NotesBase|DateTime|Item|MIMEEntity|EmbeddedObject|Stream)\s+
        (?P<field>\w+)\s*[;=]""",
    re.I | re.X,
)
RE_BEAN_MARKER = re.compile(
    r"""@ManagedBean\b|@Name\s*\(|@SessionScoped\b|@ViewScoped\b|@ApplicationScoped\b|
        @RequestScoped\b|faces-config\.xml|ManagedBean|sessionScope\.(?:put|set)|
        viewScope\.(?:put|set)|applicationScope\.(?:put|set)""",
    re.I | re.X,
)
RE_SCOPE_PUT_HANDLE = re.compile(
    r"""(?:sessionScope|viewScope|applicationScope)\s*\.\s*(?:put|set)\s*\(\s*[^,]+,\s*
        (?P<expr>[^)]*(?:Document|Database|View|Session|ViewEntry|doc|db|view)\w*)""",
    re.I | re.X,
)


def _java_like_unit(unit: CodeUnit) -> bool:
    lang = (unit.language or "").lower()
    if "lotus" in lang or lang in {"ls", "lss", "notes"}:
        return False
    return True


def _var_recycled(body: str, var: str, *, after: int | None = None) -> bool:
    text = body if after is None else body[after:]
    return bool(re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", text, re.I))


def detect_dom017(unit: CodeUnit) -> list[Finding]:
    """Un-recycled EmbeddedObject / attachment handles (Java/SSJS)."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    for match in RE_EMBEDDED_JAVA.finditer(unit.body):
        var = match.group("var") or match.group("var2")
        if not var:
            continue
        meth = match.groupdict().get("meth") or "getEmbeddedObject"
        if _var_recycled(unit.body, var):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-017",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=88,
                impact=(
                    f"`{meth}` yields EmbeddedObject handle `{var}` without `.recycle()`. "
                    "Attachment objects pin native C-API slots and leak badly inside attachment loops."
                ),
                remediation=remediation_template("DOM-017", unit.language),
                action=f"Recycle `{var}` in finally after reading bytes / file path.",
                handle_lifecycle_warning=f"Line {line}: EmbeddedObject `{var}` never recycled.",
            )
        )
    return findings


def detect_dom018(unit: CodeUnit) -> list[Finding]:
    """ViewEntry.getDocument() without recycling the Document (especially in loops)."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    for match in RE_ENTRY_GET_DOC.finditer(unit.body):
        doc_var = match.group("doc")
        entry_var = match.group("entry")
        # Skip obvious non-entry receivers
        if entry_var.lower() in {"db", "database", "view", "session", "doc", "document"}:
            continue
        if _var_recycled(unit.body, doc_var, after=match.end()):
            continue
        before = unit.body[max(0, match.start() - 500) : match.start()]
        in_loop = bool(re.search(r"\b(?:for|while)\b", before, re.I))
        # Prefer entry walk context
        if not re.search(
            rf"\b{re.escape(entry_var)}\b.*\b(?:getNextEntry|getFirstEntry|ViewEntry)\b"
            rf"|\bViewEntry\b.*\b{re.escape(entry_var)}\b"
            rf"|\b{re.escape(entry_var)}\s*=\s*\w+\s*\.\s*get(?:Next|First)Entry",
            unit.body,
            re.I | re.S,
        ) and not re.search(r"\bViewEntry\b", unit.body, re.I):
            # Still flag if receiver looks like entry/ve/navEntry
            if not re.search(r"entry|ve\b|nav", entry_var, re.I):
                continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-018",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=90 if in_loop else 82,
                in_loop=in_loop,
                impact=(
                    f"`{entry_var}.getDocument()` allocates Document `{doc_var}` without `.recycle()`. "
                    "Entry walks that materialize documents are among the fastest ways to exhaust "
                    "the HTTP-task handle table — recycle the Document every iteration (and the entry)."
                ),
                remediation=remediation_template("DOM-018", unit.language, has_loop=in_loop),
                action=f"Recycle `{doc_var}` each iteration; then recycle `{entry_var}` before advancing.",
                handle_lifecycle_warning=(
                    f"Line {line}: Document `{doc_var}` from ViewEntry.getDocument() never recycled."
                ),
            )
        )
    return findings


def detect_dom019(unit: CodeUnit) -> list[Finding]:
    """getAllDocumentsByKey / unread collections without recycle."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    for match in RE_ALL_DOCS_BY_KEY.finditer(unit.body):
        var = match.group("var") or match.group("var2")
        meth = match.group("meth") or match.group("meth2") or "getAllDocumentsByKey"
        if not var:
            continue
        if _var_recycled(unit.body, var):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-019",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=90,
                impact=(
                    f"`{meth}` returns DocumentCollection `{var}` without `.recycle()`. "
                    "Multi-doc collections hold many child handles; leaking them is high-impact."
                ),
                remediation=remediation_template("DOM-019", unit.language),
                action=f"Walk `{var}` with next-doc recycle, then `{var}.recycle()`.",
                handle_lifecycle_warning=f"Line {line}: collection `{var}` from {meth} never recycled.",
            )
        )
    return findings


def detect_dom020(unit: CodeUnit) -> list[Finding]:
    """Dangerous recycle of Session or current Database (shared platform handles)."""
    if not _java_like_unit(unit):
        return []
    from analytics.code_auditor.snippets import normalize_language

    lang = (unit.language or "").lower()
    lang_n = normalize_language(unit.language)
    findings: list[Finding] = []
    for match in RE_BAD_SESSION_DB_RECYCLE.finditer(unit.body):
        gd = match.groupdict()
        if gd.get("naf"):
            # Covered by DOM-024 (dominoNAF) — avoid double-reporting
            continue
        if gd.get("xspDb"):
            # Bare `database.recycle()` — XPages/SSJS antipattern; skip normal Java locals.
            if lang_n not in {"ssjs", "javascript", "xpages", "jscript"}:
                before = unit.body[: match.start()]
                if re.search(
                    r"\bDatabase\s+database\b|\bdatabase\s*=\s*\w+\s*\.\s*getDatabase\s*\(",
                    before,
                    re.I,
                ):
                    continue
                if "java" in lang and "xpage" not in lang and "xsp" not in lang:
                    continue
        evidence = _snippet(unit.body, match.start())
        target = gd.get("sess") or gd.get("cdb") or gd.get("xspDb") or "getCurrentDatabase()"
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-020",
                unit,
                line=line,
                evidence=evidence,
                confidence=93,
                impact=(
                    f"Recycling `{target}` releases a platform-owned / shared handle. "
                    "This can crash the HTTP task, invalidate later requests, or orphan child objects. "
                    "Never recycle Session or the current database — only handles you opened."
                ),
                remediation=remediation_template("DOM-020", unit.language),
                action="Remove this recycle; only recycle Database/View/Document instances you opened.",
                handle_lifecycle_warning=(
                    f"Line {line}: dangerous recycle of shared Session/current Database handle."
                ),
            )
        )
    return findings


def detect_dom021(unit: CodeUnit) -> list[Finding]:
    """Un-recycled Stream / NotesStream handles."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    for match in RE_STREAM_JAVA.finditer(unit.body):
        var = match.group("var") or match.group("var2")
        if not var:
            continue
        if _var_recycled(unit.body, var):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-021",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=85,
                impact=(
                    f"Stream `{var}` is allocated without `.recycle()`. "
                    "Streams hold native I/O handles; leak risk rises when streams are opened per document."
                ),
                remediation=remediation_template("DOM-021", unit.language),
                action=f"Close and recycle `{var}` in finally after write/read.",
                handle_lifecycle_warning=f"Line {line}: Stream `{var}` never recycled.",
            )
        )
    return findings


def detect_dom022(unit: CodeUnit) -> list[Finding]:
    """Children recycled in a walk, but parent Collection/Vector/Navigator left open."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in RE_WRAPPER_ALLOC.finditer(unit.body):
        gd = match.groupdict()
        var = gd.get("var") or gd.get("var2") or gd.get("vec")
        if not var or var in seen:
            continue
        meth = gd.get("meth") or gd.get("vmeth") or "collection"
        if _var_recycled(unit.body, var):
            continue
        after = unit.body[match.end() :]
        child_recycle = bool(
            re.search(
                r"""(?:\b(?:doc|document|entry|ve|item|dt|dateTime|next)\w*\s*\.\s*recycle\s*\()"""
                r"""|(?:\.recycle\s*\(\s*\))""",
                after,
                re.I | re.X,
            )
        )
        walk = bool(
            re.search(
                r"getNext(?:Document|Entry|Category)\s*\(|getFirst(?:Document|Entry)\s*\(",
                after,
                re.I,
            )
        )
        if not (child_recycle and walk):
            continue
        before = unit.body[max(0, match.start() - 400) : match.start()]
        in_loop = bool(re.search(r"\b(?:for|while)\b", before + after[:200], re.I))
        seen.add(var)
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-022",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=90 if in_loop else 84,
                in_loop=in_loop,
                impact=(
                    f"Wrapper `{var}` from `{meth}` is left un-recycled after child handles are "
                    "recycled in the walk. DocumentCollection / ViewEntryCollection / ViewNavigator / "
                    "DateTime Vector parents still pin native slots until the wrapper is recycled in finally."
                ),
                remediation=remediation_template("DOM-022", unit.language, has_loop=in_loop),
                action=f"After the loop, recycle wrapper `{var}` in a finally block.",
                handle_lifecycle_warning=(
                    f"Line {line}: collection/vector wrapper `{var}` never recycled after child cleanup."
                ),
            )
        )
    return findings


def detect_dom023(unit: CodeUnit) -> list[Finding]:
    """Managed Bean / scope map persists live lotus.domino.NotesBase across requests."""
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    body = unit.body or ""
    beanish = bool(RE_BEAN_MARKER.search(body)) or any(
        tok in (unit.element_name or "").lower()
        for tok in ("bean", "controller", "managed", "scope")
    )

    if beanish:
        for match in RE_BEAN_HANDLE_FIELD.finditer(body):
            field = match.group("field")
            typ = match.group("type")
            line_start = body.rfind("\n", 0, match.start()) + 1
            prefix = body[line_start : match.start()]
            if prefix.count("{") or prefix.strip().startswith("//"):
                continue
            line = _line_of(body, match.start(), unit.start_line)
            findings.append(
                _finding(
                    "DOM-023",
                    unit,
                    line=line,
                    evidence=_snippet(body, match.start()),
                    confidence=88,
                    impact=(
                        f"Member field `{field}` ({typ}) holds a live Domino handle on a Managed Bean / "
                        "long-lived class. XPages scope persistence across HTTP requests pins C-API memory "
                        "and shares unsafe state between users/threads."
                    ),
                    remediation=remediation_template("DOM-023", unit.language),
                    action=f"Store UNID/strings/DTOs in `{field}`; fetch handles per request.",
                    handle_lifecycle_warning=(
                        f"Line {line}: scoped/bean field `{field}` retains live `{typ}` handle."
                    ),
                )
            )

    for match in RE_SCOPE_PUT_HANDLE.finditer(body):
        line = _line_of(body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-023",
                unit,
                line=line,
                evidence=_snippet(body, match.start()),
                confidence=90,
                impact=(
                    "Putting a live Domino handle into sessionScope/viewScope/applicationScope retains "
                    "native C-API memory for the lifetime of the scope and can leak across requests."
                ),
                remediation=remediation_template("DOM-023", unit.language),
                action="Put UNIDs or serializable values into scopes — never live NotesBase instances.",
                handle_lifecycle_warning=f"Line {line}: scope map stores a live Domino handle.",
            )
        )
    return findings


def detect_dom024(unit: CodeUnit) -> list[Finding]:
    """CRITICAL: recycle of platform-owned globals including dominoNAF.

    Inverse policy (AI + docs): do NOT require .recycle() on session /
    XPages ``database`` / getCurrentDatabase() / dominoNAF.
    """
    if not _java_like_unit(unit):
        return []
    findings: list[Finding] = []
    for match in RE_BAD_SESSION_DB_RECYCLE.finditer(unit.body):
        gd = match.groupdict()
        if not gd.get("naf"):
            continue
        target = gd.get("naf") or "dominoNAF"
        line = _line_of(unit.body, match.start(), unit.start_line)
        findings.append(
            _finding(
                "DOM-024",
                unit,
                line=line,
                evidence=_snippet(unit.body, match.start()),
                confidence=97,
                impact=(
                    f"Recycling platform-owned `{target}` is forbidden. session / XPages database / "
                    "getCurrentDatabase() / dominoNAF are framework-managed; recycling them can crash "
                    "nHTTP. Conversely, missing .recycle() on those globals is NOT a leak."
                ),
                remediation=remediation_template("DOM-024", unit.language),
                action=f"Remove `{target}.recycle()`; never dispose platform globals.",
                handle_lifecycle_warning=f"Line {line}: illegal recycle of platform global `{target}`.",
            )
        )
    return findings


DETECTORS = [
    detect_dom001,
    detect_dom002,
    detect_dom003,
    detect_dom004,
    detect_dom005,
    detect_dom006,
    detect_dom007,
    detect_dom008,
    detect_dom009,
    detect_dom010,
    detect_dom011,
    detect_dom012,
    detect_dom013,
    detect_dom014,
    detect_dom015,
    detect_dom016,
    detect_dom017,
    detect_dom018,
    detect_dom019,
    detect_dom020,
    detect_dom021,
    detect_dom022,
    detect_dom023,
    detect_dom024,
]


def run_rule_engine(
    units: Iterable[CodeUnit],
    *,
    graph: dict | None = None,
    edges: list | None = None,
) -> list[Finding]:
    from analytics.code_auditor.ext_rules import EXT_DETECTORS
    from analytics.code_auditor.ext_rules import bind_helpers as bind_ext
    from analytics.code_auditor.form_rules import (
        FORM_DETECTORS,
        detect_form004,
        detect_form004_from_graph,
    )
    from analytics.code_auditor.form_rules import bind_helpers as bind_form
    from analytics.code_auditor.ls_ext_rules import LS_EXT_DETECTORS
    from analytics.code_auditor.ls_ext_rules import bind_helpers as bind_ls_ext
    from analytics.code_auditor.ownership_rules import bind_helpers as bind_own
    from analytics.code_auditor.ownership_rules import run_ownership_detectors
    from analytics.code_auditor.perf_rules import PERF_DETECTORS
    from analytics.code_auditor.perf_rules import bind_helpers as bind_perf
    from analytics.code_auditor.sec_rules import SEC_DETECTORS
    from analytics.code_auditor.sec_rules import bind_helpers as bind_sec

    unit_list = list(units)
    # LS-DOM-* detectors are not wired: LotusScript does not share Java C-API handle exhaustion.
    # LS-EXT-* are a narrow exception (JavaSession / OpenConnection).
    bind_perf(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_sec(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_form(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_own(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_ext(finding=_finding, line_of=_line_of, snippet=_snippet)
    bind_ls_ext(finding=_finding, line_of=_line_of, snippet=_snippet)

    findings: list[Finding] = []
    for unit in unit_list:
        # Narrow LotusScript exception: external bridge / DB2 connection leaks only.
        if is_lotusscript_language(unit.language):
            for detector in LS_EXT_DETECTORS:
                findings.extend(detector(unit))
            # Summary-flag antipatterns appear in LS agents too (32KB assessment findings).
            findings.extend(detect_form004(unit))
            continue
        # CSJS is browser-side — not C-API handle exhaustion / server JDBC
        if is_client_javascript(
            unit.language, event=unit.event, element_name=unit.element_name
        ):
            continue
        for detector in DETECTORS:
            findings.extend(detector(unit))
        for detector in PERF_DETECTORS:
            findings.extend(detector(unit))
        for detector in SEC_DETECTORS:
            findings.extend(detector(unit))
        for detector in FORM_DETECTORS:
            findings.extend(detector(unit))
        for detector in EXT_DETECTORS:
            findings.extend(detector(unit))
    # Design-time summary-field budget (graph forms)
    findings.extend(detect_form004_from_graph(graph))
    # Cross-unit / cross-library ownership (needs full set + optional graph edges)
    findings.extend(run_ownership_detectors(unit_list, graph=graph, edges=edges))
    # Hard filter: never surface LotusScript C-API findings — allow LS-EXT-* and FORM-004.
    findings = [
        f
        for f in findings
        if (not is_lotusscript_language(f.language))
        or (f.rule_id or "").startswith("LS-EXT-")
        or (f.rule_id or "") == "FORM-004"
    ]
    # Assign stable IDs
    for idx, finding in enumerate(findings, start=1):
        finding.id = f"F-{idx:03d}"
    return findings
