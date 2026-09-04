"""Deterministic Domino memory / handle anti-pattern detectors."""

from __future__ import annotations

import re
from typing import Iterable

from analytics.code_auditor.models import RULE_CATALOG, CodeUnit, Finding
from analytics.code_auditor.snippets import attach_snippet_fields, default_try_finally_remediation

RE_CHAINED_CREATE = re.compile(
    r"""(?P<ev>(?:session|Session|notesSession|NotesSession|uiDoc|uidoc)\s*\.\s*
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
    r"\b(?:lotus\.domino\.)?(?:Session|Database|Document|View|ViewEntry|DocumentCollection|DateTime|Name)\b"
    r"|\bNotes(?:Session|Database|Document|View|ViewEntry|DateTime|Name)\b"
    r"|\.get(?:Database|View|Document|FirstDocument|NextDocument)\s*\(",
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
# LotusScript module-level Static / Public handle fields (not ordinary Dim locals in Subs)
RE_LS_STATIC = re.compile(
    r"(?m)^\s*(?:Static|Public)\s+\w+\s+As\s+Notes(?:Session|Database|Document|View|DateTime|Name)\b",
    re.I,
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
        NotesDatabase|NotesDocument|NotesView|NotesViewEntry|NotesDateTime)\b
        \s+(?P<var>\w+)\s*=
        |(?P<var2>\w+)\s*=\s*(?:\(\s*)?(?:Database|View|Document|Session)
        |\b(?:Set\s+)?(?P<var3>\w+)\s*=\s*.*\.(?:getDatabase|getView|getFirstDocument|getDocumentByKey|
            getAllDocumentsByKey|getAllEntries|createDateTime|createName)\s*\()""",
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

# DOM-012: recycle inside if within a loop-ish region
RE_CONDITIONAL_RECYCLE = re.compile(
    r"""(?:for|while|do)\b[\s\S]{0,400}?
        \bif\s*\([^)]*\)\s*\{[^}]{0,200}?\.\s*recycle\s*\(\s*\)
        |\bIf\b[^\n]{0,120}\n[^\n]{0,120}\.(?:recycle|Remove|Delete)\b""",
    re.I | re.X,
)

# DOM-013: doc = coll.getNextDocument(doc) without prior recycle of doc
RE_UNSAFE_REASSIGN = re.compile(
    r"""(?P<var>\w+)\s*=\s*[\w\.]+\.getNext(?:Document|Entry)\s*\(\s*(?P=var)\s*\)
        |Set\s+(?P<var2>\w+)\s*=\s*[\w\.]+\.GetNext(?:Document|Entry)\s*\(\s*(?P=var2)\s*\)""",
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
) -> Finding:
    meta = RULE_CATALOG[rule_id]
    warning = handle_lifecycle_warning or impact
    rem = remediation.strip() or default_try_finally_remediation(unit.language)
    snippet_fields = attach_snippet_fields(
        unit=unit,
        focus_line=line,
        evidence=evidence,
        remediation=rem,
        handle_lifecycle_warning=warning,
    )
    return Finding(
        id="",  # assigned later
        rule_id=rule_id,
        title=meta["title"],
        severity=(severity or meta["default_severity"]),  # type: ignore[arg-type]
        confidence=confidence,
        source_file=unit.source_file,
        element_name=unit.element_name,
        element_type=unit.element_type,
        language=unit.language,
        line=line,
        evidence=evidence,
        technical_impact=impact,
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
    if not RE_LOOP.search(unit.body) or not RE_GET_NEXT.search(unit.body):
        return []
    # Loop with getNext* but no recycle nearby → high risk
    if RE_RECYCLE.search(unit.body):
        # Still flag if recycle appears only outside obvious loop body heuristic
        # Medium confidence when recycle exists somewhere
        confidence = 72
        severity = "HIGH"
    else:
        confidence = 92
        severity = "CRITICAL"
    match = RE_GET_NEXT.search(unit.body)
    assert match is not None
    return [
        _finding(
            "DOM-002",
            unit,
            line=_line_of(unit.body, match.start(), unit.start_line),
            evidence=_snippet(unit.body, match.start(), 260),
            confidence=confidence,
            severity=severity,
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
                    "OpenNTF Domino API manages recycle automatically. Manual .recycle() destroys shared "
                    "underlying handles, causing double-recycle exceptions, thread stalls, and Metaspace churn."
                ),
                remediation=(
                    "// Remove manual recycle when using org.openntf.domino.*\n"
                    "// ODA AutoMime / Factory handles disposal at the end of the request.\n"
                    "Document doc = db.getDocumentByUNID(unid);\n"
                    "String subject = doc.getItemValueString(\"Subject\");"
                ),
                action="Delete explicit .recycle() calls on ODA-wrapped objects.",
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
            remediation=default_try_finally_remediation(unit.language),
            action="Wrap Domino object creation in try/finally and recycle every allocated handle.",
            handle_lifecycle_warning=(
                f"Line {line}: Native object `{var}` initialized without guaranteed recycle() in a finally block."
            ),
        )
    ]


def detect_dom011(unit: CodeUnit) -> list[Finding]:
    """Parent recycled while child handles may still be live."""
    findings: list[Finding] = []
    for match in RE_PARENT_RECYCLE.finditer(unit.body):
        parent = match.group("parent")
        after = unit.body[match.end() : match.end() + 400]
        child_match = RE_CHILD_USE.search(after)
        # Also look slightly before for child acquisition from this parent
        before = unit.body[max(0, match.start() - 500) : match.start()]
        acquired_child = bool(
            re.search(
                rf"\b(?:doc|entry|document)\b[^\n]{{0,80}}{re.escape(parent)}\s*\.\s*get",
                before,
                re.I,
            )
            or re.search(
                rf"{re.escape(parent)}\s*\.\s*get(?:First|Next)?(?:Document|Entry)",
                before,
                re.I,
            )
        )
        if not (child_match or acquired_child):
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
    match = RE_CONDITIONAL_RECYCLE.search(unit.body)
    if not match:
        # Secondary heuristic: recycle appears inside if but getNext exists
        if RE_GET_NEXT.search(unit.body) and re.search(
            r"if\s*\([^\)]*\)\s*\{[^}]*\.recycle\s*\(", unit.body, re.I | re.S
        ):
            match = re.search(r"if\s*\([^\)]*\)\s*\{[^}]*\.recycle\s*\(", unit.body, re.I | re.S)
        else:
            return []
    assert match is not None
    line = _line_of(unit.body, match.start(), unit.start_line)
    return [
        _finding(
            "DOM-012",
            unit,
            line=line,
            evidence=_snippet(unit.body, match.start(), 280),
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
    """Re-assign loop variable via getNext*(sameVar) without recycling first."""
    findings: list[Finding] = []
    for match in RE_UNSAFE_REASSIGN.finditer(unit.body):
        var = match.group("var") or match.group("var2") or "doc"
        # If recycle of that var appears in the 120 chars before assignment, treat as safer
        prelude = unit.body[max(0, match.start() - 160) : match.start()]
        if re.search(rf"\b{re.escape(var)}\s*\.\s*recycle\s*\(", prelude, re.I):
            continue
        if re.search(rf"\bDelete\s+{re.escape(var)}\b", prelude, re.I):
            continue
        line = _line_of(unit.body, match.start(), unit.start_line)
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
]


def run_rule_engine(units: Iterable[CodeUnit]) -> list[Finding]:
    findings: list[Finding] = []
    for unit in units:
        for detector in DETECTORS:
            findings.extend(detector(unit))
    # Assign stable IDs
    for idx, finding in enumerate(findings, start=1):
        finding.id = f"F-{idx:03d}"
    return findings
