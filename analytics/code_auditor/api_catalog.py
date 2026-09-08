"""Shared Domino handle API catalog — allocation + cleanup signals for inventory & rules.

Keep typed Notes*/lotus.domino patterns preferred over bare Document/View names to
reduce Java false positives. Inventory and ownership rules consume this catalog.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------------------
# Catalog entries
# ---------------------------------------------------------------------------

# Types that own C-API / Notes handle table slots (LS Dim / Java typed).
HANDLE_TYPES_LS: tuple[str, ...] = (
    "NotesDocument",
    "NotesView",
    "NotesDatabase",
    "NotesViewEntry",
    "NotesViewNavigator",
    "NotesViewNav",
    "NotesViewEntryCollection",
    "NotesDocumentCollection",
    "NotesItem",
    "NotesRichTextItem",
    "NotesMIMEEntity",
    "NotesStream",
    "NotesName",
    "NotesDateTime",
    "NotesDateRange",
    "NotesHTTPRequest",
    "NotesJSONNavigator",
    "NotesJSONElement",
    "NotesEmbeddedObject",
    "NotesACL",
    "NotesACLEntry",
    "NotesAgent",
    "NotesOutline",
    "NotesRegistration",
)

HANDLE_TYPES_JAVA: tuple[str, ...] = (
    "Document",
    "View",
    "Database",
    "ViewEntry",
    "ViewNavigator",
    "ViewEntryCollection",
    "DocumentCollection",
    "Item",
    "RichTextItem",
    "MIMEEntity",
    "Stream",
    "Name",
    "DateTime",
    "DateRange",
    "NotesDocument",
    "NotesView",
    "NotesDatabase",
    "lotus.domino.Document",
    "lotus.domino.View",
    "lotus.domino.Database",
)

# Method / factory names that allocate handles (language-agnostic word matches).
ALLOC_METHODS: tuple[str, ...] = (
    "GetDocumentByUNID",
    "getDocumentByUNID",
    "GetFirstDocument",
    "getFirstDocument",
    "GetNextDocument",
    "getNextDocument",
    "GetNthDocument",
    "getNthDocument",
    "GetNthEntry",
    "getNthEntry",
    "GetEntryByKey",
    "getEntryByKey",
    "GetNextEntry",
    "getNextEntry",
    "GetAllDocumentsByKey",
    "getAllDocumentsByKey",
    "CreateDocument",
    "createDocument",
    "GetView",
    "getView",
    "GetDatabase",
    "getDatabase",
    "createDateTime",
    "CreateDateTime",
    "createViewNav",
    "CreateViewNav",
    "createViewNavFrom",
    "getAllEntriesByKey",
    "FTSearch",
    "Search",
    "search",
    "createItem",
    "CreateItem",
    "CreateMIMEEntity",
    "createMIMEEntity",
    "CreateRichTextItem",
    "createRichTextItem",
    "CreateStream",
    "createStream",
    "CreateName",
    "createName",
    "CreateHTTPRequest",
    "createHTTPRequest",
    "GetItem",
    "getFirstItem",
    "GetFirstItem",
    "GetMIMEEntity",
    "getMIMEEntity",
)

# Compiled once
_LS_TYPE_ALT = "|".join(re.escape(t) for t in HANDLE_TYPES_LS)
_JAVA_TYPE_ALT = "|".join(
    re.escape(t) for t in sorted(HANDLE_TYPES_JAVA, key=len, reverse=True)
)
_ALLOC_METHOD_ALT = "|".join(re.escape(m) for m in ALLOC_METHODS)

RE_LS_DIM = re.compile(
    rf"(?im)^\s*Dim\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+As\s+(?:New\s+)?({_LS_TYPE_ALT})\b"
)
RE_LS_SET_ALLOC = re.compile(
    rf"(?i)\bSet\s+([A-Za-z_]\w*)\s*=\s*.*?\b({_ALLOC_METHOD_ALT})\s*\("
)
RE_LS_DELETE = re.compile(r"(?i)\bDelete\s+([A-Za-z_]\w*)\b")
RE_LS_RECYCLE = re.compile(
    r"(?i)\b(?:Call\s+)?([A-Za-z_]\w*)\s*\.\s*Recycle\s*\("
)

RE_JAVA_TYPED = re.compile(
    rf"(?m)^\s*(?:final\s+|private\s+|protected\s+|public\s+|static\s+)*"
    rf"(?:{_JAVA_TYPE_ALT})\s+([A-Za-z_]\w*)\s*(?:=\s*[^;]+)?;"
)
RE_JAVA_ASSIGN_ALLOC = re.compile(
    rf"(?i)\b([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\s*\.\s*)?({_ALLOC_METHOD_ALT})\s*\("
)
RE_JAVA_RECYCLE = re.compile(r"(?i)\b([A-Za-z_]\w*)\s*\.\s*recycle\s*\(")
RE_JAVA_DELETE = re.compile(r"(?i)\bDelete\s+([A-Za-z_]\w*)\b")
RE_RECYCLE_LOTUSES = re.compile(r"(?i)\brecycleLotuses\s*\(")

RE_FINALLY = re.compile(r"(?i)\bfinally\b")
RE_IF_BLOCK_HINT = re.compile(r"(?is)\bIf\b.{0,200}?\b(?:Delete\s+\w+|\w+\s*\.\s*Recycle\s*\()", re.I)
RE_JAVA_IF_RECYCLE = re.compile(
    r"(?is)\bif\s*\([^)]*\)\s*\{[^}]{0,240}?\.\s*recycle\s*\("
)

# Broad presence patterns (fallback when vars can't be named)
LS_ALLOCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"\b(?:{_LS_TYPE_ALT})\b", re.I),
    re.compile(rf"\b(?:{_ALLOC_METHOD_ALT})\b"),
]
ALLOCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"\b(?:{_LS_TYPE_ALT})\b", re.I),
    re.compile(r"\blotus\.domino\.\w+\b"),
    re.compile(rf"\b(?:{_ALLOC_METHOD_ALT})\b"),
    # Typed lotus handles — avoid bare \bDocument\b / \bView\b (too noisy)
    re.compile(r"\b(?:NotesDocument|NotesView|NotesDatabase|DocumentCollection|ViewEntryCollection|ViewNavigator|MIMEEntity|RichTextItem)\b"),
]


@dataclass
class CleanupAnalysis:
    allocates: bool
    allocated_vars: list[str]
    cleaned_vars: list[str]
    unclean_vars: list[str]
    recycle_call_count: int
    cleanup_conditional: bool
    has_finally: bool
    status: str  # FunctionStatus string


def is_lotusscript(lang: str) -> bool:
    low = (lang or "").lower()
    return "lotus" in low or low in {"ls", "lss", "notes"}


def body_allocates(body: str, language: str = "") -> bool:
    patterns = LS_ALLOCATION_PATTERNS if is_lotusscript(language) else ALLOCATION_PATTERNS
    return any(p.search(body or "") for p in patterns)


def count_cleanup_statements(body: str, language: str = "") -> int:
    """Count explicit cleanup statements without double-counting overlapping spans."""
    text = body or ""
    if is_lotusscript(language):
        patterns = [RE_LS_RECYCLE, RE_LS_DELETE]
    else:
        patterns = [
            re.compile(r"(?i)\bCall\s+\w+\.recycle\s*\([^)]*\)"),
            re.compile(r"(?i)\.\s*recycle\s*\([^)]*\)"),
            RE_JAVA_DELETE,
            RE_RECYCLE_LOTUSES,
        ]
    occupied: list[tuple[int, int]] = []
    total = 0
    for pattern in patterns:
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if any(not (end <= a or start >= b) for a, b in occupied):
                continue
            occupied.append((start, end))
            total += 1
    return total


def find_allocated_vars(body: str, language: str = "") -> list[str]:
    """Return variables that *receive* a handle allocation (not merely Dim'd)."""
    text = body or ""
    names: set[str] = set()
    if is_lotusscript(language):
        # Dim establishes type, but Set … = Get*/Create* is the allocation signal
        typed: set[str] = set()
        for m in RE_LS_DIM.finditer(text):
            for part in m.group(1).split(","):
                name = part.strip().split()[0] if part.strip() else ""
                if name:
                    typed.add(name)
        for m in RE_LS_SET_ALLOC.finditer(text):
            names.add(m.group(1))
        # Also: Set x = y.GetFirstDocument without method on our list? already covered by ALLOC_METHODS
        # Include Set x = CreateDocument / New NotesDocument
        for m in re.finditer(
            rf"(?i)\bSet\s+([A-Za-z_]\w*)\s*=\s*(?:New\s+)?({_LS_TYPE_ALT})\b",
            text,
        ):
            names.add(m.group(1))
        # If Set assigns from another handle var that was allocated, skip — presence of Get* is enough
        # Dim-only names are intentionally excluded (avoids false PARTIAL on unused Dim db)
        _ = typed  # reserved for future typed-assign refinement
    else:
        for m in RE_JAVA_ASSIGN_ALLOC.finditer(text):
            names.add(m.group(1))
        # Typed declaration with initializer
        for m in re.finditer(
            rf"(?m)^\s*(?:final\s+|private\s+|protected\s+|public\s+|static\s+)*"
            rf"(?:{_JAVA_TYPE_ALT})\s+([A-Za-z_]\w*)\s*=\s*[^;]+;",
            text,
        ):
            names.add(m.group(1))
    return sorted(names)


def find_cleaned_vars(body: str, language: str = "") -> list[str]:
    text = body or ""
    names: set[str] = set()
    if is_lotusscript(language):
        for m in RE_LS_DELETE.finditer(text):
            names.add(m.group(1))
        for m in RE_LS_RECYCLE.finditer(text):
            names.add(m.group(1))
    else:
        for m in RE_JAVA_RECYCLE.finditer(text):
            names.add(m.group(1))
        for m in RE_JAVA_DELETE.finditer(text):
            names.add(m.group(1))
        if RE_RECYCLE_LOTUSES.search(text):
            # Bulk helper — treat all allocated names as cleaned when present
            for v in find_allocated_vars(text, language):
                names.add(v)
    return sorted(names)


def cleanup_looks_conditional(body: str, language: str = "") -> bool:
    """True when cleanup appears only under If and there is no finally."""
    text = body or ""
    if RE_FINALLY.search(text):
        return False
    recycle_count = count_cleanup_statements(text, language)
    if recycle_count == 0:
        return False
    if is_lotusscript(language):
        # Count Delete/Recycle occurrences; if every match is preceded by If nearby, flag
        if RE_IF_BLOCK_HINT.search(text):
            # Unconditional Delete at start of line outside If is rare — use crude check:
            unconditional = re.search(
                r"(?im)^(?!\s*').{0,40}\b(?:Delete\s+\w+|Call\s+\w+\.Recycle\s*\()",
                text,
            )
            # If we also have On Error paths with Exit without Delete, still conditional-ish
            if not unconditional:
                return True
            # All cleanups nested after Then on same structure
            outside_if = re.findall(
                r"(?im)^[ \t]*(?:Delete\s+\w+|Call\s+\w+\.Recycle\s*\([^)]*\))",
                text,
            )
            inside_hint = len(RE_IF_BLOCK_HINT.findall(text))
            if inside_hint and len(outside_if) <= inside_hint:
                # Prefer conditional when If-guarded cleanups dominate
                guarded = len(
                    re.findall(
                        r"(?is)\bIf\b[^\n]{0,120}\n[^\n]{0,120}\b(?:Delete\s+\w+|\w+\.Recycle\s*\()",
                        text,
                    )
                )
                if guarded >= recycle_count:
                    return True
        return False
    if RE_JAVA_IF_RECYCLE.search(text):
        # Any recycle outside if?
        stripped = RE_JAVA_IF_RECYCLE.sub(" ", text)
        if not re.search(r"(?i)\.\s*recycle\s*\(", stripped) and not RE_RECYCLE_LOTUSES.search(stripped):
            return True
    return False


def _transferred_vars(body: str, language: str, unclean: set[str], cleaned: set[str]) -> set[str]:
    """Handle walk pattern: Set doc = nextDoc after Delete doc — nextDoc is not a separate leak."""
    text = body or ""
    transferred: set[str] = set()
    if is_lotusscript(language):
        # Only plain var-to-var Set (not Set x = y.Get…)
        for m in re.finditer(
            r"(?i)\bSet\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*(?![.(])",
            text,
        ):
            left, right = m.group(1), m.group(2)
            if right in unclean and left in cleaned | unclean:
                transferred.add(right)
    else:
        for m in re.finditer(
            r"(?i)\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;",
            text,
        ):
            left, right = m.group(1), m.group(2)
            if right in unclean and left in cleaned | unclean:
                transferred.add(right)
    return transferred


def analyze_handle_cleanup(body: str, language: str = "") -> CleanupAnalysis:
    """Path-aware cleanup classification for inventory."""
    text = body or ""
    allocated = find_allocated_vars(text, language)
    cleaned = find_cleaned_vars(text, language)
    recycle_count = count_cleanup_statements(text, language)
    allocates = bool(allocated) or body_allocates(text, language)
    has_finally = bool(RE_FINALLY.search(text))
    conditional = cleanup_looks_conditional(text, language)

    if not allocates:
        return CleanupAnalysis(
            allocates=False,
            allocated_vars=[],
            cleaned_vars=[],
            unclean_vars=[],
            recycle_call_count=recycle_count,
            cleanup_conditional=False,
            has_finally=has_finally,
            status="SAFE_NO_HANDLES",
        )

    unclean_set = set(allocated) - set(cleaned) if allocated else set()
    if unclean_set and cleaned:
        unclean_set -= _transferred_vars(text, language, unclean_set, set(cleaned))
    unclean = sorted(unclean_set)

    if allocated:
        if not cleaned and recycle_count == 0:
            status = "UNPROTECTED_ALLOCATION"
        elif unclean:
            status = "PARTIAL_CLEANUP"
        elif conditional and not has_finally:
            status = "CONDITIONAL_CLEANUP"
        else:
            status = "PROTECTED"
    else:
        # No named vars — fall back to presence + conditional heuristic
        if recycle_count == 0:
            status = "UNPROTECTED_ALLOCATION"
        elif conditional and not has_finally:
            status = "CONDITIONAL_CLEANUP"
        else:
            status = "PROTECTED"

    return CleanupAnalysis(
        allocates=True,
        allocated_vars=allocated,
        cleaned_vars=cleaned,
        unclean_vars=unclean,
        recycle_call_count=recycle_count,
        cleanup_conditional=conditional,
        has_finally=has_finally,
        status=status,
    )


def returns_handle_type(signature_or_body: str, language: str = "") -> bool:
    text = signature_or_body or ""
    if is_lotusscript(language):
        return bool(re.search(rf"(?i)\bAs\s+(?:{_LS_TYPE_ALT})\b", text))
    return bool(
        re.search(
            rf"(?m)^\s*(?:public|private|protected|static|\s)*({_JAVA_TYPE_ALT})\s+[A-Za-z_]",
            text,
        )
    )


def handle_params(signature: str, language: str = "") -> list[str]:
    """Extract parameter names that are typed as Domino handles."""
    text = signature or ""
    names: list[str] = []
    if is_lotusscript(language):
        for m in re.finditer(
            rf"(?i)\b([A-Za-z_]\w*)\s+As\s+(?:{_LS_TYPE_ALT})\b",
            text,
        ):
            names.append(m.group(1))
    else:
        for m in re.finditer(
            rf"(?i)\b(?:{_JAVA_TYPE_ALT})\s+([A-Za-z_]\w*)\b",
            text,
        ):
            names.append(m.group(1))
    return names


def iter_catalog_summary() -> Iterable[dict[str, object]]:
    yield {"kind": "ls_types", "count": len(HANDLE_TYPES_LS), "items": HANDLE_TYPES_LS}
    yield {"kind": "java_types", "count": len(HANDLE_TYPES_JAVA), "items": HANDLE_TYPES_JAVA}
    yield {"kind": "alloc_methods", "count": len(ALLOC_METHODS), "items": ALLOC_METHODS}
