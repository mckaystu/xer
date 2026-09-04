"""Extract Java / SSJS / XPages / LotusScript code blocks from DXL and pre-filter."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from analytics.code_auditor.models import CodeUnit

CODE_TAGS = {"java", "lotusscript", "javascript", "jscript", "ssjs", "formula", "source", "script"}
INTERESTING_LANGS = {"java", "lotusscript", "javascript", "jscript", "ssjs", "source", "script"}

PREFILTER_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    ("session", re.compile(r"\bsession\b", re.I)),
    ("createDateTime", re.compile(r"createDateTime", re.I)),
    ("createName", re.compile(r"createName", re.I)),
    ("Database", re.compile(r"\b(?:Database|NotesDatabase|getDatabase)\b")),
    ("Document", re.compile(r"\b(?:Document|NotesDocument|getDocument|getNextDocument)\b")),
    ("View", re.compile(r"\b(?:View|NotesView|getView|getNextEntry|ViewEntry)\b")),
    ("recycle", re.compile(r"\.recycle\s*\(", re.I)),
    ("static", re.compile(r"\bstatic\b")),
    ("openntf", re.compile(r"org\.openntf\.domino", re.I)),
    ("lotus.domino", re.compile(r"lotus\.domino", re.I)),
    ("sessionScope", re.compile(r"sessionScope|applicationScope|viewScope", re.I)),
    ("getColumnValues", re.compile(r"getColumnValues?|getColumnValue", re.I)),
    ("Factory", re.compile(r"Factory\.fromLotus", re.I)),
]


def local_tag(elem: ET.Element) -> str:
    tag = elem.tag
    if "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()
    return tag.lower()


def elem_attr(elem: ET.Element, name: str) -> str | None:
    for key, value in elem.attrib.items():
        if key.lower() == name.lower() or key.lower().endswith("}" + name.lower()):
            return value
    return None


def text_content(elem: ET.Element) -> str:
    parts: list[str] = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(text_content(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def prefilter_keywords(body: str) -> list[str]:
    hits: list[str] = []
    for label, pattern in PREFILTER_KEYWORDS:
        if pattern.search(body):
            hits.append(label)
    return hits


def _nearest_named_ancestor(elem: ET.Element, parent_map: dict[ET.Element, ET.Element]) -> tuple[str, str]:
    current: ET.Element | None = elem
    while current is not None:
        tag = local_tag(current)
        name = elem_attr(current, "name") or elem_attr(current, "title")
        if name and tag in {
            "form",
            "subform",
            "view",
            "folder",
            "agent",
            "scriptlibrary",
            "sharedfield",
            "page",
            "frameset",
            "outline",
            "imageresource",
            "database",
            "note",
        }:
            return tag, name
        if tag == "code":
            event = elem_attr(current, "event")
            if event:
                parent = parent_map.get(current)
                if parent is not None:
                    ptag, pname = _nearest_named_ancestor(parent, parent_map)
                    return ptag, f"{pname}/{event}" if pname != "unknown" else event
        current = parent_map.get(current)
    return "unknown", "unknown"


def extract_units_from_dxl_bytes(content: bytes | str, source_file: str) -> list[CodeUnit]:
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="ignore")
    else:
        text = content

    # Recover from common DXL quirks
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Try wrapping fragments
        try:
            root = ET.fromstring(f"<dxl>{text}</dxl>")
        except ET.ParseError:
            return [
                CodeUnit(
                    source_file=source_file,
                    element_name=Path(source_file).name,
                    element_type="file",
                    language="unknown",
                    event=None,
                    body=text,
                    start_line=1,
                    keywords_matched=prefilter_keywords(text),
                )
            ]

    parent_map = {child: parent for parent in root.iter() for child in parent}
    units: list[CodeUnit] = []

    for elem in root.iter():
        tag = local_tag(elem)
        if tag not in CODE_TAGS:
            continue
        # Prefer leaf language tags; skip empty wrappers
        body = text_content(elem).strip()
        if not body or len(body) < 8:
            continue

        language = tag
        event = None
        # If nested under <code event=...>, capture event
        parent = parent_map.get(elem)
        if parent is not None and local_tag(parent) == "code":
            event = elem_attr(parent, "event")
            language = tag if tag != "script" else (elem_attr(elem, "language") or "javascript")
        elif tag in {"script", "source"}:
            language = (elem_attr(elem, "language") or elem_attr(elem, "type") or tag).lower()
            if "javascript" in language or language in {"js", "ssjs", "jscript"}:
                language = "javascript"
            elif "java" in language:
                language = "java"

        if language == "formula":
            # Formula rarely owns C-API handles; skip unless recycle/ODA keywords appear
            kws = prefilter_keywords(body)
            if not any(k in kws for k in ("recycle", "openntf", "lotus.domino", "createDateTime")):
                continue

        element_type, element_name = _nearest_named_ancestor(elem, parent_map)
        # Approximate start line from absolute offset in source text
        snippet = body[:80]
        idx = text.find(snippet)
        start_line = text.count("\n", 0, idx) + 1 if idx >= 0 else 1

        units.append(
            CodeUnit(
                source_file=source_file,
                element_name=element_name,
                element_type=element_type,
                language=language,
                event=event,
                body=body,
                start_line=start_line,
                keywords_matched=prefilter_keywords(body),
            )
        )

    return units


def extract_units_from_path(path: Path) -> list[CodeUnit]:
    path = Path(path)
    if path.is_file():
        files = [path]
    else:
        files = sorted(
            [
                *path.rglob("*.dxl"),
                *path.rglob("*.xml"),
                *path.rglob("*.lss"),
                *path.rglob("*.ls"),
                *path.rglob("*.java"),
                *path.rglob("*.jss"),
                *path.rglob("*.xsp"),
            ]
        )

    units: list[CodeUnit] = []
    for file_path in files:
        raw = file_path.read_bytes()
        suffix = file_path.suffix.lower()
        if suffix in {".lss", ".ls", ".java", ".jss", ".xsp"}:
            body = raw.decode("utf-8", errors="ignore")
            lang = {
                ".lss": "lotusscript",
                ".ls": "lotusscript",
                ".java": "java",
                ".jss": "javascript",
                ".xsp": "xpages",
            }.get(suffix, "unknown")
            units.append(
                CodeUnit(
                    source_file=str(file_path),
                    element_name=file_path.name,
                    element_type="odp_file",
                    language=lang,
                    event=None,
                    body=body,
                    start_line=1,
                    keywords_matched=prefilter_keywords(body),
                )
            )
        else:
            units.extend(extract_units_from_dxl_bytes(raw, str(file_path)))
    return units


def extract_units_from_graph(graph: dict) -> list[CodeUnit]:
    """Build audit units from a stored Xer application graph (no raw DXL needed)."""
    units: list[CodeUnit] = []
    for block in graph.get("business_logic") or []:
        lang = (block.get("language") or "unknown").lower()
        if lang == "formula":
            continue
        body = block.get("body") or ""
        if not body.strip():
            continue
        units.append(
            CodeUnit(
                source_file=block.get("source_file") or "graph",
                element_name=block.get("owner_name") or "unknown",
                element_type=block.get("owner_type") or "unknown",
                language=lang,
                event=block.get("event"),
                body=body,
                start_line=1,
                keywords_matched=prefilter_keywords(body),
            )
        )
    return units


def apply_prefilter(units: Iterable[CodeUnit], *, require_keywords: bool = True) -> list[CodeUnit]:
    out: list[CodeUnit] = []
    for unit in units:
        if require_keywords and not unit.keywords_matched:
            continue
        # Always keep Java/SSJS/LotusScript with keywords
        if unit.language in INTERESTING_LANGS or unit.keywords_matched:
            out.append(unit)
    return out
