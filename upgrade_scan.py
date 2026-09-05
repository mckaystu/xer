#!/usr/bin/env python3
"""
Domino DXL Upgrade Scan — language-scoped database / API reference counters.

Scans DXL XML and applies **Java rules only to Java/javaproject blocks** and
**LotusScript rules only to LotusScript blocks**, so LS ``NotesDatabase`` /
``GetDatabase`` hits are never double-counted as Java ``getDatabase`` references.

Examples
--------
  python3 upgrade_scan.py dxl_input_fromboss/Code_FrombossRest.dxl
  python3 upgrade_scan.py ./dxl_input --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

XER_ROOT = Path(__file__).resolve().parent

# Language containers in Domino DXL / ODP
LS_TAGS = frozenset({"lotusscript", "ls", "lss"})
JAVA_TAGS = frozenset({"java", "javaproject", "javaclass", "code.javaproject"})
JS_TAGS = frozenset({"javascript", "jscript", "ssjs", "script"})
CODE_LEAF_TAGS = LS_TAGS | JAVA_TAGS | JS_TAGS | frozenset({"formula", "source"})

# Language-scoped patterns (must NOT run across languages)
LS_DB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("NotesDatabase_ctor", re.compile(r"\bNotesDatabase\s*\(", re.I)),
    ("GetDatabase", re.compile(r"\bGetDatabase\s*\(", re.I)),
    ("CurrentDatabase", re.compile(r"\bCurrentDatabase\b", re.I)),
    ("OpenDatabase", re.compile(r"\bOpenDatabase\s*\(", re.I)),
    ("New_NotesDatabase", re.compile(r"\bNew\s+NotesDatabase\b", re.I)),
]
JAVA_DB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("getDatabase", re.compile(r"\bgetDatabase\s*\(")),
    ("Database_open", re.compile(r"\bDatabase\s*\.\s*open\s*\(")),
    ("session_getDatabase", re.compile(r"\bsession\s*\.\s*getDatabase\s*\(", re.I)),
    ("lotus_domino_Database", re.compile(r"\blotus\.domino\.Database\b")),
]


@dataclass
class LangHit:
    language: str
    pattern: str
    count: int
    samples: list[str] = field(default_factory=list)


@dataclass
class UpgradeScanReport:
    source: str
    blocks_by_language: dict[str, int]
    hits: list[LangHit]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "blocks_by_language": self.blocks_by_language,
            "hits": [asdict(h) for h in self.hits],
            "totals_by_language": self.totals_by_language(),
            "notes": self.notes,
        }

    def totals_by_language(self) -> dict[str, int]:
        totals: dict[str, int] = defaultdict(int)
        for h in self.hits:
            totals[h.language] += h.count
        return dict(totals)


def _local_tag(elem: ET.Element) -> str:
    tag = elem.tag
    if "}" in tag:
        tag = tag.rsplit("}", 1)[-1]
    return tag.lower()


def _text_content(elem: ET.Element) -> str:
    parts: list[str] = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(_text_content(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _normalize_language(tag: str, elem: ET.Element | None = None) -> str | None:
    t = tag.lower()
    if t in LS_TAGS:
        return "lotusscript"
    if t in JAVA_TAGS or t == "javaproject":
        return "java"
    if t in JS_TAGS:
        # <script language="Java"> vs JavaScript
        if elem is not None:
            lang_attr = ""
            for key, value in elem.attrib.items():
                if key.lower().endswith("language") or key.lower() == "type":
                    lang_attr = (value or "").lower()
            if "lotus" in lang_attr:
                return "lotusscript"
            if lang_attr in {"java", "text/java"} or lang_attr.endswith("/java"):
                return "java"
            if "javascript" in lang_attr or lang_attr in {"js", "ssjs", "jscript", "text/javascript"}:
                return "javascript"
        return "javascript"
    if t == "formula":
        return "formula"
    if t == "source":
        return "java"  # ODP java source often under <source>
    return None


def _ancestor_language(elem: ET.Element, parent_map: dict[ET.Element, ET.Element]) -> str | None:
    """Walk parents for an explicit language container (<lotusscript>, <javaproject>, …)."""
    cur: ET.Element | None = elem
    while cur is not None:
        tag = _local_tag(cur)
        if tag == "javaproject":
            return "java"
        lang = _normalize_language(tag, cur)
        if lang and tag in CODE_LEAF_TAGS | {"javaproject"}:
            return lang
        cur = parent_map.get(cur)
    return None


def extract_language_blocks(root: ET.Element) -> list[tuple[str, str]]:
    """Return (language, body) pairs from DXL with strict parent-language scoping."""
    parent_map = {child: parent for parent in root.iter() for child in parent}
    blocks: list[tuple[str, str]] = []
    seen: set[tuple[str, int, int]] = set()

    for elem in root.iter():
        tag = _local_tag(elem)
        lang = _normalize_language(tag, elem)
        if not lang:
            # e.g. raw text under javaproject without a java child tag
            parent_lang = _ancestor_language(elem, parent_map)
            if parent_lang == "java" and tag in {"code", "source", "text"}:
                lang = "java"
            else:
                continue

        # Prefer leaf language tags; skip formula for DB API upgrade counts
        if lang == "formula":
            continue

        body = _text_content(elem).strip()
        if len(body) < 8:
            continue

        # De-dupe nested wrappers (e.g. <code><lotusscript>…</lotusscript></code>)
        key = (lang, hash(body[:200]), len(body))
        if key in seen:
            continue
        # If parent is also a code leaf with same text, skip outer
        parent = parent_map.get(elem)
        if parent is not None:
            ptag = _local_tag(parent)
            if ptag in CODE_LEAF_TAGS and _text_content(parent).strip() == body:
                continue
        seen.add(key)
        blocks.append((lang, body))

    return blocks


def _count_patterns(
    body: str,
    patterns: list[tuple[str, re.Pattern[str]]],
    *,
    language: str,
    bucket: dict[tuple[str, str], LangHit],
) -> None:
    for name, pattern in patterns:
        matches = list(pattern.finditer(body))
        if not matches:
            continue
        key = (language, name)
        hit = bucket.get(key)
        if hit is None:
            hit = LangHit(language=language, pattern=name, count=0, samples=[])
            bucket[key] = hit
        hit.count += len(matches)
        for m in matches[:3]:
            sample = body[max(0, m.start() - 20) : m.end() + 40].replace("\n", " ")
            if sample not in hit.samples:
                hit.samples.append(sample[:120])


def scan_dxl_text(text: str, *, source: str) -> UpgradeScanReport:
    notes: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        try:
            root = ET.fromstring(f"<dxl>{text}</dxl>")
            notes.append("Wrapped non-rooted DXL fragment in <dxl>.")
        except ET.ParseError as exc:
            return UpgradeScanReport(
                source=source,
                blocks_by_language={},
                hits=[],
                notes=[f"XML parse error: {exc}"],
            )

    blocks = extract_language_blocks(root)
    blocks_by_language: dict[str, int] = defaultdict(int)
    bucket: dict[tuple[str, str], LangHit] = {}

    for lang, body in blocks:
        blocks_by_language[lang] += 1
        if lang == "lotusscript":
            _count_patterns(body, LS_DB_PATTERNS, language="lotusscript", bucket=bucket)
        elif lang == "java":
            _count_patterns(body, JAVA_DB_PATTERNS, language="java", bucket=bucket)
        # javascript: intentionally no Domino DB API upgrade counters here

    # Guardrail note if someone previously double-counted
    ls_get = bucket.get(("lotusscript", "GetDatabase"))
    java_get = bucket.get(("java", "getDatabase"))
    if ls_get and java_get:
        notes.append(
            "Language scoping active: LotusScript GetDatabase and Java getDatabase "
            "are counted separately (no cross-language duplication)."
        )
    elif ls_get and not java_get:
        notes.append(
            "LotusScript database references found; no Java getDatabase hits "
            "(LS is not labeled as Java)."
        )

    hits = sorted(bucket.values(), key=lambda h: (h.language, h.pattern))
    return UpgradeScanReport(
        source=source,
        blocks_by_language=dict(blocks_by_language),
        hits=hits,
        notes=notes,
    )


def scan_path(path: Path) -> UpgradeScanReport:
    path = Path(path)
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="ignore")
        return scan_dxl_text(text, source=str(path))

    merged_blocks: dict[str, int] = defaultdict(int)
    merged_hits: dict[tuple[str, str], LangHit] = {}
    notes: list[str] = []
    files = sorted([*path.rglob("*.dxl"), *path.rglob("*.xml")])
    for fp in files:
        part = scan_dxl_text(fp.read_text(encoding="utf-8", errors="ignore"), source=str(fp))
        for lang, n in part.blocks_by_language.items():
            merged_blocks[lang] += n
        for hit in part.hits:
            key = (hit.language, hit.pattern)
            if key not in merged_hits:
                merged_hits[key] = LangHit(
                    language=hit.language, pattern=hit.pattern, count=0, samples=[]
                )
            merged_hits[key].count += hit.count
            for s in hit.samples:
                if s not in merged_hits[key].samples and len(merged_hits[key].samples) < 5:
                    merged_hits[key].samples.append(s)
        notes.extend(part.notes)
    return UpgradeScanReport(
        source=str(path),
        blocks_by_language=dict(merged_blocks),
        hits=sorted(merged_hits.values(), key=lambda h: (h.language, h.pattern)),
        notes=list(dict.fromkeys(notes)),
    )


def console_summary(report: UpgradeScanReport) -> str:
    lines = [
        f"Upgrade scan: {report.source}",
        f"Blocks by language: {report.blocks_by_language}",
        f"DB-ref totals by language: {report.totals_by_language()}",
        "Hits:",
    ]
    for h in report.hits:
        lines.append(f"  [{h.language}] {h.pattern}: {h.count}")
    for n in report.notes:
        lines.append(f"Note: {n}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Language-scoped Domino DXL upgrade scan")
    parser.add_argument("path", type=Path, help="DXL file or directory")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    args = parser.parse_args(argv)

    report = scan_path(args.path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(console_summary(report))
    return 0 if not any("parse error" in n.lower() for n in report.notes) else 2


if __name__ == "__main__":
    sys.exit(main())
