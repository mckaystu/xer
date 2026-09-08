"""Extract Java / JavaScript / XPage source from Domino DXL ``$FileData`` notes.

On-disk project style NSF exports store ``.java``, ``.xsp``, and ``.jss`` as
``<note>`` file resources with ``$TITLE`` + ``$FileData`` / ``rawitemdata``,
not as ``<java>`` / ``<javascript>`` design tags. Without decoding these,
Handle Exhaustion analysis misses nearly all Java and XPage SSJS.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterable

FILEDATA_ITEM = "$FileData"
CLIENT_JS_ITEM = "$ClientJavaScriptLibrary"

_RE_JS_EL = re.compile(r"#\{\s*javascript\s*:\s*(.*?)\}", re.I | re.S)
_RE_XP_SCRIPT = re.compile(
    r"<(?:xp:)?script\b[^>]*>(.*?)</(?:xp:)?script>",
    re.I | re.S,
)
_RE_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)

_SOURCE_MARKERS = (
    "<?xml",
    "package ",
    "import ",
    "public ",
    "protected ",
    "private ",
    "/**",
    "/*",
    "var ",
    "function ",
    "class ",
    "interface ",
    "//",
)


@dataclass(frozen=True)
class FileDataCode:
    """One extracted source unit from a file-resource note."""

    title: str
    language: str  # java | javascript | xpages
    event: str | None
    body: str
    owner_type: str  # javaclass | xpage | javascript_resource


def _local_tag(elem: ET.Element) -> str:
    tag = elem.tag
    if "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()
    return tag.lower()


def _elem_attr(elem: ET.Element, name: str) -> str | None:
    needle = name.lower()
    for key, val in elem.attrib.items():
        if key.lower() == needle or key.lower().endswith("}" + needle):
            return val
    return None


def _item_text(item: ET.Element) -> str:
    parts: list[str] = []
    for child in item.iter():
        if _local_tag(child) == "text" and child.text:
            parts.append(child.text)
        if _local_tag(child) == "rawitemdata":
            parts.append("".join(child.itertext()))
    if parts:
        return "".join(parts)
    return "".join(item.itertext())


def decode_filedata_bytes(raw: bytes) -> str:
    """Strip Notes CF header and return UTF-8 / latin-1 source text."""
    s_utf = raw.decode("utf-8", errors="ignore")
    for marker in _SOURCE_MARKERS:
        idx = s_utf.find(marker)
        if idx >= 0:
            return s_utf[idx:].replace("\r\n", "\n").replace("\r", "\n").rstrip("\x00").rstrip()
    s_lat = raw.decode("latin-1", errors="ignore")
    for marker in _SOURCE_MARKERS:
        idx = s_lat.find(marker)
        if idx >= 0:
            return s_lat[idx:].replace("\r\n", "\n").replace("\r", "\n").rstrip("\x00").rstrip()
    i = 0
    while i < len(raw) and raw[i] < 32 and raw[i] not in (9, 10, 13):
        i += 1
    while i < len(raw):
        window = raw[i : i + 8]
        if len(window) == 8 and all(32 <= b < 127 or b in (9, 10, 13) for b in window):
            break
        i += 1
    return (
        raw[i:]
        .decode("utf-8", errors="ignore")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .rstrip("\x00")
        .rstrip()
    )


def decode_filedata_chunks(raw_b64_chunks: Iterable[str]) -> str:
    parts: list[str] = []
    for b64 in raw_b64_chunks:
        data = re.sub(r"\s+", "", b64 or "")
        if not data:
            continue
        try:
            raw = base64.b64decode(data, validate=False)
        except Exception:  # noqa: BLE001
            continue
        if raw:
            parts.append(decode_filedata_bytes(raw))
    return "".join(parts).rstrip()


def _note_title(note: ET.Element) -> str | None:
    for item in note:
        if _local_tag(item) != "item":
            continue
        if (_elem_attr(item, "name") or "") != "$TITLE":
            continue
        title = _item_text(item).strip()
        if title:
            return title
    # Descendants (title sometimes nested)
    for item in note.iter():
        if _local_tag(item) != "item":
            continue
        if (_elem_attr(item, "name") or "") != "$TITLE":
            continue
        title = _item_text(item).strip()
        if title:
            return title
    return None


def _note_filedata_chunks(note: ET.Element) -> list[str]:
    chunks: list[str] = []
    for item in note.iter():
        if _local_tag(item) != "item":
            continue
        name = _elem_attr(item, "name") or ""
        if name != FILEDATA_ITEM:
            continue
        for child in item.iter():
            if _local_tag(child) == "rawitemdata":
                text = "".join(child.itertext())
                if text and text.strip():
                    chunks.append(text)
    return chunks


def _classify_title(title: str) -> tuple[str, str] | None:
    """Return (language, owner_type) for analyzable file resource titles."""
    low = title.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    if base.endswith(".java"):
        return "java", "javaclass"
    if base.endswith(".xsp"):
        return "xpages", "xpage"
    if base.endswith((".jss", ".js")):
        return "javascript", "javascript_resource"
    return None


def extract_javascript_from_xpage(xml_body: str) -> list[tuple[str | None, str]]:
    """Pull discrete SSJS fragments from XPage markup."""
    fragments: list[tuple[str | None, str]] = []
    seen: set[str] = set()

    def add(event: str | None, body: str) -> None:
        body = body.strip()
        if len(body) < 4:
            return
        key = body[:200]
        if key in seen:
            return
        seen.add(key)
        fragments.append((event, body))

    for m in _RE_JS_EL.finditer(xml_body):
        add("javascript_el", m.group(1).strip())

    for m in _RE_XP_SCRIPT.finditer(xml_body):
        inner = m.group(1)
        for cm in _RE_CDATA.finditer(inner):
            add("xp_script", cm.group(1).strip())
        stripped = _RE_CDATA.sub("", inner).strip()
        if stripped and not stripped.startswith("#{"):
            add("xp_script", stripped)

    # CDATA that wraps #{javascript:...} already covered; also bare CDATA with SSJS APIs
    for m in _RE_CDATA.finditer(xml_body):
        cdata = m.group(1).strip()
        if cdata.startswith("#{") or "javascript:" in cdata[:40].lower():
            continue
        if any(
            tok in cdata
            for tok in (
                "session.",
                "database.",
                "getDatabase",
                "getDocument",
                "recycle(",
                "NotesDocument",
                "NotesDatabase",
                "facesContext",
            )
        ):
            add("xp_cdata", cdata)

    return fragments


def extract_filedata_code_from_note(note: ET.Element) -> list[FileDataCode]:
    title = _note_title(note)
    if not title:
        return []
    classified = _classify_title(title)
    if not classified:
        return []
    language, owner_type = classified
    chunks = _note_filedata_chunks(note)
    if not chunks:
        return []
    body = decode_filedata_chunks(chunks)
    if not body or len(body.strip()) < 8:
        return []

    out: list[FileDataCode] = []
    if language == "xpages":
        # Full XPage for context
        out.append(
            FileDataCode(
                title=title,
                language="xpages",
                event="xpage",
                body=body,
                owner_type=owner_type,
            )
        )
        for event, frag in extract_javascript_from_xpage(body):
            out.append(
                FileDataCode(
                    title=title,
                    language="javascript",
                    event=event,
                    body=frag,
                    owner_type=owner_type,
                )
            )
    else:
        out.append(
            FileDataCode(
                title=title,
                language=language,
                event="source",
                body=body,
                owner_type=owner_type,
            )
        )
    return out


def extract_filedata_code_from_root(root: ET.Element) -> list[FileDataCode]:
    """Walk all ``<note>`` elements and extract Java / XPage / JS file resources."""
    results: list[FileDataCode] = []
    for elem in root.iter():
        if _local_tag(elem) != "note":
            continue
        results.extend(extract_filedata_code_from_note(elem))
    return results


def extract_javaproject_java(container: ET.Element) -> list[tuple[str, str]]:
    """Return (context_hint, body) for ``<javaproject>`` / bare ``<java>`` under container."""
    found: list[tuple[str, str]] = []
    for elem in container.iter():
        tag = _local_tag(elem)
        if tag == "java":
            # Skip if already under <code> (handled by extract_code_blocks)
            parent = None  # ElementTree has no parent; detect via ancestor walk in caller
            body = "".join(elem.itertext()).strip()
            if body and len(body) >= 8:
                found.append(("java", body))
        elif tag == "javaproject":
            body = "".join(elem.itertext()).strip()
            if body and len(body) >= 8 and "<" not in body[:20]:
                found.append(("javaproject", body))
    return found
