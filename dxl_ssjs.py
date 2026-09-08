"""Decode Domino DXL ``$ServerJavaScriptLibrary`` script-library payloads.

SSJS libraries are often stored as one or more ``<item name='$ServerJavaScriptLibrary'>``
``<rawitemdata>`` chunks (base64 + binary Notes header), not as ``<code><javascript>``.
Both the application-graph parser and the code auditor must decode these or SSJS
APIs (e.g. ``accounting.claimsPayments.uploadFile``) are invisible to analysis.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from typing import Iterable

SERVER_JS_ITEM = "$ServerJavaScriptLibrary"
CLIENT_JS_ITEM = "$ClientJavaScriptLibrary"

# Start of real SSJS source inside a Notes composite item payload.
_RE_JS_START = re.compile(
    r"(?:/\*{3,}"
    r"|(?<![A-Za-z0-9_])var\s+[A-Za-z_]"
    r"|(?<![A-Za-z0-9_])function\s+[A-Za-z_]"
    r"|(?:^|[\r\n])\s*//)",
)


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


def _strip_notes_header(raw: bytes) -> str:
    """Drop the Domino composite header and return latin-1 source text."""
    s = raw.decode("latin-1", errors="ignore")
    match = _RE_JS_START.search(s)
    if match:
        return s[match.start() :]
    # Fallback: skip leading control bytes until a printable ASCII run.
    i = 0
    while i < len(raw) and raw[i] < 32 and raw[i] not in (9, 10, 13):
        i += 1
    while i < len(raw):
        window = raw[i : i + 8]
        if len(window) == 8 and all(32 <= b < 127 or b in (9, 10, 13) for b in window):
            break
        i += 1
    return raw[i:].decode("latin-1", errors="ignore")


def decode_server_javascript_chunks(raw_b64_chunks: Iterable[str]) -> str:
    """Concatenate base64 ``rawitemdata`` chunks into one SSJS library body."""
    parts: list[str] = []
    for b64 in raw_b64_chunks:
        data = re.sub(r"\s+", "", b64 or "")
        if not data:
            continue
        try:
            raw = base64.b64decode(data, validate=False)
        except Exception:  # noqa: BLE001
            continue
        if not raw:
            continue
        parts.append(_strip_notes_header(raw))
    body = "".join(parts)
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    # Trailing NULs / junk after last function
    body = body.rstrip("\x00").rstrip()
    return body


def iter_server_javascript_rawitemdata(scriptlibrary_elem: ET.Element) -> list[str]:
    """Collect base64 payloads from ``$ServerJavaScriptLibrary`` items under a library."""
    return _iter_named_rawitemdata(scriptlibrary_elem, SERVER_JS_ITEM)


def iter_client_javascript_rawitemdata(scriptlibrary_elem: ET.Element) -> list[str]:
    """Collect base64 payloads from ``$ClientJavaScriptLibrary`` items under a library."""
    return _iter_named_rawitemdata(scriptlibrary_elem, CLIENT_JS_ITEM)


def _iter_named_rawitemdata(scriptlibrary_elem: ET.Element, item_name: str) -> list[str]:
    chunks: list[str] = []
    for item in scriptlibrary_elem.iter():
        if _local_tag(item) != "item":
            continue
        name = _elem_attr(item, "name") or ""
        if name != item_name:
            continue
        for child in item.iter():
            if _local_tag(child) == "rawitemdata":
                text = "".join(child.itertext())
                if text and text.strip():
                    chunks.append(text)
    return chunks


def extract_server_javascript_library(scriptlibrary_elem: ET.Element) -> str | None:
    """Return decoded SSJS source for a ``<scriptlibrary>``, or None if absent/empty."""
    chunks = iter_server_javascript_rawitemdata(scriptlibrary_elem)
    if not chunks:
        return None
    body = decode_server_javascript_chunks(chunks)
    if not body or len(body.strip()) < 8:
        return None
    return body


def extract_client_javascript_library(scriptlibrary_elem: ET.Element) -> str | None:
    """Return decoded CSJS source from ``$ClientJavaScriptLibrary``, or None."""
    chunks = iter_client_javascript_rawitemdata(scriptlibrary_elem)
    if not chunks:
        return None
    body = decode_server_javascript_chunks(chunks)
    if not body or len(body.strip()) < 8:
        return None
    return body
