#!/usr/bin/env python3
"""
DXL Application Graph Parser

Scans HCL Domino DXL XML exports in xer/dxl_input/ and produces a structured
application_graph.json capturing design elements, embedded logic, and dependency edges.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET

XER_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = XER_ROOT / "dxl_input"
DEFAULT_OUTPUT_PATH = XER_ROOT / "application_graph.json"

PARSER_VERSION = "1.2.0"
DXL_NS = "http://www.lotus.com/dxl"
NS = {"dxl": DXL_NS}

# ---------------------------------------------------------------------------
# Regex patterns for dependency and formula extraction
# ---------------------------------------------------------------------------
RE_GET_VIEW = re.compile(
    r"""GetView\s*\(\s*(?:\"([^\"]+)\"|'([^']+)')\s*\)""",
    re.IGNORECASE,
)
RE_GET_DOCUMENT_BY_KEY = re.compile(
    r"""GetDocumentByKey\s*\(\s*(?:\"([^\"]+)\"|'([^']+)')\s*(?:,\s*[^)]+)?\s*\)""",
    re.IGNORECASE,
)
RE_USE_LIBRARY = re.compile(
    r"""^\s*Use\s+\"([^\"]+)\"""",
    re.IGNORECASE | re.MULTILINE,
)
RE_FORM_IN_SELECTION = re.compile(
    r"""Form\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
RE_REF_FIELD = re.compile(
    r"""<field\b[^>]*\bname=['\"]?\$REF['\"]?[^>]*>""",
    re.IGNORECASE,
)
RE_STRING_LITERAL = re.compile(r"""['"]([^'"]+)['"]""")
RE_TOOLS_RUN_MACRO = re.compile(
    r"""@Command\s*\(\s*\[ToolsRunMacro\]\s*;\s*["']?\(([^)]+)\)["']?""",
    re.IGNORECASE,
)
RE_LS_RUN_MACRO = re.compile(
    r"""RunMacro\s*\(\s*["']\(([^)]+)\)["']""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CodeBlock:
    language: str  # formula | lotusscript | java | javascript
    event: str | None
    body: str
    context: str  # e.g. form:Name/field:Status


@dataclass
class FieldModel:
    name: str
    type: str | None = None
    kind: str | None = None
    hidewhen: str | None = None
    is_ref: bool = False
    embedded_formulas: list[str] = field(default_factory=list)
    default_value: str | None = None
    input_validation: str | None = None
    input_translation: str | None = None


@dataclass
class ColumnModel:
    name: str
    itemname: str | None = None
    sort: str | None = None
    categorized: bool = False
    sortorder: str | None = None


@dataclass
class DesignElementRef:
    element_type: str
    name: str
    source_file: str | None = None
    database_id: str | None = None


@dataclass
class Edge:
    type: str
    source: DesignElementRef
    target: DesignElementRef
    evidence: str
    source_file: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FormModel:
    name: str
    alias: str | None
    source_file: str
    database_id: str
    fields: list[FieldModel] = field(default_factory=list)
    subform_refs: list[str] = field(default_factory=list)
    code_events: list[CodeBlock] = field(default_factory=list)
    is_subform: bool = False


@dataclass
class ViewModel:
    name: str
    alias: str | None
    source_file: str
    database_id: str
    selection_formula: str | None = None
    columns: list[ColumnModel] = field(default_factory=list)
    code_events: list[CodeBlock] = field(default_factory=list)


@dataclass
class AgentModel:
    name: str
    alias: str | None
    source_file: str
    database_id: str
    agent_trigger: str | None = None
    target: str | None = None
    code_events: list[CodeBlock] = field(default_factory=list)


@dataclass
class ScriptLibraryModel:
    name: str
    alias: str | None
    source_file: str
    database_id: str
    code_events: list[CodeBlock] = field(default_factory=list)


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def local_tag(elem: ET.Element) -> str:
    tag = elem.tag
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def elem_attr(elem: ET.Element, name: str, default: str | None = None) -> str | None:
    value = elem.get(name)
    if value is not None:
        return value
    # DXL sometimes uses namespaced attributes inconsistently; scan all attrs.
    needle = name.lower()
    for key, val in elem.attrib.items():
        if key.lower().endswith(name.lower()) or key.lower() == needle:
            return val
    return default


def text_content(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    parts: list[str] = []
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        parts.append(text_content(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts).strip()


def find_child(elem: ET.Element, tag: str) -> ET.Element | None:
    for child in elem:
        if local_tag(child) == tag:
            return child
    return None


def find_children(elem: ET.Element, tag: str) -> list[ET.Element]:
    return [child for child in elem if local_tag(child) == tag]


def find_descendants(elem: ET.Element, tag: str) -> list[ET.Element]:
    return [node for node in elem.iter() if local_tag(node) == tag]


def extract_code_blocks(container: ET.Element, context: str) -> list[CodeBlock]:
    blocks: list[CodeBlock] = []
    for code_elem in find_descendants(container, "code"):
        event = elem_attr(code_elem, "event")
        for child in code_elem:
            tag = local_tag(child)
            if tag in {"formula", "lotusscript", "java", "javascript"}:
                body = text_content(child)
                if body:
                    blocks.append(
                        CodeBlock(
                            language=tag,
                            event=event,
                            body=body,
                            context=context,
                        )
                    )
    return blocks


def extract_string_args(arg_blob: str) -> list[str]:
    """Pull quoted string literals from a @DbLookup/@DbColumn argument list."""
    return RE_STRING_LITERAL.findall(arg_blob)


def split_formula_arguments(arg_blob: str) -> list[str]:
    """Split a @Formula argument list on semicolons, respecting quoted strings and nesting."""
    args: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    quote_char = ""
    i = 0
    while i < len(arg_blob):
        ch = arg_blob[i]
        if in_string:
            current.append(ch)
            if ch == quote_char and (i == 0 or arg_blob[i - 1] != "\\"):
                in_string = False
                quote_char = ""
        elif ch in "\"'":
            in_string = True
            quote_char = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == ";" and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        args.append("".join(current).strip())
    return args


def quoted_strings_from_arg(arg: str) -> list[str]:
    return RE_STRING_LITERAL.findall(arg)


def primary_quoted_value(arg: str) -> str | None:
    """Return the last non-empty quoted literal in an argument segment."""
    values = [part for part in quoted_strings_from_arg(arg) if part.strip()]
    return values[-1] if values else None


def extract_at_db_function_bodies(text: str, func_name: str) -> list[str]:
    """Extract argument blobs from @DbLookup/@DbColumn using balanced parentheses."""
    bodies: list[str] = []
    token = f"@{func_name}"
    lower_text = text.lower()
    search_from = 0

    while True:
        idx = lower_text.find(token.lower(), search_from)
        if idx == -1:
            break
        open_paren = text.find("(", idx + len(token))
        if open_paren == -1:
            break

        depth = 0
        in_string = False
        quote_char = ""
        pos = open_paren
        while pos < len(text):
            ch = text[pos]
            if in_string:
                if ch == quote_char and text[pos - 1] != "\\":
                    in_string = False
                    quote_char = ""
            elif ch in "\"'":
                in_string = True
                quote_char = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    bodies.append(text[open_paren + 1 : pos])
                    search_from = pos + 1
                    break
            pos += 1
        else:
            break

    return bodies


def parse_db_func_args(arg_blob: str) -> tuple[str | None, str | None, str | None]:
    """
    Resolve (view, return_field, key_field) from @DbLookup/@DbColumn arguments.

    The view name is the primary quoted value in the 3rd semicolon-separated argument
    (after class/cache and server/database placeholders).
    """
    parts = split_formula_arguments(arg_blob)
    if len(parts) < 3:
        literals = [part for part in extract_string_args(arg_blob) if part.strip()]
        if len(literals) < 3:
            return None, None, None
        view_name = literals[-3] if len(literals) >= 3 else None
        return_field = literals[-2] if len(literals) >= 2 else None
        key_field = literals[-1] if literals else None
        return view_name, return_field, key_field

    view_name = primary_quoted_value(parts[2])
    return_field = primary_quoted_value(parts[3]) if len(parts) > 3 else None
    key_field = primary_quoted_value(parts[4]) if len(parts) > 4 else None
    return view_name, return_field, key_field


def build_element_parent_map(root: ET.Element) -> dict[ET.Element, ET.Element]:
    parent_map: dict[ET.Element, ET.Element] = {}
    for parent in root.iter():
        for child in parent:
            parent_map[child] = parent
    return parent_map


def build_pardef_hidewhen_map(form_elem: ET.Element) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node in form_elem.iter():
        if local_tag(node) != "pardef":
            continue
        pardef_id = elem_attr(node, "id")
        if not pardef_id:
            continue
        for code_elem in find_descendants(node, "code"):
            if (elem_attr(code_elem, "event") or "").lower() != "hidewhen":
                continue
            formula_elem = find_child(code_elem, "formula")
            if formula_elem is None:
                continue
            body = text_content(formula_elem)
            if body:
                mapping[pardef_id] = body
    return mapping


def hidewhen_from_context(
    field_elem: ET.Element,
    parent_map: dict[ET.Element, ET.Element],
    pardef_map: dict[str, str],
) -> str | None:
    """Resolve paragraph-level hide-when formulas via enclosing <par def='...'> nodes."""
    current: ET.Element | None = field_elem
    visited: set[ET.Element] = set()

    while current is not None and current not in visited:
        visited.add(current)

        if local_tag(current) == "code" and (elem_attr(current, "event") or "").lower() == "hidewhen":
            formula_elem = find_child(current, "formula")
            if formula_elem is not None:
                body = text_content(formula_elem)
                if body:
                    return body

        if local_tag(current) == "par":
            def_id = elem_attr(current, "def")
            if def_id and def_id in pardef_map:
                return pardef_map[def_id]

        parent = parent_map.get(current)
        if parent is None:
            break

        if local_tag(parent) in {"run", "par", "tablecell", "tablerow", "table"}:
            for sibling in parent:
                if sibling is current:
                    continue
                if local_tag(sibling) != "pardef":
                    continue
                pardef_id = elem_attr(sibling, "id")
                if pardef_id and pardef_id in pardef_map:
                    return pardef_map[pardef_id]

        current = parent

    return None


# ---------------------------------------------------------------------------
# Field / form / view parsers
# ---------------------------------------------------------------------------


def parse_field(
    field_elem: ET.Element,
    parent_map: dict[ET.Element, ET.Element] | None = None,
    pardef_map: dict[str, str] | None = None,
) -> FieldModel:
    name = elem_attr(field_elem, "name") or ""
    field_type = elem_attr(field_elem, "type")
    kind = elem_attr(field_elem, "kind")
    hidewhen: str | None = None
    default_value: str | None = None
    input_validation: str | None = None
    input_translation: str | None = None
    formulas: list[str] = []
    known_events = {
        "hidewhen",
        "defaultvalue",
        "inputvalidation",
        "inputtranslation",
        "htmlattributes",
    }

    for code_elem in find_descendants(field_elem, "code"):
        event = (elem_attr(code_elem, "event") or "").lower()
        formula_elem = find_child(code_elem, "formula")
        if formula_elem is None:
            continue
        body = text_content(formula_elem)
        if not body:
            continue
        if event == "hidewhen":
            hidewhen = body
        elif event == "defaultvalue":
            default_value = body
            formulas.append(body)
        elif event == "inputvalidation":
            input_validation = body
            formulas.append(body)
        elif event == "inputtranslation":
            input_translation = body
            formulas.append(body)
        elif event not in known_events or not event:
            formulas.append(body)

    if not hidewhen and parent_map is not None and pardef_map is not None:
        hidewhen = hidewhen_from_context(field_elem, parent_map, pardef_map)

    # Keyword/dialog lists often embed @DbLookup in bare <formula> nodes.
    for formula_elem in find_descendants(field_elem, "formula"):
        ancestor_code = None
        for candidate in field_elem.iter():
            if local_tag(candidate) == "code" and formula_elem in list(candidate.iter()):
                ancestor_code = candidate
                break
        ancestor_event = (elem_attr(ancestor_code, "event") or "").lower() if ancestor_code is not None else ""
        if ancestor_event in {"hidewhen", "htmlattributes"}:
            continue
        body = text_content(formula_elem)
        if body and body not in formulas:
            formulas.append(body)

    return FieldModel(
        name=name,
        type=field_type,
        kind=kind,
        hidewhen=hidewhen,
        is_ref=name.upper() == "$REF",
        embedded_formulas=formulas,
        default_value=default_value,
        input_validation=input_validation,
        input_translation=input_translation,
    )


def database_id_from_source(source_file: str, database_path: str | None = None) -> str:
    """Stable database identifier for multi-DXL graphs."""
    if database_path:
        path_part = database_path.split("!!")[-1] if "!!" in database_path else database_path
        name = path_part.replace("\\", "/").split("/")[-1].strip()
        if name:
            return name
    stem = Path(source_file).stem
    if stem.endswith(".nsf"):
        return stem
    return stem


def normalize_agent_name(macro_name: str) -> str:
    macro_name = macro_name.strip()
    if macro_name.startswith("(") and macro_name.endswith(")"):
        return macro_name
    return f"({macro_name})"


def parse_db_database_ref(arg_blob: str) -> str | None:
    """Extract server:database reference from @DbLookup/@DbColumn argument list."""
    parts = split_formula_arguments(arg_blob)
    if len(parts) < 2:
        return None
    db_ref = primary_quoted_value(parts[1])
    if db_ref and db_ref.strip() not in {'""', "''"}:
        return db_ref.strip()
    raw = parts[1].strip()
    return raw if raw and raw not in {'""', "''"} else None


def parse_form_like(elem: ET.Element, source_file: str, database_id: str, is_subform: bool) -> FormModel:
    name = elem_attr(elem, "name") or "Unnamed"
    alias = elem_attr(elem, "alias")
    context_prefix = "subform" if is_subform else "form"

    parent_map = build_element_parent_map(elem)
    pardef_map = build_pardef_hidewhen_map(elem)

    fields: list[FieldModel] = []
    subform_refs: list[str] = []

    for child in find_descendants(elem, "field"):
        fields.append(parse_field(child, parent_map, pardef_map))

    for subform_ref in find_descendants(elem, "subformref"):
        ref_name = elem_attr(subform_ref, "name")
        if ref_name:
            subform_refs.append(ref_name)

    code_events = extract_code_blocks(elem, f"{context_prefix}:{name}")

    return FormModel(
        name=name,
        alias=alias,
        source_file=source_file,
        database_id=database_id,
        fields=fields,
        subform_refs=subform_refs,
        code_events=code_events,
        is_subform=is_subform,
    )


def parse_view(elem: ET.Element, source_file: str, database_id: str) -> ViewModel:
    name = elem_attr(elem, "name") or "Unnamed"
    alias = elem_attr(elem, "alias")
    selection_formula: str | None = None

    for code_elem in find_descendants(elem, "code"):
        if (elem_attr(code_elem, "event") or "").lower() == "selection":
            formula_elem = find_child(code_elem, "formula")
            if formula_elem is not None:
                selection_formula = text_content(formula_elem)

    columns: list[ColumnModel] = []
    for col_elem in find_descendants(elem, "column"):
        columns.append(
            ColumnModel(
                name=elem_attr(col_elem, "title")
                or elem_attr(col_elem, "itemname")
                or "Column",
                itemname=elem_attr(col_elem, "itemname"),
                sort=elem_attr(col_elem, "sort"),
                categorized=(elem_attr(col_elem, "categorized") or "").lower() == "true",
                sortorder=elem_attr(col_elem, "sortorder"),
            )
        )

    code_events = extract_code_blocks(elem, f"view:{name}")

    return ViewModel(
        name=name,
        alias=alias,
        source_file=source_file,
        database_id=database_id,
        selection_formula=selection_formula,
        columns=columns,
        code_events=code_events,
    )


def parse_agent(elem: ET.Element, source_file: str, database_id: str) -> AgentModel:
    name = elem_attr(elem, "name") or "Unnamed"
    alias = elem_attr(elem, "alias")
    target = elem_attr(elem, "target")
    agent_trigger = parse_agent_trigger(elem)

    code_events = extract_code_blocks(elem, f"agent:{name}")

    return AgentModel(
        name=name,
        alias=alias,
        source_file=source_file,
        database_id=database_id,
        agent_trigger=agent_trigger,
        target=target,
        code_events=code_events,
    )


def parse_agent_trigger(agent_elem: ET.Element) -> str | None:
    """Parse child <trigger> and nested <schedule> elements into agent_trigger."""
    trigger_elem = None
    for child in agent_elem:
        if local_tag(child) == "trigger":
            trigger_elem = child
            break

    if trigger_elem is None:
        return elem_attr(agent_elem, "trigger")

    trigger_type = elem_attr(trigger_elem, "type")
    if not trigger_type:
        return None

    schedule_elem = find_child(trigger_elem, "schedule")
    if schedule_elem is None:
        for node in trigger_elem.iter():
            if local_tag(node) == "schedule":
                schedule_elem = node
                break

    if schedule_elem is not None:
        schedule_type = elem_attr(schedule_elem, "type") or "scheduled"
        return f"{trigger_type}:{schedule_type}"

    return trigger_type


def parse_script_library(elem: ET.Element, source_file: str, database_id: str) -> ScriptLibraryModel:
    name = elem_attr(elem, "name") or "Unnamed"
    alias = elem_attr(elem, "alias")
    code_events = extract_code_blocks(elem, f"scriptlibrary:{name}")
    return ScriptLibraryModel(
        name=name,
        alias=alias,
        source_file=source_file,
        database_id=database_id,
        code_events=code_events,
    )


# ---------------------------------------------------------------------------
# Dependency edge extraction
# ---------------------------------------------------------------------------


def make_ref(
    element_type: str,
    name: str,
    source_file: str,
    database_id: str | None = None,
) -> DesignElementRef:
    return DesignElementRef(
        element_type=element_type,
        name=name,
        source_file=source_file,
        database_id=database_id,
    )


def edges_from_form(form: FormModel) -> list[Edge]:
    edges: list[Edge] = []
    source = make_ref("form", form.name, form.source_file, form.database_id)

    for subform_name in form.subform_refs:
        edges.append(
            Edge(
                type="INCLUDES_SUBFORM",
                source=source,
                target=make_ref("subform", subform_name, form.source_file, form.database_id),
                evidence=f'<subformref name="{subform_name}">',
                source_file=form.source_file,
            )
        )

    ref_fields = [f for f in form.fields if f.is_ref]
    for ref_field in ref_fields:
        edges.append(
            Edge(
                type="PARENT_CHILD_REF",
                source=make_ref("form", form.name, form.source_file, form.database_id),
                target=make_ref("form", "ParentDocument", form.source_file, form.database_id),
                evidence=f"Response document field ${ref_field.name} establishes parent linkage",
                source_file=form.source_file,
                metadata={"field": ref_field.name},
            )
        )

    return edges


def edges_from_view(view: ViewModel) -> list[Edge]:
    edges: list[Edge] = []
    source = make_ref("view", view.name, view.source_file, view.database_id)

    if view.selection_formula:
        seen_forms: set[str] = set()
        for form_name in RE_FORM_IN_SELECTION.findall(view.selection_formula):
            if form_name in seen_forms:
                continue
            seen_forms.add(form_name)
            edges.append(
                Edge(
                    type="SELECTS_FORM",
                    source=source,
                    target=make_ref("form", form_name, view.source_file, view.database_id),
                    evidence=f'Form="{form_name}"',
                    source_file=view.source_file,
                    metadata={"selection_formula": view.selection_formula},
                )
            )

    return edges


def edges_from_code_blocks(
    blocks: Iterable[CodeBlock],
    owner_type: str,
    owner_name: str,
    source_file: str,
    database_id: str,
) -> list[Edge]:
    edges: list[Edge] = []
    owner_ref = make_ref(owner_type, owner_name, source_file, database_id)

    for block in blocks:
        body = block.body

        for func_name in ("DbLookup", "DbColumn"):
            for arg_blob in extract_at_db_function_bodies(body, func_name):
                view_name, return_field, key_field = parse_db_func_args(arg_blob)
                if not view_name:
                    continue
                evidence = f"@{func_name}({arg_blob})"[:500]
                db_ref = parse_db_database_ref(arg_blob)
                metadata: dict[str, Any] = {
                    "language": block.language,
                    "event": block.event,
                    "context": block.context,
                }
                if db_ref:
                    metadata["database_ref"] = db_ref
                if func_name.lower() == "dblookup":
                    metadata["lookup_field"] = key_field
                    metadata["return_field"] = return_field
                else:
                    metadata["column_field"] = return_field
                    metadata["key_field"] = key_field
                edges.append(
                    Edge(
                        type="LOOKUP_VIA_VIEW",
                        source=owner_ref,
                        target=make_ref("view", view_name, source_file, database_id),
                        evidence=evidence,
                        source_file=source_file,
                        metadata=metadata,
                    )
                )
                if db_ref:
                    edges.append(
                        Edge(
                            type="REFERENCES_DATABASE",
                            source=owner_ref,
                            target=make_ref("database", db_ref, source_file, None),
                            evidence=evidence,
                            source_file=source_file,
                            metadata={**metadata, "view_name": view_name},
                        )
                    )

        for pattern in (RE_TOOLS_RUN_MACRO, RE_LS_RUN_MACRO):
            for match in pattern.finditer(body):
                agent_name = normalize_agent_name(match.group(1))
                edges.append(
                    Edge(
                        type="INVOKES_AGENT",
                        source=owner_ref,
                        target=make_ref("agent", agent_name, source_file, database_id),
                        evidence=match.group(0)[:500],
                        source_file=source_file,
                        metadata={
                            "language": block.language,
                            "event": block.event,
                            "context": block.context,
                        },
                    )
                )

        for match in RE_GET_VIEW.finditer(body):
            view_name = match.group(1) or match.group(2)
            if view_name:
                edges.append(
                    Edge(
                        type="ACCESSES_VIEW",
                        source=owner_ref,
                        target=make_ref("view", view_name, source_file, database_id),
                        evidence=match.group(0),
                        source_file=source_file,
                        metadata={
                            "language": block.language,
                            "event": block.event,
                            "context": block.context,
                        },
                    )
                )

        for match in RE_GET_DOCUMENT_BY_KEY.finditer(body):
            key_hint = match.group(1) or match.group(2)
            edges.append(
                Edge(
                    type="ACCESSES_VIEW",
                    source=owner_ref,
                    target=make_ref("view", "ByKey", source_file, database_id),
                    evidence=match.group(0),
                    source_file=source_file,
                    metadata={
                        "key_hint": key_hint,
                        "language": block.language,
                        "event": block.event,
                        "context": block.context,
                    },
                )
            )

        for match in RE_USE_LIBRARY.finditer(body):
            lib_name = match.group(1)
            edges.append(
                Edge(
                    type="USES_SCRIPT_LIBRARY",
                    source=owner_ref,
                    target=make_ref("scriptlibrary", lib_name, source_file, database_id),
                    evidence=match.group(0).strip(),
                    source_file=source_file,
                    metadata={
                        "language": block.language,
                        "event": block.event,
                        "context": block.context,
                    },
                )
            )

    return edges


def dedupe_edges(edges: list[Edge]) -> list[Edge]:
    seen: set[tuple[Any, ...]] = set()
    unique: list[Edge] = []
    for edge in edges:
        key = (
            edge.type,
            edge.source.element_type,
            edge.source.name,
            edge.source.database_id,
            edge.target.element_type,
            edge.target.name,
            edge.target.database_id,
            edge.evidence[:120],
            edge.source_file,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique


# ---------------------------------------------------------------------------
# File-level parser
# ---------------------------------------------------------------------------


@dataclass
class ParsedDXLFile:
    path: Path
    database_title: str | None
    database_path: str | None
    forms: list[FormModel]
    subforms: list[FormModel]
    views: list[ViewModel]
    agents: list[AgentModel]
    script_libraries: list[ScriptLibraryModel]
    edges: list[Edge]
    parse_errors: list[str] = field(default_factory=list)


class DXLFileParser:
    def parse_file(self, path: Path) -> ParsedDXLFile:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_text(raw_text, path.name, path)

    def parse_text(self, raw_text: str, source_file: str, path: Path | None = None) -> ParsedDXLFile:
        path = path or Path(source_file)
        database_path: str | None = None
        forms: list[FormModel] = []
        subforms: list[FormModel] = []
        views: list[ViewModel] = []
        agents: list[AgentModel] = []
        script_libraries: list[ScriptLibraryModel] = []
        edges: list[Edge] = []
        parse_errors: list[str] = []

        try:
            root = ET.fromstring(raw_text)
        except ET.ParseError as exc:
            parse_errors.append(f"XML parse error: {exc}")
            edges.extend(self._regex_fallback_edges(raw_text, source_file))
            return ParsedDXLFile(
                path=path,
                database_title=database_title,
                database_path=database_path,
                forms=forms,
                subforms=subforms,
                views=views,
                agents=agents,
                script_libraries=script_libraries,
                edges=edges,
                parse_errors=parse_errors,
            )

        database_title = elem_attr(root, "title")
        database_path = elem_attr(root, "path")
        database_id = database_id_from_source(source_file, database_path)

        for form_elem in root.findall(f".//{{{DXL_NS}}}form"):
            form = parse_form_like(form_elem, source_file, database_id, is_subform=False)
            forms.append(form)
            edges.extend(edges_from_form(form))
            edges.extend(
                edges_from_code_blocks(form.code_events, "form", form.name, source_file, database_id)
            )
            for fld in form.fields:
                embedded = fld.embedded_formulas
                for formula_body in embedded:
                    edges.extend(
                        edges_from_code_blocks(
                            [
                                CodeBlock(
                                    language="formula",
                                    event="default",
                                    body=formula_body,
                                    context=f"form:{form.name}/field:{fld.name}",
                                )
                            ],
                            "form",
                            form.name,
                            source_file,
                            database_id,
                        )
                    )
                if fld.hidewhen:
                    edges.extend(
                        edges_from_code_blocks(
                            [
                                CodeBlock(
                                    language="formula",
                                    event="hidewhen",
                                    body=fld.hidewhen,
                                    context=f"form:{form.name}/field:{fld.name}",
                                )
                            ],
                            "form",
                            form.name,
                            source_file,
                            database_id,
                        )
                    )

        for subform_elem in root.findall(f".//{{{DXL_NS}}}subform"):
            subform = parse_form_like(subform_elem, source_file, database_id, is_subform=True)
            subforms.append(subform)
            edges.extend(edges_from_form(subform))
            edges.extend(
                edges_from_code_blocks(
                    subform.code_events, "subform", subform.name, source_file, database_id
                )
            )

        for view_elem in root.findall(f".//{{{DXL_NS}}}view"):
            view = parse_view(view_elem, source_file, database_id)
            views.append(view)
            edges.extend(edges_from_view(view))
            edges.extend(
                edges_from_code_blocks(view.code_events, "view", view.name, source_file, database_id)
            )

        for agent_elem in root.findall(f".//{{{DXL_NS}}}agent"):
            agent = parse_agent(agent_elem, source_file, database_id)
            agents.append(agent)
            edges.extend(
                edges_from_code_blocks(agent.code_events, "agent", agent.name, source_file, database_id)
            )

        for lib_elem in root.findall(f".//{{{DXL_NS}}}scriptlibrary"):
            lib = parse_script_library(lib_elem, source_file, database_id)
            script_libraries.append(lib)
            edges.extend(
                edges_from_code_blocks(
                    lib.code_events, "scriptlibrary", lib.name, source_file, database_id
                )
            )

        edges = dedupe_edges(edges)

        return ParsedDXLFile(
            path=path,
            database_title=database_title,
            database_path=database_path,
            forms=forms,
            subforms=subforms,
            views=views,
            agents=agents,
            script_libraries=script_libraries,
            edges=edges,
            parse_errors=parse_errors,
        )

    def _regex_fallback_edges(self, raw_text: str, source_file: str) -> list[Edge]:
        """Best-effort edge extraction when XML is malformed."""
        database_id = database_id_from_source(source_file)
        generic_blocks = [
            CodeBlock(language="unknown", event=None, body=raw_text, context="file")
        ]
        return dedupe_edges(
            edges_from_code_blocks(generic_blocks, "database", source_file, source_file, database_id)
        )


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def to_plain(obj: Any) -> Any:
    if isinstance(obj, (FormModel, ViewModel, AgentModel, ScriptLibraryModel, FieldModel, ColumnModel, CodeBlock, DesignElementRef, Edge)):
        return {k: to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [to_plain(item) for item in obj]
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, Path):
        return str(obj)
    return obj


class ApplicationGraphBuilder:
    def __init__(self, input_dir: Path) -> None:
        self.input_dir = input_dir
        self.parser = DXLFileParser()

    def build(self) -> dict[str, Any]:
        patterns = ("*.dxl", "*.xml", "*.DXL", "*.XML")
        files: list[Path] = []
        for pattern in patterns:
            files.extend(sorted(self.input_dir.glob(pattern)))
        files = sorted(set(files))
        parsed_files = [self.parser.parse_file(path) for path in files]
        return self.build_from_parsed(parsed_files, input_label=str(self.input_dir))

    def build_from_parsed(
        self,
        parsed_files: list[ParsedDXLFile],
        *,
        input_label: str,
    ) -> dict[str, Any]:
        all_forms: list[FormModel] = []
        all_subforms: list[FormModel] = []
        all_views: list[ViewModel] = []
        all_agents: list[AgentModel] = []
        all_libraries: list[ScriptLibraryModel] = []
        all_edges: list[Edge] = []
        source_files: list[dict[str, Any]] = []
        global_errors: list[dict[str, str]] = []

        for parsed in parsed_files:
            db_id = database_id_from_source(parsed.path.name, parsed.database_path)
            rel_path = parsed.path.name
            if self.input_dir.exists() and parsed.path.is_absolute():
                try:
                    rel_path = str(parsed.path.relative_to(self.input_dir))
                except ValueError:
                    rel_path = parsed.path.name

            all_forms.extend(parsed.forms)
            all_subforms.extend(parsed.subforms)
            all_views.extend(parsed.views)
            all_agents.extend(parsed.agents)
            all_libraries.extend(parsed.script_libraries)
            all_edges.extend(parsed.edges)

            source_files.append(
                {
                    "path": rel_path,
                    "database_id": db_id,
                    "database_title": parsed.database_title,
                    "database_path": parsed.database_path,
                    "counts": {
                        "forms": len(parsed.forms),
                        "subforms": len(parsed.subforms),
                        "views": len(parsed.views),
                        "agents": len(parsed.agents),
                        "script_libraries": len(parsed.script_libraries),
                        "edges": len(parsed.edges),
                    },
                }
            )
            for err in parsed.parse_errors:
                global_errors.append({"file": parsed.path.name, "error": err})

        databases = [
            {
                "id": sf["database_id"],
                "title": sf.get("database_title"),
                "path": sf.get("database_path"),
                "source_file": sf.get("path"),
                "counts": sf.get("counts", {}),
            }
            for sf in source_files
        ]

        all_edges = dedupe_edges(all_edges)
        all_edges.extend(self._resolve_cross_database_edges(all_edges, databases, all_views))
        all_edges = dedupe_edges(all_edges)

        business_logic = self._collect_business_logic(
            all_forms, all_subforms, all_views, all_agents, all_libraries
        )

        return {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "parser_version": PARSER_VERSION,
                "input_directory": input_label,
                "source_files": source_files,
                "databases": databases,
                "totals": {
                    "forms": len(all_forms),
                    "subforms": len(all_subforms),
                    "views": len(all_views),
                    "agents": len(all_agents),
                    "script_libraries": len(all_libraries),
                    "edges": len(all_edges),
                    "business_logic_blocks": len(business_logic),
                },
                "errors": global_errors,
            },
            "design_elements": {
                "forms": to_plain(all_forms),
                "subforms": to_plain(all_subforms),
                "views": to_plain(all_views),
                "agents": to_plain(all_agents),
                "script_libraries": to_plain(all_libraries),
            },
            "edges": to_plain(all_edges),
            "business_logic": business_logic,
        }

    def _collect_business_logic(
        self,
        forms: list[FormModel],
        subforms: list[FormModel],
        views: list[ViewModel],
        agents: list[AgentModel],
        libraries: list[ScriptLibraryModel],
    ) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = []

        def add_blocks(
            owner_type: str,
            owner_name: str,
            source_file: str,
            database_id: str,
            code_events: list[CodeBlock],
        ) -> None:
            for code in code_events:
                category = self._categorize_logic(code)
                blocks.append(
                    {
                        "category": category,
                        "owner_type": owner_type,
                        "owner_name": owner_name,
                        "source_file": source_file,
                        "database_id": database_id,
                        "language": code.language,
                        "event": code.event,
                        "context": code.context,
                        "body": code.body,
                    }
                )

        def add_field_blocks(owner_type: str, form: FormModel) -> None:
            for fld in form.fields:
                field_ctx = f"{owner_type}:{form.name}/field:{fld.name}"
                event_bodies = [
                    ("defaultvalue", fld.default_value, "conditional_logic"),
                    ("inputvalidation", fld.input_validation, "validation"),
                    ("inputtranslation", fld.input_translation, "conditional_logic"),
                    ("hidewhen", fld.hidewhen, "hidewhen"),
                ]
                seen_bodies = {body for _, body, _ in event_bodies if body}
                for event, body, category in event_bodies:
                    if not body:
                        continue
                    blocks.append(
                        {
                            "category": category,
                            "owner_type": owner_type,
                            "owner_name": form.name,
                            "source_file": form.source_file,
                            "database_id": form.database_id,
                            "language": "formula",
                            "event": event,
                            "context": field_ctx,
                            "body": body,
                        }
                    )
                for formula_body in fld.embedded_formulas:
                    if formula_body in seen_bodies:
                        continue
                    blocks.append(
                        {
                            "category": "conditional_logic",
                            "owner_type": owner_type,
                            "owner_name": form.name,
                            "source_file": form.source_file,
                            "database_id": form.database_id,
                            "language": "formula",
                            "event": "default",
                            "context": field_ctx,
                            "body": formula_body,
                        }
                    )

        for form in forms:
            add_blocks("form", form.name, form.source_file, form.database_id, form.code_events)
            add_field_blocks("form", form)

        for subform in subforms:
            add_blocks("subform", subform.name, subform.source_file, subform.database_id, subform.code_events)
            add_field_blocks("subform", subform)

        for view in views:
            add_blocks("view", view.name, view.source_file, view.database_id, view.code_events)
            if view.selection_formula:
                blocks.append(
                    {
                        "category": "view_selection",
                        "owner_type": "view",
                        "owner_name": view.name,
                        "source_file": view.source_file,
                        "database_id": view.database_id,
                        "language": "formula",
                        "event": "selection",
                        "context": f"view:{view.name}",
                        "body": view.selection_formula,
                    }
                )

        for agent in agents:
            add_blocks("agent", agent.name, agent.source_file, agent.database_id, agent.code_events)

        for lib in libraries:
            add_blocks("scriptlibrary", lib.name, lib.source_file, lib.database_id, lib.code_events)

        return blocks

    @staticmethod
    def _resolve_cross_database_edges(
        edges: list[Edge],
        databases: list[dict[str, Any]],
        views: list[ViewModel],
    ) -> list[Edge]:
        """Link lookups that target a view in a different parsed database."""
        if len(databases) < 2:
            return []

        db_index: dict[str, str] = {}
        for db in databases:
            for key in (db.get("id"), db.get("path"), db.get("title"), db.get("source_file")):
                if key:
                    db_index[str(key).lower()] = db["id"]

        view_by_db: dict[tuple[str, str], ViewModel] = {
            (view.database_id, view.name): view for view in views
        }

        cross_edges: list[Edge] = []
        for edge in edges:
            if edge.type != "LOOKUP_VIA_VIEW":
                continue
            db_ref = (edge.metadata or {}).get("database_ref")
            if not db_ref:
                continue
            target_db = db_index.get(db_ref.lower())
            if not target_db or target_db == edge.source.database_id:
                continue
            view_name = edge.target.name
            if (target_db, view_name) not in view_by_db:
                continue
            cross_edges.append(
                Edge(
                    type="CROSS_DATABASE_LOOKUP",
                    source=edge.source,
                    target=make_ref("view", view_name, edge.source_file or "", target_db),
                    evidence=edge.evidence,
                    source_file=edge.source_file or "",
                    metadata={
                        **(edge.metadata or {}),
                        "source_database": edge.source.database_id,
                        "target_database": target_db,
                    },
                )
            )
        return cross_edges

    @staticmethod
    def _categorize_logic(code: CodeBlock) -> str:
        event = (code.event or "").lower()
        body_lower = code.body.lower()

        if event == "hidewhen":
            return "hidewhen"
        if event in {"inputvalidation", "validation"}:
            return "validation"
        if event in {"querysave", "postsave", "presave"}:
            return "state_transition"
        if event in {"queryopen", "postopen", "queryclose"}:
            return "lifecycle"
        if event == "selection":
            return "view_selection"
        if event in {"options", "declarations", "initialize", "terminate"}:
            return "agent_setup"
        if "@if" in body_lower or "@isnewdoc" in body_lower or "@userroles" in body_lower:
            return "conditional_logic"
        if code.language == "lotusscript":
            return "lotusscript_logic"
        if code.language == "java":
            return "java_logic"
        return "general_formula"


def build_graph_from_dxl_bytes(content: bytes, filename: str) -> dict[str, Any]:
    """Parse a single DXL/XML upload and return an application graph dict."""
    parser = DXLFileParser()
    raw_text = content.decode("utf-8", errors="replace")
    parsed = parser.parse_text(raw_text, filename)
    builder = ApplicationGraphBuilder(XER_ROOT / "upload")
    return builder.build_from_parsed([parsed], input_label=f"upload:{filename}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse HCL Domino DXL exports into application_graph.json"
    )
    parser.add_argument(
        "input_pos",
        nargs="?",
        type=Path,
        help="Input directory (positional shorthand for --input)",
    )
    parser.add_argument(
        "output_pos",
        nargs="?",
        type=Path,
        help="Output JSON path (positional shorthand for --output)",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=None,
        help=f"Directory containing DXL/XML exports (default: {DEFAULT_INPUT_DIR})",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help=f"Output JSON graph path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation (default: 2)",
    )
    parser.add_argument(
        "--store-neon",
        action="store_true",
        help="Store parsed graph in Neon PostgreSQL (requires DATABASE_URL)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_dir: Path = args.input or args.input_pos or DEFAULT_INPUT_DIR
    output_path: Path = args.output or args.output_pos or DEFAULT_OUTPUT_PATH

    if not input_dir.exists():
        print(f"Error: input directory not found: {input_dir}", file=sys.stderr)
        return 1

    builder = ApplicationGraphBuilder(input_dir)
    graph = builder.build()

    output_path.write_text(
        json.dumps(graph, indent=args.indent, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    totals = graph["meta"]["totals"]
    print(f"Wrote {output_path}")
    print(
        "Parsed "
        f"{totals['forms']} forms, "
        f"{totals['views']} views, "
        f"{totals['agents']} agents, "
        f"{totals['script_libraries']} script libraries, "
        f"{totals['edges']} edges."
    )

    if graph["meta"]["errors"]:
        print(f"Warnings: {len(graph['meta']['errors'])} parse issue(s) — see meta.errors in output.")

    if args.store_neon:
        try:
            from dotenv import load_dotenv

            load_dotenv(XER_ROOT / ".env", override=False)
            from neon_db import store_graph

            graph_id = store_graph(graph)
            print(f"Stored in Neon: {graph_id}")
        except Exception as exc:
            print(f"Neon store failed: {exc}", file=sys.stderr)
            return 3

    if graph["meta"]["errors"]:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
