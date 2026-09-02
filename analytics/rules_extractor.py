"""
Extract a structured BusinessRulesCatalog from a parsed Xer application graph.

Walks form/subform fields for data types, default/validation/translation/hide-when
formulas, @DbLookup/@DbColumn dependencies, and LotusScript GetView accesses.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from dxl_parser import (
    extract_at_db_function_bodies,
    parse_db_database_ref,
    parse_db_func_args,
)
from analytics.plain_english import describe_field_rules, humanize_field_name

SCHEMA_VERSION = "1.1"

RE_FAILURE = re.compile(r'@Failure\s*\(\s*"((?:\\.|[^"\\])*)"', re.I)
RE_GETVIEW = re.compile(
    r"""(?:Set\s+\w+\s*=\s*)?(?:\w+\.)?GetView\s*\(\s*["']([^"']+)["']\s*\)""",
    re.I,
)
RE_NOTES_DB = re.compile(
    r"""NotesDatabase\s*\(\s*["']([^"']*)["']\s*,\s*["']([^"']+)["']\s*\)""",
    re.I,
)


def _failure_messages(formula: str | None) -> list[str]:
    if not formula:
        return []
    return [m.group(1).replace('\\"', '"') for m in RE_FAILURE.finditer(formula)]


def _field_name_from_context(context: str | None) -> str | None:
    if not context or "/field:" not in context:
        return None
    return context.split("/field:", 1)[1].strip() or None


def _lookups_from_formula(body: str) -> list[dict[str, Any]]:
    lookups: list[dict[str, Any]] = []
    for func_name in ("DbLookup", "DbColumn"):
        for arg_blob in extract_at_db_function_bodies(body, func_name):
            view_name, return_field, key_field = parse_db_func_args(arg_blob)
            db_ref = parse_db_database_ref(arg_blob)
            lookups.append(
                {
                    "function": f"@{func_name}",
                    "target_database": db_ref,
                    "target_view": view_name,
                    "lookup_key": key_field,
                    "return_field": return_field,
                    "source": "formula",
                }
            )
    return lookups


def _lookups_from_lotusscript(body: str) -> list[dict[str, Any]]:
    lookups: list[dict[str, Any]] = []
    db_paths = [m.group(2) for m in RE_NOTES_DB.finditer(body)]
    db_hint = db_paths[-1] if db_paths else None
    for match in RE_GETVIEW.finditer(body):
        lookups.append(
            {
                "function": "GetView",
                "target_database": db_hint,
                "target_view": match.group(1),
                "lookup_key": None,
                "return_field": None,
                "source": "lotusscript",
            }
        )
    return lookups


def _formula_bucket(
    field: dict[str, Any],
    logic_by_event: dict[str, list[str]],
) -> dict[str, Any]:
    """Resolve default / validation / translation from field attrs or logic blocks."""
    default_value = field.get("default_value")
    input_validation = field.get("input_validation")
    input_translation = field.get("input_translation")

    if not default_value:
        for key in ("defaultvalue", "default"):
            if logic_by_event.get(key):
                default_value = logic_by_event[key][0]
                break
    if not input_validation and logic_by_event.get("inputvalidation"):
        input_validation = logic_by_event["inputvalidation"][0]
    if not input_translation and logic_by_event.get("inputtranslation"):
        input_translation = logic_by_event["inputtranslation"][0]

    # Legacy graphs store unlabeled field formulas as event "default"
    if not default_value and not input_validation:
        for body in logic_by_event.get("default", []):
            if RE_FAILURE.search(body):
                input_validation = input_validation or body
            elif not default_value:
                default_value = body

    # Legacy / mixed: validation often only lives in embedded_formulas
    if not input_validation:
        for body in field.get("embedded_formulas") or []:
            if RE_FAILURE.search(body):
                input_validation = body
                break

    hide_when = field.get("hidewhen")
    if not hide_when and logic_by_event.get("hidewhen"):
        hide_when = logic_by_event["hidewhen"][0]

    return {
        "default_value": default_value,
        "input_validation": input_validation,
        "input_translation": input_translation,
        "hide_when": hide_when,
    }


def _index_field_logic(graph: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, list[str]]]:
    """Map (owner_type, owner_name, field_name) -> event -> [bodies]."""
    index: dict[tuple[str, str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for block in graph.get("business_logic", []):
        field_name = _field_name_from_context(block.get("context"))
        if not field_name:
            continue
        owner_type = block.get("owner_type") or "form"
        owner_name = block.get("owner_name") or ""
        event = (block.get("event") or "default").lower()
        body = block.get("body") or ""
        if body:
            index[(owner_type, owner_name, field_name)][event].append(body)
    return index


def _edge_lookups_by_form(graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_form: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in graph.get("edges", []):
        if edge.get("type") not in {"LOOKUP_VIA_VIEW", "REFERENCES_DATABASE", "ACCESSES_VIEW"}:
            continue
        src = edge.get("source") or {}
        if src.get("element_type") not in {"form", "subform"}:
            continue
        tgt = edge.get("target") or {}
        meta = edge.get("metadata") or {}
        by_form[src.get("name", "")].append(
            {
                "function": meta.get("function")
                or ("@DbLookup" if edge.get("type") == "LOOKUP_VIA_VIEW" else edge.get("type")),
                "target_database": meta.get("database")
                or (tgt.get("name") if tgt.get("element_type") == "database" else None),
                "target_view": tgt.get("name") if tgt.get("element_type") == "view" else meta.get("view"),
                "lookup_key": meta.get("lookup_field") or meta.get("key"),
                "return_field": meta.get("return_field") or meta.get("column_field"),
                "source": "edge",
                "edge_type": edge.get("type"),
                "evidence": (edge.get("evidence") or "")[:200],
            }
        )
    return by_form


def _dedupe_lookups(lookups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in lookups:
        key = (
            item.get("function"),
            item.get("target_database"),
            item.get("target_view"),
            item.get("lookup_key"),
            item.get("return_field"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _catalog_field(
    field: dict[str, Any],
    *,
    owner_type: str,
    owner_name: str,
    logic_index: dict[tuple[str, str, str], dict[str, list[str]]],
    form_edge_lookups: list[dict[str, Any]],
) -> dict[str, Any]:
    name = field.get("name") or ""
    logic = logic_index.get((owner_type, owner_name, name), {})
    formulas = _formula_bucket(field, logic)

    lookups: list[dict[str, Any]] = []
    for body in (
        formulas["default_value"],
        formulas["input_validation"],
        formulas["input_translation"],
        formulas["hide_when"],
        *(field.get("embedded_formulas") or []),
        *[b for bodies in logic.values() for b in bodies],
    ):
        if not body:
            continue
        lookups.extend(_lookups_from_formula(body))
        lookups.extend(_lookups_from_lotusscript(body))

    # Attach form-level edge lookups only when this field's formula mentions the view
    field_text = " ".join(
        filter(
            None,
            [
                formulas["default_value"],
                formulas["input_validation"],
                formulas["input_translation"],
                *(field.get("embedded_formulas") or []),
            ],
        )
    ).lower()
    for edge_lu in form_edge_lookups:
        view = (edge_lu.get("target_view") or "").lower()
        if view and view in field_text:
            lookups.append(edge_lu)

    validation = formulas["input_validation"]
    failure_messages = _failure_messages(validation)
    lookups = _dedupe_lookups(lookups)
    plain = describe_field_rules(
        field_name=name,
        data_type=field.get("type"),
        kind=field.get("kind"),
        default_value=formulas["default_value"],
        validation_formula=validation,
        failure_messages=failure_messages,
        input_translation=formulas["input_translation"],
        hide_when=formulas["hide_when"],
        lookups=lookups,
    )
    return {
        "name": name,
        "label": plain["label"],
        "data_type": field.get("type") or "unknown",
        "kind": field.get("kind"),
        "is_ref": bool(field.get("is_ref")),
        "business_summary": plain["business_summary"],
        "default_value": formulas["default_value"],
        "default_summary": plain["default_summary"],
        "input_validation": {
            "formula": validation,
            "failure_messages": failure_messages,
            "summary": plain["validation_summary"],
        }
        if validation
        else None,
        "input_translation": formulas["input_translation"],
        "translation_summary": plain["translation_summary"],
        "hide_when": formulas["hide_when"],
        "hide_summary": plain["hide_summary"],
        "lookups": lookups,
        "lookup_summary": plain["lookup_summary"],
    }


def extract_business_rules_catalog(graph: dict[str, Any]) -> dict[str, Any]:
    """
    Build a BusinessRulesCatalog JSON object from an application graph.

    Compatible with both newly enhanced field models (default_value /
    input_validation / …) and legacy graphs that only have embedded_formulas.
    """
    logic_index = _index_field_logic(graph)
    edge_by_form = _edge_lookups_by_form(graph)
    design = graph.get("design_elements", {})

    forms_out: list[dict[str, Any]] = []
    field_count = 0
    validation_count = 0
    lookup_count = 0
    hide_count = 0

    for element_type, key in (("form", "forms"), ("subform", "subforms")):
        for form in design.get(key, []):
            owner_name = form.get("name") or ""
            edge_lookups = edge_by_form.get(owner_name, [])
            fields_out: list[dict[str, Any]] = []
            for field in form.get("fields", []):
                entry = _catalog_field(
                    field,
                    owner_type=element_type,
                    owner_name=owner_name,
                    logic_index=logic_index,
                    form_edge_lookups=edge_lookups,
                )
                fields_out.append(entry)
                field_count += 1
                if entry.get("input_validation"):
                    validation_count += 1
                if entry.get("hide_when"):
                    hide_count += 1
                lookup_count += len(entry.get("lookups") or [])

            # Form-level LotusScript / validation not tied to a single field
            form_lookups: list[dict[str, Any]] = []
            form_rules: list[dict[str, Any]] = []
            for block in graph.get("business_logic", []):
                if block.get("owner_name") != owner_name:
                    continue
                if _field_name_from_context(block.get("context")):
                    continue
                body = block.get("body") or ""
                form_lookups.extend(_lookups_from_formula(body))
                form_lookups.extend(_lookups_from_lotusscript(body))
                if block.get("category") in {"validation", "state_transition"} or (
                    block.get("event") or ""
                ).lower() in {"inputvalidation", "querysave", "webquerysave"}:
                    form_rules.append(
                        {
                            "event": block.get("event"),
                            "category": block.get("category"),
                            "language": block.get("language"),
                            "failure_messages": _failure_messages(body),
                            "formula_excerpt": body[:400],
                        }
                    )

            forms_out.append(
                {
                    "form": owner_name,
                    "element_type": element_type,
                    "database_id": form.get("database_id") or form.get("source_file"),
                    "alias": form.get("alias"),
                    "fields": fields_out,
                    "form_rules": form_rules,
                    "form_lookups": _dedupe_lookups(form_lookups + edge_lookups),
                }
            )
            lookup_count += len(forms_out[-1]["form_lookups"])

    forms_out.sort(key=lambda f: (f.get("element_type", ""), f.get("form", "").lower()))

    return {
        "schema_version": SCHEMA_VERSION,
        "forms": forms_out,
        "totals": {
            "forms": sum(1 for f in forms_out if f["element_type"] == "form"),
            "subforms": sum(1 for f in forms_out if f["element_type"] == "subform"),
            "fields": field_count,
            "fields_with_validation": validation_count,
            "fields_with_hide_when": hide_count,
            "lookups": lookup_count,
        },
    }
