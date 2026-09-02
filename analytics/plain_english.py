"""
Turn Domino formula / LotusScript snippets into business-readable descriptions.

Heuristic — not an LLM — but covers the common patterns found in DXL exports
(defaults that copy fields, @Failure validations, @DbLookup, role lists, dates).
"""

from __future__ import annotations

import re
from typing import Any

RE_FAILURE = re.compile(r'@Failure\s*\(\s*"((?:\\.|[^"\\])*)"', re.I)
RE_SUCCESS = re.compile(r"@Success\b", re.I)
RE_IS_DOC_SAVED = re.compile(r"@IsDocBeingSaved", re.I)
RE_IS_NEW = re.compile(r"@IsNewDoc", re.I)
RE_USER_ROLES = re.compile(r"@UserRoles", re.I)
RE_DB_NAME = re.compile(r"@DbName", re.I)
RE_SUBSET_DB = re.compile(r"@Subset\s*\(\s*@DbName\s*;\s*1\s*\)", re.I)
RE_NAME_LOOKUP = re.compile(r"@NameLookup", re.I)
RE_COMMAND = re.compile(r"@Command\s*\(\s*\[([^\]]+)\]", re.I)
RE_IF = re.compile(r"@If\s*\(", re.I)
RE_YEAR = re.compile(r"@Year\s*\(", re.I)
RE_MONTH = re.compile(r"@Month\s*\(", re.I)
RE_DAY = re.compile(r"@Day\s*\(", re.I)
RE_TEXT = re.compile(r"@Text\s*\(", re.I)
RE_RIGHT = re.compile(r"@Right\s*\(", re.I)
RE_LEFT = re.compile(r"@Left\s*\(", re.I)
RE_RETURN = re.compile(r"@Return\s*\(", re.I)
RE_SIMPLE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RE_ROLE_TOKEN = re.compile(r'\["([^"]+)"\]|"(\[[^\]]+\])"')
RE_QUOTED = re.compile(r'"([^"]{1,80})"')
RE_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
RE_PREFIX = re.compile(r"^(h|tmp|temp|fld|fld_|f_|v_|c_|w_|web)(?=[A-Z_])", re.I)

# Common Domino field prefixes → business meaning
PREFIX_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^OH", re.I), "order header"),
    (re.compile(r"^OD", re.I), "order detail"),
    (re.compile(r"^JBA", re.I), "JBA / ERP"),
    (re.compile(r"Cust", re.I), "customer"),
    (re.compile(r"Ship", re.I), "shipping"),
    (re.compile(r"Bill", re.I), "billing"),
    (re.compile(r"Qty|Quantity", re.I), "quantity"),
    (re.compile(r"Price|Cost|Amt|Amount", re.I), "pricing"),
    (re.compile(r"Date|Dt$", re.I), "date"),
    (re.compile(r"Status", re.I), "status"),
    (re.compile(r"Author|Reader", re.I), "access control"),
]


def humanize_field_name(name: str) -> str:
    """Convert Domino field names into a readable label."""
    if not name:
        return "Field"
    raw = name.strip()
    cleaned = RE_PREFIX.sub("", raw)
    cleaned = cleaned.replace("_", " ").replace("-", " ")
    cleaned = RE_CAMEL.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        cleaned = raw
    # Keep known acronyms uppercase-ish
    words = []
    for w in cleaned.split(" "):
        if w.upper() in {"OH", "OD", "JBA", "ERP", "ADA", "ZIP", "ID", "SKU", "CC"}:
            words.append(w.upper())
        elif len(w) <= 2:
            words.append(w.upper() if w.isalpha() else w)
        else:
            words.append(w[:1].upper() + w[1:])
    return " ".join(words)


def _roles_from_text(text: str) -> list[str]:
    roles: list[str] = []
    for m in RE_ROLE_TOKEN.finditer(text):
        role = m.group(1) or m.group(2)
        if role and role not in roles:
            roles.append(role)
    return roles


def _lookups_plain(lookups: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for lu in lookups:
        view = lu.get("target_view") or "a view"
        db = lu.get("target_database")
        key = lu.get("lookup_key")
        ret = lu.get("return_field")
        fn = lu.get("function") or "lookup"
        bits = [f"Looks up data via {fn} in view “{view}”"]
        if db:
            bits.append(f"in database “{db}”")
        if key:
            bits.append(f"using key “{key}”")
        if ret:
            bits.append(f"returning “{ret}”")
        lines.append(" ".join(bits) + ".")
    return lines


def describe_formula(
    body: str | None,
    *,
    role: str = "logic",
    field_name: str | None = None,
    field_kind: str | None = None,
    lookups: list[dict[str, Any]] | None = None,
) -> str:
    """
    Produce a single plain-English sentence (or short paragraph) for a formula.

    ``role`` is one of: default | validation | translation | hidewhen | logic
    """
    if not body or not str(body).strip():
        return ""

    text = str(body).strip()
    lower = text.lower()
    label = humanize_field_name(field_name) if field_name else "This field"
    parts: list[str] = []

    # --- Validations ---
    failures = [m.group(1).replace('\\"', '"') for m in RE_FAILURE.finditer(text)]
    if failures or role == "validation":
        when = "when the document is saved" if RE_IS_DOC_SAVED.search(text) else "on input"
        if failures:
            msgs = "; ".join(f"“{m}”" for m in failures[:3])
            parts.append(f"Blocks save {when} unless the rule passes: {msgs}.")
        else:
            parts.append(f"Validates {label.lower()} {when}.")

    # --- Simple copy / constant defaults ---
    if role in {"default", "logic"} and RE_SIMPLE_IDENT.match(text):
        src = humanize_field_name(text)
        if field_kind and "computed" in field_kind.lower():
            parts.append(f"Computed by copying the value from “{src}”.")
        else:
            parts.append(f"Defaults to the value of “{src}”.")

    roles = _roles_from_text(text)
    if roles and ("author" in (field_name or "").lower() or "reader" in (field_name or "").lower() or ":" in text):
        joined = ", ".join(roles)
        if "author" in (field_name or "").lower():
            parts.append(f"Grants document edit rights to: {joined}.")
        elif "reader" in (field_name or "").lower():
            parts.append(f"Restricts document read access to: {joined}.")
        else:
            parts.append(f"Uses Domino roles: {joined}.")

    if RE_SUBSET_DB.search(text):
        parts.append("Captures the current Domino server name from the open database.")
    elif RE_DB_NAME.search(text):
        parts.append("Reads the current database identity (@DbName).")

    if RE_NAME_LOOKUP.search(text):
        parts.append("Looks up the current user’s directory profile (for example employee ID).")

    if RE_USER_ROLES.search(text):
        parts.append("Checks the current user’s Domino roles before applying the rule.")

    if RE_IS_NEW.search(text):
        parts.append("Behaves differently for new documents vs existing ones.")

    # Date packing / formatting heuristics
    if RE_YEAR.search(text) and (RE_MONTH.search(text) or RE_DAY.search(text)):
        if "jba" in lower or "century" in lower or RE_RIGHT.search(text):
            parts.append(
                f"Builds a system/ERP-friendly date string for {label.lower()} "
                "(year, month, and day packed into a coded format)."
            )
        else:
            parts.append(f"Derives a formatted date value for {label.lower()}.")

    if lookups:
        parts.extend(_lookups_plain(lookups)[:2])
    elif "@dblookup" in lower or "@dbcolumn" in lower:
        parts.append("Retrieves related information from another Domino view or database.")

    if role == "hidewhen":
        if RE_IF.search(text) or "@is" in lower:
            parts.append(f"Hides {label.lower()} based on document or field conditions.")
        elif not parts:
            parts.append(f"Conditionally hides {label.lower()} on the form.")

    if role == "translation" and not parts:
        parts.append(f"Normalizes or reformats {label.lower()} as the user leaves the field.")

    cmd = RE_COMMAND.search(text)
    if cmd:
        parts.append(f"Runs the Domino command [{cmd.group(1)}].")

    if text.lower().lstrip().startswith("sub ") or re.search(r"\bsub\s+\w+", text[:80], re.I):
        parts.append("Runs a LotusScript routine (custom server/client procedure).")

    if "messagebox" in lower or "msgbox" in lower:
        quoted = RE_QUOTED.findall(text)
        if quoted:
            parts.append(f"Shows the user a message: “{quoted[0]}”.")
        else:
            parts.append("Shows the user a dialog message.")

    if RE_IF.search(text) and not parts:
        parts.append(f"Applies conditional business logic to set {label.lower()}.")

    if not parts:
        # Last resort: short paraphrase from first non-empty line
        first = next((ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("'")), text)
        excerpt = first.replace("\n", " ")
        if len(excerpt) > 100:
            excerpt = excerpt[:97] + "…"
        if role == "default":
            return f"Sets the default/computed value for {label.lower()} using formula logic."
        if role == "validation":
            return f"Validates {label.lower()} before the document can be saved."
        return f"Business logic on {label.lower()}: {excerpt}"

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return " ".join(unique)


def describe_field_rules(
    *,
    field_name: str,
    data_type: str | None,
    kind: str | None,
    default_value: str | None,
    validation_formula: str | None,
    failure_messages: list[str] | None,
    input_translation: str | None,
    hide_when: str | None,
    lookups: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """Return plain-English summaries for each rule facet + an overall blurb."""
    lookups = lookups or []
    failure_messages = failure_messages or []

    default_summary = describe_formula(
        default_value, role="default", field_name=field_name, field_kind=kind, lookups=lookups if default_value else None
    )
    validation_summary = describe_formula(
        validation_formula, role="validation", field_name=field_name, field_kind=kind
    )
    if not validation_summary and failure_messages:
        validation_summary = "Blocks save unless the rule passes: " + "; ".join(
            f"“{m}”" for m in failure_messages[:3]
        ) + "."

    translation_summary = describe_formula(
        input_translation, role="translation", field_name=field_name, field_kind=kind
    )
    hide_summary = describe_formula(hide_when, role="hidewhen", field_name=field_name, field_kind=kind)
    lookup_summary = " ".join(_lookups_plain(lookups)[:3])

    label = humanize_field_name(field_name)
    kind_bit = ""
    if kind:
        k = kind.lower()
        if "computedfordisplay" in k:
            kind_bit = "display-only calculated field"
        elif "computedwhencomposed" in k:
            kind_bit = "set once when the document is created"
        elif "computed" in k:
            kind_bit = "system-calculated field"
        elif "editable" in k:
            kind_bit = "user-editable field"
    type_bit = f"{data_type} " if data_type and data_type != "unknown" else ""

    overview_bits = [f"{label} is a {type_bit}{kind_bit or 'form field'}.".replace("  ", " ")]
    for piece in (default_summary, validation_summary, hide_summary, lookup_summary):
        if piece and piece not in overview_bits:
            overview_bits.append(piece)

    return {
        "label": label,
        "business_summary": " ".join(overview_bits).strip(),
        "default_summary": default_summary,
        "validation_summary": validation_summary,
        "translation_summary": translation_summary,
        "hide_summary": hide_summary,
        "lookup_summary": lookup_summary,
    }
