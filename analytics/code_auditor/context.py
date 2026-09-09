"""Shared execution-context helpers for loop-aware severity and templates."""

from __future__ import annotations

import re
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# LotusScript + Java/SSJS loop constructs
RE_ANY_LOOP = re.compile(
    r"(?is)\b(?:"
    r"Do\s+While|Do\s+Until|Forall|(?<![\w.])While\b|Wend\b|End\s+Forall|"
    r"For\s+[A-Za-z_]\w*\s*=|"  # LotusScript For i =
    r"\bfor\s*\(|\bwhile\s*\("  # Java/SSJS
    r")",
)

# C-API / Notes handle-table exhaustion applies to Java, SSJS, XPages — not LotusScript
# and not browser Client JavaScript (CSJS).
CAPI_HANDLE_LANG_TOKENS = (
    "java",
    "ssjs",
    "javascript",  # legacy / ambiguous server JS label
    "jscript",
    "xpage",
    "xsp",
)

# Explicit client-side JS — DOM C-API .recycle() does not apply in the browser.
CLIENT_JS_LANG_TOKENS = (
    "csjs",
    "client_javascript",
    "client-javascript",
    "client js",
)

# Rules where missing cleanup inside a loop is handle-exhaustion (CRITICAL).
# Outside a loop they are routine hygiene (MEDIUM/LOW).
# LotusScript LS-DOM-* intentionally omitted — not the same C-API exhaustion model.
LOOP_SENSITIVE_HANDLE_RULES = frozenset(
    {
        "DOM-001",
        "DOM-002",
        "DOM-003",
        "DOM-010",
        "DOM-011",
        "DOM-012",
        "DOM-013",
        "DOM-014",
        "DOM-015",
        "DOM-016",
        "DOM-BS-001",
        "DOM-BS-002",
        "DOM-OWN-001",
    }
)

NON_LOOP_HYGIENE_NOTE = (
    "Non-loop single execution: Low risk of handle table exhaustion, "
    "recommended for general code hygiene."
)


def is_lotusscript_language(lang: str | None) -> bool:
    low = (lang or "").lower()
    return "lotus" in low or low in {"ls", "lss", "notes"}


def is_client_javascript(
    lang: str | None,
    *,
    event: str | None = None,
    element_name: str | None = None,
) -> bool:
    """True for Domino Client JavaScript (CSJS) — not C-API handle exhaustion."""
    low = (lang or "").lower().strip()
    if any(tok in low for tok in CLIENT_JS_LANG_TOKENS) or low in {"csjs", "client"}:
        return True
    if (event or "").lower() in {"client_library", "client", "csjs"}:
        return True
    name = (element_name or "").lower()
    leaf = name.split(":")[-1].strip()
    # csjsClaims, Copy Of csjsPcspMailing, scriptlibrary:csjsFoo
    if leaf.startswith("csjs") or " csjs" in leaf or leaf.startswith("copy of csjs"):
        return True
    if re.search(r"(^|[\s:/_\-])csjs(?![a-z])", name):
        return True
    return False


def is_ssjs_language(
    lang: str | None,
    *,
    event: str | None = None,
    element_name: str | None = None,
) -> bool:
    """True for Domino Server JavaScript libraries / SSJS."""
    if is_client_javascript(lang, event=event, element_name=element_name):
        return False
    low = (lang or "").lower().strip()
    name = (element_name or "").lower()
    leaf = name.split(":")[-1].strip()
    if leaf.startswith("ssjs") or " ssjs" in leaf or leaf.startswith("copy of ssjs"):
        return True
    if low in {"ssjs", "jscript"} or low == "javascript" or low == "js":
        return True
    if "ssjs" in low and "csjs" not in low:
        return True
    if (event or "").lower() in {"library", "server_library", "ssjs"}:
        return True
    if re.search(r"(^|[\s:/_\-])ssjs(?![a-z])", name):
        return True
    return False


def is_java_language(lang: str | None) -> bool:
    low = (lang or "").lower().strip()
    if is_lotusscript_language(lang) or is_client_javascript(lang):
        return False
    if "javascript" in low or "ssjs" in low or "jscript" in low or low in {"js", "csjs"}:
        return False
    return "java" in low or low == "java"


def is_java_or_ssjs_language(
    lang: str | None,
    *,
    event: str | None = None,
    element_name: str | None = None,
) -> bool:
    """Primary work-list languages: Java agents/classes and SSJS (not CSJS / XPages / LS)."""
    if is_client_javascript(lang, event=event, element_name=element_name):
        return False
    low = (lang or "").lower()
    if "xpage" in low or low in {"xsp", "formula"}:
        return False
    if is_java_language(lang):
        return True
    return is_ssjs_language(lang, event=event, element_name=element_name)


def is_capi_handle_language(
    lang: str | None,
    *,
    event: str | None = None,
    element_name: str | None = None,
) -> bool:
    """True for Java / SSJS / JavaScript / XPages — languages that recycle() C-API handles."""
    if is_lotusscript_language(lang):
        return False
    if is_client_javascript(lang, event=event, element_name=element_name):
        return False
    low = (lang or "").lower()
    if low in {"formula", "unknown", ""}:
        return False
    return any(tok in low for tok in CAPI_HANDLE_LANG_TOKENS) or low in {"js", "source", "script"}


def contributes_to_handle_exhaustion(finding: Any) -> bool:
    """Whether a finding should drive Handle Exhaustion Risk (Java/JS C-API recycle only)."""
    if getattr(finding, "is_false_positive", False):
        return False
    rid = getattr(finding, "rule_id", "") or ""
    if rid.startswith("LS-DOM"):
        return False
    if rid.startswith(("PERF-", "SEC-", "FORM-")):
        return False
    if not rid.startswith("DOM-"):
        return False
    return is_capi_handle_language(getattr(finding, "language", None))


def body_has_loop(body: str | None) -> bool:
    if not body:
        return False
    return RE_ANY_LOOP.search(body) is not None


def calibrate_handle_severity(
    rule_id: str,
    default_severity: str,
    *,
    in_loop: bool | None = None,
    body: str | None = None,
) -> Severity:
    """
    Loop-aware severity:
      - In a collection/hot loop → CRITICAL (handle exhaustion)
      - One-shot helper / no loop → LOW or MEDIUM (routine hygiene)
    """
    sev = (default_severity or "MEDIUM").upper()
    if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        sev = "MEDIUM"
    if rule_id not in LOOP_SENSITIVE_HANDLE_RULES:
        return sev  # type: ignore[return-value]

    if in_loop is None:
        in_loop = body_has_loop(body)

    if in_loop:
        # Exhaustion path — promote hygiene findings to CRITICAL in loops
        if sev in {"HIGH", "MEDIUM"}:
            return "CRITICAL"
        return sev  # type: ignore[return-value]

    # One-shot / non-loop demotion
    if sev == "CRITICAL":
        return "MEDIUM"
    if sev == "HIGH":
        return "MEDIUM"
    if sev == "MEDIUM":
        return "LOW"
    return "LOW"


def inventory_risk_severity(
    *,
    status: str,
    in_loop: bool,
    language: str | None = None,
    event: str | None = None,
    element_name: str | None = None,
) -> Severity:
    """Severity shown on Function Inventory deep-dives.

    Client JavaScript (CSJS) is always LOW — browser scripts are not C-API handle-table
    exhaustion. SSJS / Java keep loop-aware CRITICAL/HIGH scoring.
    """
    if is_client_javascript(language, event=event, element_name=element_name):
        return "LOW"
    if status == "PROTECTED":
        return "LOW"
    if status == "SAFE_NO_HANDLES":
        return "LOW"
    if status == "CONDITIONAL_CLEANUP":
        return "HIGH" if in_loop else "MEDIUM"
    if status == "ESCAPE_PATH_GAP":
        return "CRITICAL" if in_loop else "HIGH"
    if status == "PARTIAL_CLEANUP":
        return "CRITICAL" if in_loop else "MEDIUM"
    # UNPROTECTED_ALLOCATION
    if in_loop:
        return "CRITICAL"
    return "LOW"


def inventory_language_priority(
    language: str | None,
    *,
    event: str | None = None,
    element_name: str | None = None,
) -> int:
    """Sort key: SSJS first (0), Java (1), other server (2), CSJS last (3)."""
    if is_client_javascript(language, event=event, element_name=element_name):
        return 3
    if is_ssjs_language(language, event=event, element_name=element_name):
        return 0
    if is_java_language(language):
        return 1
    return 2


def inventory_ring_risk_class(
    safety_rate: float,
    recycle_among_allocators: float,
    allocating: int,
) -> str:
    """Mirror of web/app.js ``inventoryRiskClass`` — CSS risk-* class for the inventory ring.

    When any functions allocate handles but fewer than 50% clean up, force
    ``risk-high`` even if the blended handle_safety_rate looks healthy.
    """
    if allocating > 0 and recycle_among_allocators < 50:
        return "risk-high"
    if safety_rate < 40:
        return "risk-high"
    if safety_rate < 75:
        return "risk-moderate"
    return "risk-low"
