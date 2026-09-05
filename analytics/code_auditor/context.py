"""Shared execution-context helpers for loop-aware severity and templates."""

from __future__ import annotations

import re
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# LotusScript + Java/SSJS loop constructs
RE_ANY_LOOP = re.compile(
    r"(?is)\b(?:"
    r"Do\s+While|Do\s+Until|Forall|(?<![\w.])While\b|Wend\b|End\s+Forall|"
    r"For\s+[A-Za-z_]\w*\s*=|"  # LotusScript For i =
    r"\bfor\s*\(|\bwhile\s*\("  # Java/SSJS
    r")",
)

# Rules where missing cleanup inside a loop is handle-exhaustion (CRITICAL).
# Outside a loop they are routine hygiene (MEDIUM/LOW).
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
        "LS-DOM-001",
        "LS-DOM-002",
        "LS-DOM-004",
        "LS-DOM-005",
        "LS-DOM-006",
        "LS-DOM-007",
        "LS-DOM-008",
        "DOM-BS-001",
        "DOM-BS-002",
    }
)

NON_LOOP_HYGIENE_NOTE = (
    "Non-loop single execution: Low risk of handle table exhaustion, "
    "recommended for general code hygiene."
)


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


def inventory_risk_severity(*, status: str, in_loop: bool) -> Severity:
    """Severity shown on Function Inventory deep-dives."""
    if status == "PROTECTED":
        return "LOW"
    if status == "SAFE_NO_HANDLES":
        return "LOW"
    # UNPROTECTED_ALLOCATION
    if in_loop:
        return "CRITICAL"
    return "LOW"


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
