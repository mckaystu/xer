"""Optional LLM enrichment for Domino code audit findings."""

from __future__ import annotations

import json
import os
from typing import Any

from analytics.code_auditor.models import RULE_CATALOG, CodeUnit, Finding
from analytics.code_auditor.snippets import attach_snippet_fields, remediation_template

SYSTEM_PROMPT = """You are a Domino architecture expert auditing Java, SSJS/XPages, and LotusScript
for C-API handle leaks, ODA vs lotus.domino conflicts, static handle lifetime bugs, and
high-memory Domino data access patterns.

Return ONLY valid JSON with this schema:
{
  "findings": [
    {
      "rule_id": "DOM-001|DOM-002|DOM-003|DOM-004|DOM-005|DOM-006|DOM-007|DOM-008|DOM-009",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "line_hint": 1,
      "evidence": "exact snippet",
      "technical_impact": "why it matters",
      "remediation": "fixed code sample",
      "action_required": "short action"
    }
  ]
}

Confidence guidance:
- 90-100: deterministic anti-pattern clearly present
- 70-89: structural leak likely
- <70: heuristic suspicion only
If no issues, return {"findings": []}.
"""


def llm_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY", "").strip())


def _client():
    from openai import OpenAI

    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_unit_with_llm(unit: CodeUnit, *, model: str | None = None) -> list[Finding]:
    if not llm_available():
        return []

    model = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    user_payload = {
        "source_file": unit.source_file,
        "element": f"{unit.element_type}:{unit.element_name}",
        "language": unit.language,
        "event": unit.event,
        "keywords": unit.keywords_matched,
        "code": unit.body[:12000],
    }

    client = _client()
    response = client.chat.completions.create(
        model=model,
        response_format={"type": "json_object"},
        temperature=0.1,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
    )
    content = response.choices[0].message.content or "{}"
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for raw in payload.get("findings") or []:
        rule_id = str(raw.get("rule_id") or "").upper()
        if rule_id not in RULE_CATALOG:
            # Allow free-form but map unknowns to DOM-003
            rule_id = "DOM-003"
        meta = RULE_CATALOG[rule_id]
        severity = str(raw.get("severity") or meta["default_severity"]).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = meta["default_severity"]
        try:
            confidence = int(raw.get("confidence") or 70)
        except (TypeError, ValueError):
            confidence = 70
        confidence = max(0, min(100, confidence))
        line_hint = raw.get("line_hint") or unit.start_line
        try:
            line = int(line_hint)
        except (TypeError, ValueError):
            line = unit.start_line

        rem = remediation_template(rule_id, unit.language)
        evidence = str(raw.get("evidence") or unit.body[:200])
        impact = str(raw.get("technical_impact") or "Potential Domino handle / memory risk.")
        snippet_fields = attach_snippet_fields(
            unit=unit,
            focus_line=line,
            evidence=evidence,
            remediation=rem,
            handle_lifecycle_warning=impact,
            rule_id=rule_id,
        )
        findings.append(
            Finding(
                id="",
                rule_id=rule_id,
                title=meta["title"],
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,
                source_file=unit.source_file,
                element_name=unit.element_name,
                element_type=unit.element_type,
                language=unit.language,
                line=line,
                evidence=evidence,
                technical_impact=impact,
                remediation=rem,
                action_required=str(raw.get("action_required") or "Review and remediate."),
                category=meta["category"],
                engine="llm",
                **snippet_fields,
            )
        )
    return findings


def enrich_with_llm(
    units: list[CodeUnit],
    existing: list[Finding],
    *,
    max_units: int = 25,
    model: str | None = None,
) -> tuple[list[Finding], list[str]]:
    """Run LLM on top prefiltered units not already covered heavily by rules."""
    notes: list[str] = []
    if not llm_available():
        notes.append("OPENAI_API_KEY not set — skipped LLM enrichment (rules-only audit).")
        return existing, notes

    covered = {(f.source_file, f.element_name, f.rule_id) for f in existing}
    # Prefer units with more keyword hits
    ranked = sorted(units, key=lambda u: (-len(u.keywords_matched), -len(u.body)))
    selected = ranked[:max_units]
    notes.append(f"LLM enrichment enabled for {len(selected)} code block(s).")

    llm_findings: list[Finding] = []
    for unit in selected:
        try:
            block_findings = analyze_unit_with_llm(unit, model=model)
        except Exception as exc:  # noqa: BLE001 — auditor should continue
            notes.append(f"LLM error on {unit.element_name}: {exc}")
            continue
        for finding in block_findings:
            key = (finding.source_file, finding.element_name, finding.rule_id)
            if key in covered:
                # Upgrade engine tag on duplicate rule hits
                continue
            covered.add(key)
            llm_findings.append(finding)

    merged = list(existing) + llm_findings
    for idx, finding in enumerate(merged, start=1):
        finding.id = f"F-{idx:03d}"
    return merged, notes
