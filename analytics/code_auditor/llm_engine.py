"""AI discrepancy & blind-spot auditor for Domino DXL code review.

When ``--llm`` is active, runs a two-pass cross-validation:

1. **False Positive Filter** — review rule hits for safe/non-standard cleanup.
2. **Blind-Spot Detector** — find handle leaks missed by static rules.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from analytics.code_auditor.models import RULE_CATALOG, CodeUnit, Finding
from analytics.code_auditor.snippets import attach_snippet_fields, remediation_template

HANDLE_ALLOC_HINT = re.compile(
    r"\bNotes(?:Document|View|Database|ViewEntry|DateTime|Session)\b"
    r"|\b(?:Document|View|Database|ViewEntry|DateTime)\b"
    r"|\b(?:createDateTime|createViewNav|GetDocumentByUNID|GetFirstDocument|"
    r"GetNextDocument|GetEntryByKey|getDocumentByUNID|getFirstDocument|"
    r"getNextDocument|getView|getDatabase|CreateDocument)\b",
    re.I,
)

FP_SYSTEM_PROMPT = """You are a Domino architecture expert performing FALSE-POSITIVE review.
You receive static-rule findings plus the surrounding code.

For each finding, decide:
- FALSE_POSITIVE — the code safely handles / recycles the object via non-standard means
  (ODA auto-lifecycle, custom helper that Deletes/recycles, early return after Delete,
  framework wrapper, LotusScript scope exit that is actually safe, etc.)
- VERIFIED — the leak / anti-pattern is real and still needs remediation.

Return ONLY valid JSON:
{
  "reviews": [
    {
      "finding_id": "F-001",
      "verdict": "VERIFIED|FALSE_POSITIVE",
      "confidence": 0-100,
      "reasoning": "1-3 sentences explaining why"
    }
  ]
}
Be conservative: only mark FALSE_POSITIVE when cleanup is clearly present or framework-owned.
"""

BLIND_SPOT_SYSTEM_PROMPT = """You are a Domino architecture expert hunting BLIND-SPOT handle leaks.
Static regex rules found ZERO issues in this code block, but Domino handles appear to be allocated.

Analyze logical control flow for native C-API handle leaks hidden in:
- nested branches / early exits
- conditional loops that skip Delete / .recycle()
- exception handlers that bypass cleanup
- re-assignment without releasing the prior handle
- module-level lifetime mistakes

LotusScript prefers Delete (and Call obj.Recycle); Java/SSJS prefer try/finally + .recycle().
ODA (org.openntf.domino) usually must NOT be manually recycled.

Return ONLY valid JSON:
{
  "blind_spots": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "line_hint": 1,
      "evidence": "short code excerpt",
      "technical_impact": "why it matters",
      "remediation": "fixed pattern guidance",
      "action_required": "short action",
      "reasoning": "why static rules missed this"
    }
  ]
}
If the code is genuinely safe, return {"blind_spots": []}.
Only report high-confidence real leaks (prefer confidence >= 75).
"""


def llm_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY", "").strip())


def _client():
    from openai import OpenAI

    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def _chat_json(system: str, user_payload: dict[str, Any], *, model: str) -> dict[str, Any]:
    client = _client()
    response = client.chat.completions.create(
        model=model,
        response_format={"type": "json_object"},
        temperature=0.1,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
    )
    content = response.choices[0].message.content or "{}"
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _unit_key(unit: CodeUnit) -> tuple[str, str]:
    return (unit.source_file, unit.element_name)


def _finding_unit_key(finding: Finding) -> tuple[str, str]:
    return (finding.source_file, finding.element_name)


def _pass1_false_positive_filter(
    units: list[CodeUnit],
    findings: list[Finding],
    *,
    model: str,
    max_units: int,
    notes: list[str],
) -> None:
    """Annotate / demote rule findings the model marks as FALSE_POSITIVE (in-place)."""
    by_unit: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        by_unit.setdefault(_finding_unit_key(f), []).append(f)

    unit_map = {_unit_key(u): u for u in units}
    # Prefer units with the most rule hits
    ranked_keys = sorted(by_unit.keys(), key=lambda k: -len(by_unit[k]))[:max_units]
    reviewed = 0
    fps = 0

    for key in ranked_keys:
        unit = unit_map.get(key)
        if unit is None:
            # Synthesize a minimal unit from finding metadata
            sample = by_unit[key][0]
            unit = CodeUnit(
                source_file=sample.source_file,
                element_name=sample.element_name,
                element_type=sample.element_type,
                language=sample.language,
                event=None,
                body=sample.evidence,
            )
        batch = by_unit[key]
        user_payload = {
            "source_file": unit.source_file,
            "element": f"{unit.element_type}:{unit.element_name}",
            "language": unit.language,
            "code": unit.body[:12000],
            "findings": [
                {
                    "finding_id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "line": f.line,
                    "evidence": (f.evidence or "")[:500],
                    "technical_impact": f.technical_impact,
                }
                for f in batch
            ],
        }
        try:
            payload = _chat_json(FP_SYSTEM_PROMPT, user_payload, model=model)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"AI FP filter error on {unit.element_name}: {exc}")
            continue

        by_id = {f.id: f for f in batch}
        for review in payload.get("reviews") or []:
            fid = str(review.get("finding_id") or "")
            finding = by_id.get(fid)
            if not finding:
                continue
            verdict = str(review.get("verdict") or "VERIFIED").upper().strip()
            reasoning = str(review.get("reasoning") or "").strip()
            reviewed += 1
            if verdict == "FALSE_POSITIVE":
                finding.ai_validation_status = "FALSE_POSITIVE"
                finding.ai_validation_reasoning = reasoning or (
                    "AI judged this rule hit safe due to non-standard cleanup / framework ownership."
                )
                finding.is_false_positive = True
                finding.is_blind_spot = False
                finding.engine = "hybrid"
                finding.severity = "LOW"  # demote — retained for UI "Flagged False Positives"
                finding.confidence = min(finding.confidence, 40)
                fps += 1
            else:
                finding.ai_validation_status = "VERIFIED"
                finding.ai_validation_reasoning = reasoning or (
                    "AI confirmed the static rule hit is a real handle / lifecycle risk."
                )
                finding.is_false_positive = False
                finding.engine = "hybrid" if finding.engine == "rules" else finding.engine

    notes.append(
        f"AI Pass 1 (false-positive filter): reviewed {reviewed} finding(s), "
        f"flagged {fps} false positive(s)."
    )


def _pass2_blind_spot_detector(
    units: list[CodeUnit],
    findings: list[Finding],
    *,
    model: str,
    max_units: int,
    notes: list[str],
) -> list[Finding]:
    """Discover handle leaks in units with allocations but zero rule hits."""
    hit_units = {_finding_unit_key(f) for f in findings if not f.is_false_positive}
    candidates = [
        u
        for u in units
        if _unit_key(u) not in hit_units and HANDLE_ALLOC_HINT.search(u.body or "")
    ]
    ranked = sorted(candidates, key=lambda u: (-len(u.keywords_matched), -len(u.body)))
    selected = ranked[:max_units]
    new_findings: list[Finding] = []
    spots = 0

    meta = RULE_CATALOG["DOM-BS-001"]
    for unit in selected:
        user_payload = {
            "source_file": unit.source_file,
            "element": f"{unit.element_type}:{unit.element_name}",
            "language": unit.language,
            "event": unit.event,
            "keywords": unit.keywords_matched,
            "code": unit.body[:12000],
            "note": "Static rules reported 0 findings for this block.",
        }
        try:
            payload = _chat_json(BLIND_SPOT_SYSTEM_PROMPT, user_payload, model=model)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"AI blind-spot error on {unit.element_name}: {exc}")
            continue

        for raw in payload.get("blind_spots") or []:
            try:
                confidence = int(raw.get("confidence") or 70)
            except (TypeError, ValueError):
                confidence = 70
            confidence = max(0, min(100, confidence))
            if confidence < 75:
                continue
            severity = str(raw.get("severity") or meta["default_severity"]).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = meta["default_severity"]
            try:
                line = int(raw.get("line_hint") or unit.start_line)
            except (TypeError, ValueError):
                line = unit.start_line

            evidence = str(raw.get("evidence") or unit.body[:200])
            impact = str(raw.get("technical_impact") or "Hidden Domino handle leak missed by static rules.")
            reasoning = str(raw.get("reasoning") or "Complex control flow bypassed regex detectors.")
            rem = remediation_template("DOM-BS-001", unit.language)
            snippet_fields = attach_snippet_fields(
                unit=unit,
                focus_line=line,
                evidence=evidence,
                remediation=rem,
                handle_lifecycle_warning=impact,
                rule_id="DOM-BS-001",
            )
            new_findings.append(
                Finding(
                    id="",
                    rule_id="DOM-BS-001",
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
                    action_required=str(raw.get("action_required") or "Review AI-discovered blind-spot leak."),
                    category=meta["category"],
                    engine="llm",
                    ai_validation_status="BLIND_SPOT",
                    ai_validation_reasoning=reasoning,
                    is_blind_spot=True,
                    is_false_positive=False,
                    **snippet_fields,
                )
            )
            spots += 1

    notes.append(
        f"AI Pass 2 (blind-spot detector): scanned {len(selected)} clean-but-allocating block(s), "
        f"added {spots} DOM-BS-001 finding(s)."
    )
    return new_findings


def enrich_with_llm(
    units: list[CodeUnit],
    existing: list[Finding],
    *,
    max_units: int = 25,
    model: str | None = None,
) -> tuple[list[Finding], list[str]]:
    """
    Two-pass AI discrepancy audit:

    1. False-positive filter on rule findings
    2. Blind-spot detection on handle-allocating blocks with zero rule hits
    """
    notes: list[str] = []
    if not llm_available():
        notes.append("OPENAI_API_KEY not set — skipped AI discrepancy audit (rules-only).")
        return existing, notes

    model_name = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    # Ensure stable IDs before Pass 1 references finding_id
    working = list(existing)
    for idx, finding in enumerate(working, start=1):
        finding.id = f"F-{idx:03d}"

    # Split budget roughly half/half between the two passes
    pass1_budget = max(5, max_units // 2)
    pass2_budget = max(5, max_units - pass1_budget)

    notes.append(
        f"AI discrepancy audit enabled (model={model_name}, "
        f"pass1_units≤{pass1_budget}, pass2_units≤{pass2_budget})."
    )

    if working:
        _pass1_false_positive_filter(
            units, working, model=model_name, max_units=pass1_budget, notes=notes
        )
    else:
        notes.append("AI Pass 1 skipped — no static rule findings to review.")

    blind_spots = _pass2_blind_spot_detector(
        units, working, model=model_name, max_units=pass2_budget, notes=notes
    )
    merged = working + blind_spots
    for idx, finding in enumerate(merged, start=1):
        finding.id = f"F-{idx:03d}"
    return merged, notes


# Back-compat: older callers may still import this symbol
SYSTEM_PROMPT = BLIND_SPOT_SYSTEM_PROMPT


def analyze_unit_with_llm(unit: CodeUnit, *, model: str | None = None) -> list[Finding]:
    """Legacy single-unit scan — now routes through blind-spot prompt for one block."""
    if not llm_available():
        return []
    model_name = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    notes: list[str] = []
    return _pass2_blind_spot_detector([unit], [], model=model_name, max_units=1, notes=notes)
