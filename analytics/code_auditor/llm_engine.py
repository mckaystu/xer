"""AI discrepancy & blind-spot auditor for Domino DXL code review.

When ``--llm`` is active, runs a three-pass cross-validation:

1. **False Positive Filter** — review rule hits for safe/non-standard cleanup.
2. **Blind-Spot Detector** — find handle leaks missed by static rules.
3. **Cross-Module Ownership** — caller/callee contracts + dynamic severity escalation.
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

FP_SYSTEM_PROMPT = """You are a Domino architecture expert performing FALSE-POSITIVE and
SEVERITY CONTEXT review.
You receive static-rule findings plus the surrounding code.

For each finding, decide:
- FALSE_POSITIVE — the code safely handles / recycles the object via non-standard means
  (ODA auto-lifecycle, custom helper that Deletes/recycles, early return after Delete,
  framework wrapper, LotusScript scope exit that is actually safe, etc.)
- VERIFIED_NON_LOOP — the leak / missing Delete is real BUT the allocation is in a
  one-shot helper / single-execution path (no Do While / Forall / while / for collection
  loop). Demote severity to LOW. This is routine memory hygiene, not handle-table exhaustion.
- VERIFIED — the leak / anti-pattern is real and still needs remediation (especially when
  inside a long-running collection loop or hot agent path).

Return ONLY valid JSON:
{
  "reviews": [
    {
      "finding_id": "F-001",
      "verdict": "VERIFIED|FALSE_POSITIVE|VERIFIED_NON_LOOP",
      "confidence": 0-100,
      "reasoning": "1-3 sentences explaining why",
      "in_loop": true
    }
  ]
}
Be conservative: only mark FALSE_POSITIVE when cleanup is clearly present or framework-owned.
Use VERIFIED_NON_LOOP when the un-deleted handle is clearly outside any iteration loop.
"""

NON_LOOP_AI_NOTE = (
    "Non-loop single execution: Low risk of handle table exhaustion, "
    "recommended for general code hygiene."
)

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

PASS3_SYSTEM_PROMPT = """You are a Domino architecture expert performing CROSS-MODULE handle ownership
analysis and dynamic risk escalation.

You receive multiple related code units (functions/subs) from the same application.

Tasks:
1) Cross-boundary ownership: if a function returns Document/NotesDocument OR accepts one as a
   parameter, decide whether caller or callee is responsible for Delete/.recycle(). If NEITHER
   clearly releases the handle, emit an ownership finding.
2) Risk escalation: if a leak/path runs in a scheduled/background agent (Initialize of an agent,
   polling loop, bulk processor) vs a one-shot UI event, escalate severity.
3) To-Be sanity: when suggesting remediation, preserve return values and business/transaction logic.

Return ONLY valid JSON:
{
  "ownership_gaps": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "element_name": "function or design element name",
      "line_hint": 1,
      "evidence": "short excerpt",
      "technical_impact": "why ownership is unclear",
      "action_required": "who should Delete/recycle",
      "reasoning": "caller/callee contract analysis",
      "execution_context": "background_agent|form_event|library|unknown",
      "escalate": true
    }
  ],
  "severity_adjustments": [
    {
      "finding_id": "F-001",
      "new_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "reasoning": "why escalate/demote based on hot path / background thread"
    }
  ]
}
If nothing to report: {"ownership_gaps": [], "severity_adjustments": []}.
Prefer confidence >= 75 for ownership_gaps.
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
            elif verdict in {"VERIFIED_NON_LOOP", "NON_LOOP", "VERIFIED_HYGIENE"}:
                finding.ai_validation_status = "VERIFIED_NON_LOOP"
                note = NON_LOOP_AI_NOTE
                finding.ai_validation_reasoning = (
                    (reasoning + " | " if reasoning else "") + note
                )
                finding.is_false_positive = False
                finding.is_blind_spot = False
                finding.engine = "hybrid"
                finding.severity = "LOW"
                finding.confidence = max(finding.confidence, 70)
                if note not in (finding.technical_impact or ""):
                    finding.technical_impact = (
                        (finding.technical_impact or "").rstrip() + " " + note
                    ).strip()
                if note not in (finding.handle_lifecycle_warning or ""):
                    finding.handle_lifecycle_warning = (
                        (finding.handle_lifecycle_warning or "").rstrip() + " " + note
                    ).strip()
            else:
                finding.ai_validation_status = "VERIFIED"
                finding.ai_validation_reasoning = reasoning or (
                    "AI confirmed the static rule hit is a real handle / lifecycle risk."
                )
                finding.is_false_positive = False
                finding.engine = "hybrid" if finding.engine == "rules" else finding.engine
                # If model reports in_loop=false but verdict VERIFIED, still demote gently
                if review.get("in_loop") is False and finding.severity in {
                    "CRITICAL",
                    "HIGH",
                }:
                    finding.severity = "MEDIUM"
                    finding.ai_validation_status = "VERIFIED_NON_LOOP"
                    finding.ai_validation_reasoning = (
                        (finding.ai_validation_reasoning + " | " if finding.ai_validation_reasoning else "")
                        + NON_LOOP_AI_NOTE
                    )
                    finding.severity = "LOW"

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


def _pass3_cross_module_ownership(
    units: list[CodeUnit],
    findings: list[Finding],
    *,
    model: str,
    max_units: int,
    notes: list[str],
) -> list[Finding]:
    """Pass 3: cross-function ownership gaps + dynamic severity escalation."""
    candidates = [
        u
        for u in units
        if re.search(
            r"(?i)\b(?:NotesDocument|Document)\b|As\s+NotesDocument|Function\s+\w+\s+As\s+NotesDocument"
            r"|getDocument|GetDocument",
            u.body or "",
        )
    ]
    ranked = sorted(candidates, key=lambda u: (-len(u.keywords_matched), -len(u.body)))
    selected = ranked[: max(4, min(max_units, 12))]
    if len(selected) < 2:
        notes.append("AI Pass 3 skipped — fewer than 2 cross-module candidate units.")
        return []

    payload = {
        "units": [
            {
                "element": f"{u.element_type}:{u.element_name}",
                "language": u.language,
                "event": u.event,
                "code": (u.body or "")[:8000],
            }
            for u in selected
        ],
        "existing_findings": [
            {
                "finding_id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "element": f"{f.element_type}:{f.element_name}",
                "title": f.title,
            }
            for f in findings
            if not f.is_false_positive
        ][:40],
    }
    try:
        result = _chat_json(PASS3_SYSTEM_PROMPT, payload, model=model)
    except Exception as exc:  # noqa: BLE001
        notes.append(f"AI Pass 3 error: {exc}")
        return []

    by_id = {f.id: f for f in findings}
    adjusted = 0
    for adj in result.get("severity_adjustments") or []:
        fid = str(adj.get("finding_id") or "")
        finding = by_id.get(fid)
        if not finding or finding.is_false_positive:
            continue
        new_sev = str(adj.get("new_severity") or "").upper()
        if new_sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            continue
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if order[new_sev] > order.get(finding.severity, 0):
            finding.severity = new_sev  # type: ignore[assignment]
            reason = str(adj.get("reasoning") or "Escalated due to hot/background execution context.")
            finding.ai_validation_reasoning = (
                (finding.ai_validation_reasoning + " | " if finding.ai_validation_reasoning else "")
                + f"Severity escalated to {new_sev}: {reason}"
            )
            finding.engine = "hybrid"
            adjusted += 1

    meta = RULE_CATALOG["DOM-BS-002"]
    unit_by_name = {u.element_name: u for u in selected}
    new_findings: list[Finding] = []
    for raw in result.get("ownership_gaps") or []:
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
        if raw.get("escalate") and severity in {"MEDIUM", "LOW"}:
            severity = "HIGH"
        if raw.get("execution_context") == "background_agent" and severity != "CRITICAL":
            severity = "CRITICAL" if severity == "HIGH" else "HIGH"

        element_name = str(raw.get("element_name") or selected[0].element_name)
        unit = unit_by_name.get(element_name) or next(
            (u for u in selected if element_name.lower() in (u.element_name or "").lower()),
            selected[0],
        )
        try:
            line = int(raw.get("line_hint") or unit.start_line)
        except (TypeError, ValueError):
            line = unit.start_line
        evidence = str(raw.get("evidence") or unit.body[:200])
        impact = str(raw.get("technical_impact") or "Unclear cross-function handle ownership.")
        reasoning = str(raw.get("reasoning") or "Caller/callee contract does not assign Delete/recycle.")
        rem = remediation_template("DOM-BS-002", unit.language)
        snippet_fields = attach_snippet_fields(
            unit=unit,
            focus_line=line,
            evidence=evidence,
            remediation=rem,
            handle_lifecycle_warning=impact,
            rule_id="DOM-BS-002",
        )
        new_findings.append(
            Finding(
                id="",
                rule_id="DOM-BS-002",
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
                action_required=str(
                    raw.get("action_required") or "Assign Delete/recycle ownership across caller/callee."
                ),
                category=meta["category"],
                engine="llm",
                ai_validation_status="BLIND_SPOT",
                ai_validation_reasoning=reasoning,
                is_blind_spot=True,
                is_false_positive=False,
                **snippet_fields,
            )
        )

    notes.append(
        f"AI Pass 3 (cross-module ownership): reviewed {len(selected)} unit(s), "
        f"escalated {adjusted} finding(s), added {len(new_findings)} DOM-BS-002 finding(s)."
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
    Three-pass AI discrepancy audit:

    1. False-positive filter on rule findings
    2. Blind-spot detection on handle-allocating blocks with zero rule hits
    3. Cross-module ownership + dynamic severity escalation
    """
    notes: list[str] = []
    if not llm_available():
        notes.append("OPENAI_API_KEY not set — skipped AI discrepancy audit (rules-only).")
        return existing, notes

    model_name = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    working = list(existing)
    for idx, finding in enumerate(working, start=1):
        finding.id = f"F-{idx:03d}"

    pass1_budget = max(4, max_units // 3)
    pass2_budget = max(4, max_units // 3)
    pass3_budget = max(4, max_units - pass1_budget - pass2_budget)

    notes.append(
        f"AI discrepancy audit enabled (model={model_name}, "
        f"pass1≤{pass1_budget}, pass2≤{pass2_budget}, pass3≤{pass3_budget})."
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

    ownership = _pass3_cross_module_ownership(
        units, merged, model=model_name, max_units=pass3_budget, notes=notes
    )
    merged = merged + ownership
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
