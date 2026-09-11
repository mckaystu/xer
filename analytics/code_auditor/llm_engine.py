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
    r"\bNotes(?:Document|View|Database|ViewEntry|DateTime)\b"
    r"|\b(?:createDateTime|createViewNav|GetDocumentByUNID|GetFirstDocument|"
    r"GetNextDocument|GetEntryByKey|getDocumentByUNID|getFirstDocument|"
    r"getNextDocument|getView|getDatabase|getCurrentDatabase|CreateDocument|createDocument|"
    r"getEmbeddedObject|createStream|getAllDocumentsByKey)\b"
    r"|(?:lotus\.domino\.(?:Document|View|Database|ViewEntry))",
    re.I,
)

FP_SYSTEM_PROMPT = """You are a Domino architecture expert performing FALSE-POSITIVE and
SEVERITY CONTEXT review.
You receive static-rule findings plus the surrounding code.

For each finding, decide:
- FALSE_POSITIVE — ONLY when you can quote clear evidence of safe cleanup, e.g.:
  * `.recycle()` / `Delete` of the SAME variable named in the finding
  * ODA (`org.openntf.domino` / Factory) with NO raw `lotus.domino` mix and NO need for manual recycle
  * caller recycles a returned Document in the same function (quote both return + recycle)
  Never mark FALSE_POSITIVE on speculation ("probably fine") or import-only code.
- VERIFIED_NON_LOOP — the leak is real BUT allocation is clearly outside any collection loop
  (no for/while/Do While around the alloc). Use ONLY for loop-sensitive hygiene rules
  (missing recycle scaffolding, item/stream leaks). Do NOT use VERIFIED_NON_LOOP for:
  static/session-scoped handles, ODA manual recycle, or Session/current-Database recycle.
- VERIFIED — real leak / anti-pattern that still needs remediation (especially in loops).

Return ONLY valid JSON:
{
  "reviews": [
    {
      "finding_id": "F-001",
      "verdict": "VERIFIED|FALSE_POSITIVE|VERIFIED_NON_LOOP",
      "confidence": 0-100,
      "reasoning": "1-3 sentences; quote the cleanup line or why it is unsafe",
      "in_loop": true,
      "evidence_quote": "short code excerpt proving the verdict"
    }
  ]
}
Be conservative: when unsure, return VERIFIED. Include honest confidence (0-100).
"""

NON_LOOP_AI_NOTE = (
    "Non-loop single execution: Low risk of handle table exhaustion, "
    "recommended for general code hygiene."
)

# Rules that may be demoted via VERIFIED_NON_LOOP / in_loop=false
_NON_LOOP_DEMOTE_RULES = frozenset(
    {
        "DOM-001",
        "DOM-002",
        "DOM-003",
        "DOM-010",
        "DOM-012",
        "DOM-013",
        "DOM-014",
        "DOM-016",
        "DOM-017",
        "DOM-018",
        "DOM-019",
        "DOM-021",
        "DOM-BS-001",
    }
)

BLIND_SPOT_SYSTEM_PROMPT = """You are a Domino architecture expert hunting BLIND-SPOT handle leaks.
Static regex rules found ZERO issues in this code block, but Domino handles appear to be allocated.

ONLY report a blind spot when ALL of these are true:
1) You can name a specific variable that receives a Domino handle (Document/View/Item/…)
2) You can quote the allocation line AND show that variable is not recycled/Deleted on that path
3) Confidence is high (prefer ≥85)

High-precision patterns to look for:
- temp-next walks: `next = coll.getNextDocument(doc); …; doc = next;` with no `doc.recycle()`
- early return / catch after allocation without recycle
- nested if that skips finally

Do NOT report:
- ODA-only code (`org.openntf.domino`) without lotus.domino mix
- import statements or type declarations with no allocation
- speculative "might leak" without a named unclean variable

Return ONLY valid JSON:
{
  "blind_spots": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "line_hint": 1,
      "unclean_var": "doc",
      "evidence": "short code excerpt showing alloc + missing recycle",
      "technical_impact": "why it matters",
      "remediation": "fixed pattern guidance",
      "action_required": "short action",
      "reasoning": "why static rules missed this"
    }
  ]
}
If the code is genuinely safe, return {"blind_spots": []}.
"""

PASS3_SYSTEM_PROMPT = """You are a Domino architecture expert performing CROSS-MODULE handle ownership
analysis and dynamic risk escalation.

You receive multiple related code units (functions/subs) from the same application.

Tasks:
1) Cross-boundary ownership: if a function returns Document/NotesDocument OR accepts one as a
   parameter, decide whether caller or callee is responsible for Delete/.recycle(). Emit an
   ownership gap ONLY when you can quote BOTH sides and show neither releases the handle.
2) Risk escalation: escalate ONLY when a finding is already a VERIFIED loop leak AND the
   element is a scheduled/background agent (Initialize / agent). Do not escalate UI one-shots.
3) To-Be sanity: when suggesting remediation, preserve return values and business logic.

Return ONLY valid JSON:
{
  "ownership_gaps": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "element_name": "function or design element name",
      "line_hint": 1,
      "evidence": "short excerpt proving neither side recycles",
      "technical_impact": "why ownership is unclear",
      "action_required": "who should Delete/recycle",
      "escalate": false,
      "execution_context": "ui_event|background_agent|unknown"
    }
  ],
  "severity_adjustments": [
    {
      "finding_id": "F-001",
      "new_severity": "CRITICAL",
      "confidence": 0-100,
      "reasoning": "why escalate — must cite background agent + existing loop leak"
    }
  ]
}
If nothing is clear, return empty arrays. Prefer confidence ≥85 for ownership gaps.
"""

INVENTORY_FP_SYSTEM_PROMPT = """You are a Domino architecture expert reviewing Function & Recycle
Inventory classifications for FALSE POSITIVES.

Each item is a Java / SSJS / XPages function our static scanner marked as having incomplete
.handle recycle() / cleanup. Decide for each:

- FALSE_POSITIVE — not a real handle-table risk. Examples: OpenNTF Domino API (ODA) auto-lifecycle;
  handle is returned and clearly caller-owned; recycle happens via a well-known helper in this body;
  allocation is a non-handle / false regex match; framework wrapper owns the object.
- VERIFIED_NON_LOOP — missing cleanup is real but one-shot / not in a collection loop → hygiene only.
- VERIFIED — real risk; keep (especially allocations inside loops or hot agent paths).

Return ONLY valid JSON:
{
  "reviews": [
    {
      "function_id": "FUNC-001",
      "verdict": "VERIFIED|FALSE_POSITIVE|VERIFIED_NON_LOOP",
      "confidence": 0-100,
      "reasoning": "1-3 sentences"
    }
  ]
}
Be conservative on FALSE_POSITIVE — only when cleanup ownership or framework lifecycle is clear.
Include an honest confidence (0-100); low-confidence reviews are discarded by the host.
"""


DEFAULT_AI_CONFIDENCE_MIN = 75


def ai_confidence_min() -> int:
    """Minimum AI confidence (0-100) required to act on a model verdict.

    Controlled by ``XER_AI_CONFIDENCE_MIN`` (default 75). Below this, Pass 1 / inventory
    verdicts are ignored and Pass 2/3 discoveries are dropped.
    """
    raw = os.getenv("XER_AI_CONFIDENCE_MIN", str(DEFAULT_AI_CONFIDENCE_MIN)).strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_AI_CONFIDENCE_MIN
    return max(0, min(100, value))


def _parse_confidence(raw: Any, default: int = 70) -> int:
    try:
        confidence = int(raw)
    except (TypeError, ValueError):
        confidence = default
    return max(0, min(100, confidence))


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
    skipped_low = 0
    min_conf = ai_confidence_min()

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
            confidence = _parse_confidence(review.get("confidence"), default=70)
            reviewed += 1
            if confidence < min_conf:
                skipped_low += 1
                # Soft note only — do not change FP / severity on low-confidence AI opinions
                if not finding.ai_validation_status:
                    finding.ai_validation_status = "LOW_CONFIDENCE"
                    finding.ai_validation_reasoning = (
                        f"AI confidence {confidence}% below threshold {min_conf}% — "
                        f"ignored ({verdict}). {reasoning}"
                    ).strip()
                continue
            if verdict == "FALSE_POSITIVE":
                finding.ai_validation_status = "FALSE_POSITIVE"
                finding.ai_validation_reasoning = reasoning or (
                    "AI judged this rule hit safe due to non-standard cleanup / framework ownership."
                )
                finding.is_false_positive = True
                finding.is_blind_spot = False
                finding.engine = "hybrid"
                finding.severity = "LOW"  # demote — retained for UI "Flagged False Positives"
                finding.confidence = min(finding.confidence, max(40, 100 - confidence))
                fps += 1
            elif verdict in {"VERIFIED_NON_LOOP", "NON_LOOP", "VERIFIED_HYGIENE"}:
                if finding.rule_id not in _NON_LOOP_DEMOTE_RULES:
                    # Never demote static handles / ODA misuse / session recycle via NON_LOOP
                    finding.ai_validation_status = "VERIFIED"
                    finding.ai_validation_reasoning = (
                        (reasoning or "AI confirmed risk")
                        + " | NON_LOOP demotion skipped for non-hygiene rule "
                        + finding.rule_id
                    )
                    finding.is_false_positive = False
                    finding.engine = "hybrid" if finding.engine == "rules" else finding.engine
                    finding.confidence = max(finding.confidence, confidence)
                    continue
                finding.ai_validation_status = "VERIFIED_NON_LOOP"
                note = NON_LOOP_AI_NOTE
                finding.ai_validation_reasoning = (
                    (reasoning + " | " if reasoning else "") + note
                )
                finding.is_false_positive = False
                finding.is_blind_spot = False
                finding.engine = "hybrid"
                finding.severity = "LOW"
                finding.confidence = max(finding.confidence, confidence)
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
                finding.confidence = max(finding.confidence, confidence)
                # Gentle demotion only for hygiene rules when model says not in a loop
                if (
                    review.get("in_loop") is False
                    and finding.rule_id in _NON_LOOP_DEMOTE_RULES
                    and finding.severity in {"CRITICAL", "HIGH"}
                ):
                    finding.severity = "LOW"
                    finding.ai_validation_status = "VERIFIED_NON_LOOP"
                    finding.ai_validation_reasoning = (
                        (finding.ai_validation_reasoning + " | " if finding.ai_validation_reasoning else "")
                        + NON_LOOP_AI_NOTE
                    )

    notes.append(
        f"AI Pass 1 (false-positive filter): reviewed {reviewed} finding(s), "
        f"flagged {fps} false positive(s)"
        + (f", skipped {skipped_low} below confidence {ai_confidence_min()}%." if skipped_low else ".")
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
            confidence = _parse_confidence(raw.get("confidence"), default=70)
            if confidence < ai_confidence_min():
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
        conf = _parse_confidence(adj.get("confidence"), default=0)
        if conf < ai_confidence_min():
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
    # Skip AI ownership gaps when static DOM-OWN-001 already covers the element
    static_own_elements = {
        (f.element_name or "").lower()
        for f in findings
        if f.rule_id == "DOM-OWN-001" and not f.is_false_positive
    }
    new_findings: list[Finding] = []
    for raw in result.get("ownership_gaps") or []:
        confidence = _parse_confidence(raw.get("confidence"), default=70)
        if confidence < ai_confidence_min():
            continue
        severity = str(raw.get("severity") or meta["default_severity"]).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = meta["default_severity"]
        if raw.get("escalate") and severity in {"MEDIUM", "LOW"}:
            severity = "HIGH"
        if raw.get("execution_context") == "background_agent" and severity != "CRITICAL":
            severity = "CRITICAL" if severity == "HIGH" else "HIGH"

        element_name = str(raw.get("element_name") or selected[0].element_name)
        if element_name.lower() in static_own_elements:
            continue
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
        f"confidence≥{ai_confidence_min()}%, "
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


def enrich_inventory_with_llm(
    records: list[Any],
    *,
    max_functions: int = 40,
    model: str | None = None,
) -> tuple[list[Any], list[str]]:
    """Pass 4-style FP review for actionable Function Inventory rows (in-place)."""
    from analytics.code_auditor.function_inventory import FunctionRecord

    notes: list[str] = []
    if not llm_available():
        notes.append("OPENAI_API_KEY not set — skipped inventory AI false-positive review.")
        return records, notes

    model_name = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    actionable = [
        r
        for r in records
        if isinstance(r, FunctionRecord)
        and r.status
        in {
            "UNPROTECTED_ALLOCATION",
            "PARTIAL_CLEANUP",
            "CONDITIONAL_CLEANUP",
            "ESCAPE_PATH_GAP",
        }
        and not r.is_false_positive
    ]
    # Prefer CRITICAL/HIGH and in-loop first
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    actionable.sort(
        key=lambda r: (
            sev_rank.get(r.risk_severity, 9),
            0 if r.in_loop else 1,
            r.design_element,
            r.function_name,
        )
    )
    selected = actionable[: max(1, max_functions)]
    if not selected:
        notes.append("AI inventory FP review skipped — no actionable functions.")
        return records, notes

    # Batch in chunks of 8 to keep prompts small
    reviewed = 0
    fps = 0
    skipped_low = 0
    min_conf = ai_confidence_min()
    chunk_size = 8
    for i in range(0, len(selected), chunk_size):
        batch = selected[i : i + chunk_size]
        user_payload = {
            "functions": [
                {
                    "function_id": r.id,
                    "function_name": r.function_name,
                    "design_element": r.design_element,
                    "language": r.language,
                    "status": r.status,
                    "risk_severity": r.risk_severity,
                    "in_loop": r.in_loop,
                    "allocates_handles": r.allocates_handles,
                    "recycle_call_count": r.recycle_call_count,
                    "unclean_vars": r.unclean_vars[:12],
                    "code": (r.code_snippet_as_is or "")[:6000],
                }
                for r in batch
            ]
        }
        try:
            payload = _chat_json(INVENTORY_FP_SYSTEM_PROMPT, user_payload, model=model_name)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"AI inventory FP error: {exc}")
            continue

        by_id = {r.id: r for r in batch}
        for review in payload.get("reviews") or []:
            rid = str(review.get("function_id") or "")
            rec = by_id.get(rid)
            if not rec:
                continue
            verdict = str(review.get("verdict") or "VERIFIED").upper().strip()
            reasoning = str(review.get("reasoning") or "").strip()
            confidence = _parse_confidence(review.get("confidence"), default=70)
            reviewed += 1
            if confidence < min_conf:
                skipped_low += 1
                if not rec.ai_validation_status:
                    rec.ai_validation_status = "LOW_CONFIDENCE"
                    rec.ai_validation_reasoning = (
                        f"AI confidence {confidence}% below threshold {min_conf}% — "
                        f"ignored ({verdict}). {reasoning}"
                    ).strip()
                continue
            if verdict == "FALSE_POSITIVE":
                rec.ai_validation_status = "FALSE_POSITIVE"
                rec.ai_validation_reasoning = reasoning or (
                    "AI judged this inventory hit safe (framework ownership / caller cleanup / non-handle)."
                )
                rec.is_false_positive = True
                rec.triage_source = "ai"
                rec.risk_severity = "LOW"
                fps += 1
            elif verdict in {"VERIFIED_NON_LOOP", "NON_LOOP", "VERIFIED_HYGIENE"}:
                rec.ai_validation_status = "VERIFIED_NON_LOOP"
                rec.ai_validation_reasoning = (
                    (reasoning + " | " if reasoning else "") + NON_LOOP_AI_NOTE
                )
                rec.is_false_positive = False
                rec.triage_source = "ai"
                rec.risk_severity = "LOW"
            else:
                rec.ai_validation_status = "VERIFIED"
                rec.ai_validation_reasoning = reasoning or (
                    "AI confirmed incomplete recycle coverage is a real handle risk."
                )
                rec.is_false_positive = False
                rec.triage_source = "ai"

    notes.append(
        f"AI inventory FP review: reviewed {reviewed} function(s), flagged {fps} false positive(s)"
        + (f", skipped {skipped_low} below confidence {min_conf}%." if skipped_low else ".")
    )
    return records, notes


# Back-compat: older callers may still import this symbol
SYSTEM_PROMPT = BLIND_SPOT_SYSTEM_PROMPT


def analyze_unit_with_llm(unit: CodeUnit, *, model: str | None = None) -> list[Finding]:
    """Legacy single-unit scan — now routes through blind-spot prompt for one block."""
    if not llm_available():
        return []
    model_name = model or os.getenv("XER_AUDIT_MODEL", "gpt-4o-mini")
    notes: list[str] = []
    return _pass2_blind_spot_detector([unit], [], model=model_name, max_units=1, notes=notes)
