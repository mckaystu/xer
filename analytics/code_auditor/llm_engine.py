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

FP_SYSTEM_PROMPT = """You are an expert static analysis validator and control-flow inference
engine specializing in HCL Domino 14.5, XPages, and OpenNTF Domino API (ODA) memory lifecycle
management.

Primary objective: detect C-API handle leaks (BLK_OPENED_NOTE) while actively identifying ODA
thread-deadlock anti-patterns caused by improper object recycling.

### DUAL-FRAMEWORK DISTINCTION
1. Pure `lotus.domino.*` objects MUST be released with `.recycle()` in `finally` (or a verified
   cleanup method) to prevent handle-table saturation (130,944 limit / BLK_OPENED_NOTE).
2. OpenNTF Domino API (`org.openntf.domino.*`) AUTOMATICALLY manages native handle lifecycles.
   Missing `.recycle()` on pure ODA types is NOT a leak → FALSE_POSITIVE is appropriate when
   the unit is ODA-managed (no raw lotus.domino mix requiring manual recycle).
3. Scope: Java / SSJS / XPages only (not LotusScript C-API, not browser CSJS).

### DEADLOCK PREVENTION (DOM-004 / DOM-025) — CRITICAL
Calling `.recycle()` on `org.openntf.domino.*` wrapper instances is a CRITICAL BUG. It induces
lock contention on SessionModerator during WrapperFactory.recycle() / Factory.termThread(),
causing Java thread deadlocks and abnormal HTTP terminations.
- DOM-004: any direct `.recycle()` on ODA wrappers → ALWAYS VERIFIED (CRITICAL). Never FP.
- DOM-025: ODA collection/view loops that manually recycle ODA objects OR iterate heavy
  collections without unwrapping via toLotus() → ALWAYS VERIFIED (CRITICAL). Never FP.
Safe high-volume pattern (Jesse Gallagher):
  lotus.domino.View lotusView = Factory.getWrapperFactory().toLotus(odaView);
  // then recycle lotus.domino.Document handles in finally — never the ODA wrapper

### CRITICAL SEVERITY GUARDRAIL
NEVER mark CRITICAL loop leaks (DOM-001, DOM-002, DOM-015, DOM-018, DOM-022) as FALSE_POSITIVE
for lotus.domino unless you quote finally-recycle of every named handle.
Exception: pure ODA-managed allocations (org.openntf.domino, no lotus.domino leak path) may be
FALSE_POSITIVE for missing-recycle rules — but NEVER for DOM-004 / DOM-025.
getNextDocument/Entry/Category without recycling the prior lotus handle → VERIFIED CRITICAL.

### ALSO ENFORCE
- Platform globals (session, XPages database, getCurrentDatabase, dominoNAF): do NOT require
  recycle; recycling them is CRITICAL (DOM-020 / DOM-024).
- Collection wrappers left un-recycled after child cleanup (lotus) → DOM-022.
- Managed Bean / scope maps holding live NotesBase → DOM-023.

### VERDICTS
- FALSE_POSITIVE — finally-recycle of SAME vars, platform-global, OR pure ODA auto-lifecycle
  (missing-recycle rules only). Never on speculation. Never for DOM-004/DOM-025.
- VERIFIED_NON_LOOP — real lotus missing cleanup outside loops → hygiene (not for DOM-004/025).
- VERIFIED — real leak or ODA deadlock anti-pattern.

Return ONLY valid JSON:
{
  "reviews": [
    {
      "finding_id": "F-001",
      "rule_id": "DOM-XXX",
      "verdict": "VERIFIED|FALSE_POSITIVE|VERIFIED_NON_LOOP",
      "confidence": 0-100,
      "confidence_score": 0-100,
      "severity_adjusted": "CRITICAL|HIGH|MEDIUM|LOW",
      "framework_detected": "LOTUS_NATIVE|OPENNTF_ODA|MIXED",
      "rationale": "cite allocation, loop context, cleanup; leak vs SessionModerator deadlock",
      "reasoning": "1-3 sentences; quote evidence",
      "in_loop": true,
      "evidence_quote": "short code excerpt proving the verdict",
      "suggested_remediation": "lotus try/finally OR toLotus() unwrap pattern"
    }
  ]
}
Be conservative on lotus leaks: when unsure, return VERIFIED. Prefer confidence ≥75.
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
        "DOM-022",
        "DOM-BS-001",
    }
)

# CRITICAL findings: FP only with finally-recycle evidence (or pure ODA for missing-recycle).
# DOM-004 / DOM-025 (ODA deadlock) are NEVER false positives.
_CRITICAL_FP_GUARDED_RULES = frozenset(
    {
        "DOM-001",
        "DOM-002",
        "DOM-004",
        "DOM-006",
        "DOM-015",
        "DOM-018",
        "DOM-020",
        "DOM-022",
        "DOM-023",
        "DOM-024",
        "DOM-025",
    }
)

# Missing-recycle rules where pure ODA auto-lifecycle can justify FALSE_POSITIVE.
_ODA_MISSING_RECYCLE_FP_RULES = frozenset(
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
        "DOM-017",
        "DOM-018",
        "DOM-019",
        "DOM-021",
        "DOM-022",
        "DOM-BS-001",
    }
)

# ODA deadlock / wrapper-recycle rules — never demote via NON_LOOP or FP.
_ODA_DEADLOCK_RULES = frozenset({"DOM-004", "DOM-025"})

BLIND_SPOT_SYSTEM_PROMPT = """You are an expert Domino 14.5 / ODA handle validator hunting
BLIND-SPOT issues in Java / SSJS / XPages. Static regex rules found ZERO issues.

ONLY report a blind spot when ALL are true:
1) Name a specific variable that receives a Domino handle
2) Quote allocation AND show the unsafe path (missing lotus recycle OR illegal ODA recycle)
3) Confidence high (prefer ≥85; ≥75 minimum unless CRITICAL)

High-precision patterns:
- lotus.domino temp-next walks without doc.recycle()
- Collection wrappers left un-recycled after child cleanup (lotus)
- Managed Bean / scope holding live NotesBase
- ODA wrappers calling .recycle() (SessionModerator deadlock — DOM-004/025)
- ODA collection loops recycling wrappers without Factory.getWrapperFactory().toLotus()

Do NOT report:
- Missing recycle on pure org.openntf.domino.* (ODA auto-manages lifecycle)
- Missing recycle on platform globals: session, XPages database, getCurrentDatabase(), dominoNAF
- import-only / speculative "might leak"

Return ONLY valid JSON:
{
  "blind_spots": [
    {
      "rule_id": "DOM-BS-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0-100,
      "confidence_score": 0-100,
      "framework_detected": "LOTUS_NATIVE|OPENNTF_ODA|MIXED",
      "line_hint": 1,
      "unclean_var": "doc",
      "evidence": "short excerpt",
      "technical_impact": "BLK_OPENED_NOTE leak OR SessionModerator deadlock",
      "remediation": "lotus finally recycle OR toLotus() unwrap pattern",
      "action_required": "short action",
      "rationale": "cite framework + cleanup status",
      "reasoning": "why static rules missed this"
    }
  ]
}
If genuinely safe, return {"blind_spots": []}.
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

INVENTORY_FP_SYSTEM_PROMPT = """You are an expert Domino 14.5 / ODA handle validator reviewing
Function & Recycle Inventory classifications (Java / SSJS / XPages).

DUAL-FRAMEWORK:
- lotus.domino: missing recycle in loops is real risk (VERIFIED).
- org.openntf.domino (pure ODA): auto-lifecycle → FALSE_POSITIVE for missing recycle is OK.
- Manual .recycle() on ODA wrappers → VERIFIED CRITICAL (deadlock). Never FP.

CRITICAL GUARDRAIL: Never mark FALSE_POSITIVE on getNext* walks that skip recycling prior
lotus handles unless you quote finally-recycle. Never FP ODA wrapper .recycle() (DOM-004/025).

Decide for each:
- FALSE_POSITIVE — pure ODA auto-lifecycle; caller-owned with recycle; platform globals;
  false regex match.
- VERIFIED_NON_LOOP — lotus missing cleanup, one-shot → hygiene.
- VERIFIED — real lotus leak OR ODA deadlock anti-pattern.

Return ONLY valid JSON:
{
  "reviews": [
    {
      "function_id": "FUNC-001",
      "verdict": "VERIFIED|FALSE_POSITIVE|VERIFIED_NON_LOOP",
      "confidence": 0-100,
      "confidence_score": 0-100,
      "severity_adjusted": "CRITICAL|HIGH|MEDIUM|LOW",
      "framework_detected": "LOTUS_NATIVE|OPENNTF_ODA|MIXED",
      "rationale": "cite framework + cleanup",
      "reasoning": "1-3 sentences"
    }
  ]
}
Prefer confidence ≥75; low-confidence reviews are discarded.
"""


DEFAULT_AI_CONFIDENCE_MIN = 75

# CRITICAL loop-exhaustion blind spots may land slightly below the default gate.
_CRITICAL_LOOP_CONFIDENCE_FLOOR = 60


def ai_confidence_min() -> int:
    """Minimum AI confidence (0-100) required to act on a model verdict.

    Controlled by ``XER_AI_CONFIDENCE_MIN`` (default 75). Below this, Pass 1 / inventory
    verdicts are ignored and Pass 2/3 discoveries are dropped (except CRITICAL loop
    blind spots, which may use a slightly lower floor).
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


def _review_confidence(review: dict[str, Any], default: int = 70) -> int:
    if "confidence_score" in review and review.get("confidence_score") is not None:
        return _parse_confidence(review.get("confidence_score"), default=default)
    return _parse_confidence(review.get("confidence"), default=default)


def _review_reasoning(review: dict[str, Any]) -> str:
    return str(
        review.get("rationale") or review.get("reasoning") or ""
    ).strip()


def _fp_guardrail_allows(
    finding: Finding,
    review: dict[str, Any],
    *,
    unit_body: str = "",
) -> bool:
    """CRITICAL findings need finally-recycle evidence; pure ODA may FP missing-recycle.

    DOM-004 / DOM-025 (ODA wrapper recycle / deadlock) are never FALSE_POSITIVE.
    """
    if finding.rule_id in _ODA_DEADLOCK_RULES:
        return False

    if finding.severity != "CRITICAL" and finding.rule_id not in _CRITICAL_FP_GUARDED_RULES:
        return True

    blob = " ".join(
        [
            str(review.get("evidence_quote") or ""),
            _review_reasoning(review),
            unit_body[:4000],
        ]
    ).lower()

    finally_recycle = bool(
        re.search(r"\bfinally\b", blob)
        and re.search(r"\.?\s*recycle\s*\(", blob)
    )
    if finally_recycle:
        return True

    # Pure ODA auto-lifecycle can clear missing-recycle style findings
    if finding.rule_id in _ODA_MISSING_RECYCLE_FP_RULES:
        oda = bool(
            re.search(r"org\.openntf\.domino|\boda\b", blob)
            or re.search(r"org\.openntf\.domino", unit_body or "", re.I)
        )
        lotus_raw = bool(re.search(r"lotus\.domino", unit_body or "", re.I))
        mixed_unwrapped = lotus_raw and not re.search(
            r"Factory\.fromLotus|fromLotus\s*\(", unit_body or "", re.I
        )
        if oda and not mixed_unwrapped:
            return True

    if re.search(r"\b(cleanup|dispose|recycleall|recyclenotes)\w*\s*\(", blob):
        if not re.search(r"wrapperfactory\.recycle|sessionmoderator", blob):
            return True

    return False


def _apply_severity_adjusted(finding: Finding, review: dict[str, Any]) -> None:
    adj = str(review.get("severity_adjusted") or "").upper().strip()
    if adj in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        # Never let severity_adjusted demote CRITICAL guarded findings to LOW via FP path;
        # only apply when keeping VERIFIED / elevating.
        if finding.severity == "CRITICAL" and adj in {"MEDIUM", "LOW"}:
            if finding.rule_id in _CRITICAL_FP_GUARDED_RULES:
                return
        finding.severity = adj  # type: ignore[assignment]


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
            reasoning = _review_reasoning(review)
            confidence = _review_confidence(review, default=70)
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
                if not _fp_guardrail_allows(finding, review, unit_body=unit.body or ""):
                    finding.ai_validation_status = "VERIFIED"
                    finding.ai_validation_reasoning = (
                        (reasoning or "AI proposed FALSE_POSITIVE")
                        + " | CRITICAL guardrail rejected FP without finally-recycle or "
                        "pure-ODA ownership evidence."
                    ).strip()
                    finding.is_false_positive = False
                    finding.engine = "hybrid" if finding.engine == "rules" else finding.engine
                    finding.confidence = max(finding.confidence, confidence)
                    continue
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
                # Loop advance without recycle must stay CRITICAL / VERIFIED
                ev = (
                    str(review.get("evidence_quote") or "")
                    + " "
                    + reasoning
                    + " "
                    + (finding.evidence or "")
                ).lower()
                next_walk = bool(
                    re.search(
                        r"getnext(?:document|entry|category)\s*\(",
                        ev,
                        re.I,
                    )
                ) and not re.search(r"\.?\s*recycle\s*\(", ev)
                if next_walk or (
                    review.get("in_loop") is True
                    and finding.rule_id in _CRITICAL_FP_GUARDED_RULES
                    and finding.severity == "CRITICAL"
                ):
                    finding.ai_validation_status = "VERIFIED"
                    finding.ai_validation_reasoning = (
                        (reasoning or "AI confirmed risk")
                        + " | NON_LOOP demotion blocked: CRITICAL loop / getNext* path."
                    )
                    finding.is_false_positive = False
                    finding.engine = "hybrid" if finding.engine == "rules" else finding.engine
                    finding.confidence = max(finding.confidence, confidence)
                    continue
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
                _apply_severity_adjusted(finding, review)
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
            confidence = _review_confidence(raw, default=70)
            severity = str(raw.get("severity") or meta["default_severity"]).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = meta["default_severity"]
            floor = (
                _CRITICAL_LOOP_CONFIDENCE_FLOOR
                if severity == "CRITICAL"
                else ai_confidence_min()
            )
            if confidence < floor:
                continue
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
            reasoning = _review_reasoning(review)
            confidence = _review_confidence(review, default=70)
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
                # CRITICAL lotus in-loop needs finally; pure ODA missing-recycle may pass
                blob = (reasoning + " " + str(review.get("evidence_quote") or "")).lower()
                guarded = (
                    rec.risk_severity == "CRITICAL"
                    or (rec.in_loop and rec.risk_severity in {"CRITICAL", "HIGH"})
                )
                finally_ok = bool(
                    re.search(r"\bfinally\b", blob) and re.search(r"recycle\s*\(", blob)
                )
                oda_ok = bool(
                    re.search(r"\boda\b|openntf|auto[- ]?lifecycle", blob)
                )
                # Illegal: FP for ODA *recycle* deadlock — keep if rationale is only ODA recycle
                oda_recycle_bug = bool(
                    re.search(r"recycle", blob)
                    and re.search(r"\boda\b|openntf", blob)
                    and re.search(r"deadlock|wrapper|sessionmoderator|dom-004|dom-025", blob)
                )
                if oda_recycle_bug:
                    rec.ai_validation_status = "VERIFIED"
                    rec.ai_validation_reasoning = (
                        (reasoning or "AI proposed FALSE_POSITIVE")
                        + " | ODA wrapper recycle is CRITICAL (SessionModerator deadlock)."
                    ).strip()
                    rec.is_false_positive = False
                    rec.triage_source = "ai"
                    continue
                if guarded and not (finally_ok or oda_ok):
                    rec.ai_validation_status = "VERIFIED"
                    rec.ai_validation_reasoning = (
                        (reasoning or "AI proposed FALSE_POSITIVE")
                        + " | CRITICAL guardrail rejected FP without finally-recycle or "
                        "ODA auto-lifecycle evidence."
                    ).strip()
                    rec.is_false_positive = False
                    rec.triage_source = "ai"
                    continue
                rec.ai_validation_status = "FALSE_POSITIVE"
                rec.ai_validation_reasoning = reasoning or (
                    "AI judged this inventory hit safe (framework ownership / caller cleanup / non-handle)."
                )
                rec.is_false_positive = True
                rec.triage_source = "ai"
                rec.risk_severity = "LOW"
                fps += 1
            elif verdict in {"VERIFIED_NON_LOOP", "NON_LOOP", "VERIFIED_HYGIENE"}:
                if rec.in_loop and rec.risk_severity == "CRITICAL":
                    rec.ai_validation_status = "VERIFIED"
                    rec.ai_validation_reasoning = (
                        (reasoning or "AI confirmed risk")
                        + " | NON_LOOP demotion blocked: CRITICAL loop path."
                    )
                    rec.is_false_positive = False
                    rec.triage_source = "ai"
                    continue
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
                adj = str(review.get("severity_adjusted") or "").upper().strip()
                if adj in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    if not (rec.risk_severity == "CRITICAL" and adj in {"MEDIUM", "LOW"}):
                        rec.risk_severity = adj


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
