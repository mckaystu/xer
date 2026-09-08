"""Export Code Analysis as a condensed Word report + priority function checklist."""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from typing import Any

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

from analytics.code_auditor.context import contributes_to_handle_exhaustion, is_lotusscript_language
from analytics.code_auditor.models import AuditReport, Finding

# Functions that need developer attention (not SAFE / PROTECTED)
_ACTIONABLE_STATUSES = frozenset(
    {
        "UNPROTECTED_ALLOCATION",
        "PARTIAL_CLEANUP",
        "CONDITIONAL_CLEANUP",
        "ESCAPE_PATH_GAP",
    }
)

_STATUS_PRIORITY = {
    "UNPROTECTED_ALLOCATION": 0,
    "ESCAPE_PATH_GAP": 1,
    "PARTIAL_CLEANUP": 2,
    "CONDITIONAL_CLEANUP": 3,
}

_SEV_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _add_checkbox_paragraph(doc: Document, text: str, *, bold_prefix: str | None = None) -> None:
    p = doc.add_paragraph()
    run = p.add_run("☐  ")
    run.font.size = Pt(12)
    if bold_prefix:
        br = p.add_run(bold_prefix)
        br.bold = True
        br.font.size = Pt(11)
        if text:
            p.add_run(text).font.size = Pt(11)
    else:
        p.add_run(text).font.size = Pt(11)


def _sev_color(severity: str) -> RGBColor:
    s = (severity or "").upper()
    if s == "CRITICAL":
        return RGBColor(0xB9, 0x1C, 0x1C)
    if s == "HIGH":
        return RGBColor(0xC2, 0x41, 0x0C)
    if s == "MEDIUM":
        return RGBColor(0xA1, 0x62, 0x07)
    return RGBColor(0x3F, 0x3F, 0x46)


def _safe(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    cleaned = str(text).replace("\x00", "").strip()
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def _status_label(status: str) -> str:
    return str(status or "").replace("_", " ").title()


def _function_priority_key(row: dict[str, Any]) -> tuple:
    sev = str(row.get("risk_severity") or row.get("severity") or "MEDIUM").upper()
    status = str(row.get("status") or "")
    in_loop = 0 if row.get("in_loop") else 1
    return (
        _SEV_PRIORITY.get(sev, 9),
        _STATUS_PRIORITY.get(status, 9),
        in_loop,
        str(row.get("design_element") or ""),
        str(row.get("function_name") or ""),
    )


def _actionable_functions(inventory: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = []
    if isinstance(inventory, dict):
        rows = [r for r in (inventory.get("inventory") or []) if isinstance(r, dict)]
    actionable = [
        r
        for r in rows
        if r.get("status") in _ACTIONABLE_STATUSES and not r.get("is_false_positive")
    ]
    actionable.sort(key=_function_priority_key)
    return actionable


def _finding_sort_key(f: Finding) -> tuple:
    return (_SEV_PRIORITY.get(f.severity, 9), f.rule_id, f.element_name, f.line)


def _priority_findings(report: AuditReport, *, limit: int = 40) -> list[Finding]:
    """Short condensed finding list (CRITICAL/HIGH first) for the appendix."""
    out: list[Finding] = []
    for f in report.findings:
        if f.is_false_positive:
            continue
        if is_lotusscript_language(f.language):
            continue
        rid = f.rule_id or ""
        if contributes_to_handle_exhaustion(f) or rid.startswith(
            ("DOM-", "PERF-", "SEC-", "FORM-", "DOM-OWN", "DOM-BS")
        ):
            out.append(f)
    out.sort(key=_finding_sort_key)
    return out[:limit]


def _findings_for_function(report: AuditReport, row: dict[str, Any]) -> list[Finding]:
    """Match findings that likely belong to this inventory function."""
    name = (row.get("function_name") or "").strip().lower()
    element = (row.get("design_element") or "").strip().lower()
    if not name:
        return []
    matched: list[Finding] = []
    for f in report.findings:
        if f.is_false_positive or is_lotusscript_language(f.language):
            continue
        en = (f.element_name or "").strip().lower()
        if name in en or en == name or name in (f.title or "").lower():
            matched.append(f)
            continue
        if element and element in (f.element_name or "").lower():
            # Same design element + finding mentions function in evidence
            blob = f"{f.evidence or ''} {f.title or ''}".lower()
            if name in blob:
                matched.append(f)
    matched.sort(key=_finding_sort_key)
    return matched[:3]


def build_code_audit_checklist_docx(
    report: AuditReport,
    *,
    database_title: str | None = None,
    nsf_path: str | None = None,
    inventory: dict[str, Any] | None = None,
) -> bytes:
    """Word report: condensed analysis + priority-ordered function checklist."""
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.75)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)

    title = database_title or report.source or "Domino application"
    heading = doc.add_heading("Code Analysis — Priority Checklist", level=0)
    heading.alignment = WD_ALIGN_PARAGRAPH.LEFT

    meta = doc.add_paragraph()
    meta.add_run("Application: ").bold = True
    meta.add_run(title)
    meta2 = doc.add_paragraph()
    meta2.add_run("NSF / source: ").bold = True
    meta2.add_run(nsf_path or report.source or "—")
    meta3 = doc.add_paragraph()
    meta3.add_run("Generated: ").bold = True
    meta3.add_run(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    risk = report.risk_score()
    meta4 = doc.add_paragraph()
    meta4.add_run("Handle Exhaustion Risk: ").bold = True
    risk_run = meta4.add_run(risk)
    risk_run.bold = True
    risk_run.font.color.rgb = _sev_color(risk)

    doc.add_paragraph(
        "Scope: Java / SSJS / XPages C-API .recycle(). LotusScript is out of scope. "
        "Work the function checklist in order — highest priority first."
    )

    inv_summary = {}
    if isinstance(inventory, dict):
        inv_summary = inventory.get("summary") or {}
        if not inv_summary and inventory.get("total_functions_scanned") is not None:
            inv_summary = inventory

    functions = _actionable_functions(inventory)
    findings_short = _priority_findings(report)
    exh = report.handle_exhaustion_severity_counts()
    counts = report.severity_counts()

    # —— Condensed analysis ——
    doc.add_heading("Condensed analysis", level=1)
    summary_rows = [
        ("Handle Exhaustion Risk", risk),
        (
            "Handle safety rate",
            f"{inv_summary.get('handle_safety_rate', '—')}%"
            if inv_summary.get("handle_safety_rate") is not None
            else "—",
        ),
        (
            "Functions scanned (Java/JS/XPages)",
            str(inv_summary.get("total_functions_scanned", "—")),
        ),
        ("Unprotected functions", str(inv_summary.get("unprotected_functions", "—"))),
        (
            "Partial / conditional / escape gaps",
            str(
                (inv_summary.get("functions_partial_cleanup") or 0)
                + (inv_summary.get("functions_conditional_cleanup") or 0)
                + (inv_summary.get("functions_escape_path_gap") or 0)
            ),
        ),
        (
            "Recycle coverage among allocators",
            f"{inv_summary.get('recycle_coverage_rate', '—')}%"
            if inv_summary.get("recycle_coverage_rate") is not None
            else "—",
        ),
        (
            "Handle Exhaustion CRITICAL / HIGH",
            f"{exh.get('CRITICAL', 0)} / {exh.get('HIGH', 0)}",
        ),
        (
            "Active findings (all families)",
            f"{len(report.active_findings())} · C:{counts.get('CRITICAL', 0)} "
            f"H:{counts.get('HIGH', 0)} M:{counts.get('MEDIUM', 0)} L:{counts.get('LOW', 0)}",
        ),
        ("Priority functions in checklist", str(len(functions))),
        ("Blocks scanned", f"{report.blocks_prefiltered}/{report.blocks_scanned}"),
    ]
    table = doc.add_table(rows=len(summary_rows), cols=2)
    table.style = "Table Grid"
    for i, (label, value) in enumerate(summary_rows):
        table.rows[i].cells[0].text = label
        table.rows[i].cells[1].text = str(value)

    doc.add_paragraph()
    guide = doc.add_paragraph()
    guide.add_run("How to use: ").bold = True
    guide.add_run(
        "Address CRITICAL then HIGH functions first (especially anything in a loop). "
        "Tick each box when fixed, note owner/date, then re-run Xer Code Analysis."
    )

    # —— Priority function checklist (main deliverable) ——
    doc.add_heading(f"Function checklist — priority order ({len(functions)})", level=1)
    if not functions:
        doc.add_paragraph(
            "No unprotected / partial / conditional Java/SSJS/XPages functions to checklist."
        )
    else:
        for idx, row in enumerate(functions, start=1):
            _add_function_block(doc, idx, row, report)

    # —— Condensed findings appendix ——
    doc.add_page_break()
    doc.add_heading(f"Related findings (top {len(findings_short)} by severity)", level=1)
    doc.add_paragraph(
        "Rule findings that back the function work above. Full As-Is / To-Be detail lives in the Xer UI."
    )
    if not findings_short:
        doc.add_paragraph("No active Java/SSJS/XPages findings for this graph.")
    else:
        for idx, f in enumerate(findings_short, start=1):
            _add_finding_condensed(doc, idx, f)

    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.add_run("Generated by Xer Code Analysis").italic = True

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _add_function_block(doc: Document, idx: int, row: dict[str, Any], report: AuditReport) -> None:
    sev = str(row.get("risk_severity") or row.get("severity") or "MEDIUM").upper()
    status = _status_label(str(row.get("status") or ""))
    name = row.get("function_name") or "function"
    element = row.get("design_element") or ""
    lang = row.get("language_label") or row.get("language") or ""
    loop_note = " · IN LOOP" if row.get("in_loop") else ""

    prefix = f"[{idx}] {sev} · {status}{loop_note}  "
    _add_checkbox_paragraph(doc, f"{name}", bold_prefix=prefix)

    loc = doc.add_paragraph()
    sev_run = loc.add_run(sev)
    sev_run.bold = True
    sev_run.font.color.rgb = _sev_color(sev)
    loc.add_run(
        f"  ·  {element}  ·  {lang}  ·  L{row.get('start_line') or row.get('line_number') or '—'}  "
        f"·  allocates {('yes' if row.get('allocates_handles') else 'no')}  "
        f"·  recycle calls {row.get('recycle_call_count', 0)}"
    )

    why = row.get("problem_breakdown") or row.get("handle_lifecycle_warning") or ""
    if why:
        p = doc.add_paragraph()
        p.add_run("Why: ").bold = True
        p.add_run(_safe(why, 900))

    action = row.get("remediation_guide") or ""
    if action:
        p = doc.add_paragraph()
        p.add_run("Action: ").bold = True
        p.add_run(_safe(action, 700))

    unclean = row.get("unclean_vars") or []
    if unclean:
        p = doc.add_paragraph()
        p.add_run("Uncleaned handles: ").bold = True
        p.add_run(", ".join(str(v) for v in unclean[:12]))

    to_be = row.get("code_snippet_to_be") or ""
    if to_be:
        p = doc.add_paragraph()
        p.add_run("To-Be:").bold = True
        code = doc.add_paragraph(_safe(to_be, 1800))
        for run in code.runs:
            run.font.name = "Consolas"
            run.font.size = Pt(8)

    related = _findings_for_function(report, row)
    if related:
        p = doc.add_paragraph()
        p.add_run("Related rules: ").bold = True
        p.add_run(
            "; ".join(f"{f.rule_id} ({f.severity})" for f in related)
        )

    notes = doc.add_paragraph()
    notes.add_run(
        "☐ Fixed   ☐ N/A / accepted risk   Owner: ___________   Date: ___________"
    ).font.size = Pt(10)
    notes2 = doc.add_paragraph()
    notes2.add_run("Notes: ").italic = True
    notes2.add_run("_______________________________________________________________")
    doc.add_paragraph()


def _add_finding_condensed(doc: Document, idx: int, f: Finding) -> None:
    prefix = f"[{idx}] {f.severity} · {f.rule_id}  "
    _add_checkbox_paragraph(doc, f.title or f.rule_id, bold_prefix=prefix)
    loc = doc.add_paragraph()
    loc.add_run(
        f"{f.language_label or f.language}  ·  "
        f"{f.element_type}:{f.element_name} L{f.line}  ·  conf {f.confidence}%"
    ).font.size = Pt(10)
    action = f.action_required or f.remediation_guide or f.remediation or ""
    if action:
        p = doc.add_paragraph()
        p.add_run("Action: ").bold = True
        p.add_run(_safe(action, 500))
    doc.add_paragraph()


def slug_filename(title: str | None) -> str:
    base = re.sub(r"[^\w\-]+", "_", (title or "xer_code_audit").strip())[:60].strip("_")
    return f"{base or 'xer_code_audit'}_priority_checklist.docx"
