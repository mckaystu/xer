"""Export Code Analysis findings as a developer Word checklist (.docx)."""

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


def _add_checkbox_paragraph(doc: Document, text: str, *, bold_prefix: str | None = None) -> None:
    """Checkbox character + label (works in Word; clickable content controls are overkill)."""
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


def _finding_sort_key(f: Finding) -> tuple:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return (order.get(f.severity, 9), f.rule_id, f.element_name, f.line)


def _developer_findings(report: AuditReport) -> list[Finding]:
    """Findings for the checklist: Java/JS handle exhaustion + related DOM/PERF/SEC on C-API langs."""
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
    return out


def build_code_audit_checklist_docx(
    report: AuditReport,
    *,
    database_title: str | None = None,
    nsf_path: str | None = None,
    inventory: dict[str, Any] | None = None,
) -> bytes:
    """Return a .docx bytes checklist a developer can work through in Word."""
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.75)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)

    title = database_title or report.source or "Domino application"
    heading = doc.add_heading("Handle Exhaustion — Developer Checklist", level=0)
    heading.alignment = WD_ALIGN_PARAGRAPH.LEFT

    meta = doc.add_paragraph()
    meta.add_run(f"Application: ").bold = True
    meta.add_run(title)
    meta2 = doc.add_paragraph()
    meta2.add_run("NSF / source: ").bold = True
    meta2.add_run(nsf_path or report.source or "—")
    meta3 = doc.add_paragraph()
    meta3.add_run("Generated: ").bold = True
    meta3.add_run(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    meta4 = doc.add_paragraph()
    meta4.add_run("Handle Exhaustion Risk: ").bold = True
    risk_run = meta4.add_run(report.risk_score())
    risk_run.bold = True
    risk_run.font.color.rgb = _sev_color(report.risk_score())

    doc.add_paragraph(
        "Scope: Java / SSJS / XPages C-API .recycle() findings. LotusScript is out of scope for "
        "handle-table exhaustion and is not listed here."
    )

    doc.add_heading("How to use this checklist", level=1)
    for step in (
        "Work CRITICAL and HIGH items first — especially allocations inside loops.",
        "For each item: open the design element, apply the To-Be / remediation, then tick the box.",
        "Record the reviewer name and date in the Notes line when done.",
        "Re-run Xer Code Analysis after a batch of fixes to confirm the risk score drops.",
    ):
        doc.add_paragraph(step, style="List Number")

    findings = _developer_findings(report)
    exh = report.handle_exhaustion_severity_counts()
    counts = report.severity_counts()

    doc.add_heading("Summary", level=1)
    summary_table = doc.add_table(rows=5, cols=2)
    summary_table.style = "Table Grid"
    rows = [
        ("Checklist items", str(len(findings))),
        ("Handle Exhaustion CRITICAL / HIGH", f"{exh.get('CRITICAL', 0)} / {exh.get('HIGH', 0)}"),
        ("All active findings (incl. PERF/SEC)", str(len(report.active_findings()))),
        ("Severity rollup", f"C:{counts.get('CRITICAL', 0)} H:{counts.get('HIGH', 0)} M:{counts.get('MEDIUM', 0)} L:{counts.get('LOW', 0)}"),
        ("Blocks scanned", f"{report.blocks_prefiltered}/{report.blocks_scanned}"),
    ]
    for i, (label, value) in enumerate(rows):
        summary_table.rows[i].cells[0].text = label
        summary_table.rows[i].cells[1].text = value

    inv_summary = (inventory or {}).get("summary") if isinstance(inventory, dict) else None
    if not inv_summary and isinstance(inventory, dict):
        inv_summary = inventory
    if isinstance(inv_summary, dict) and inv_summary.get("total_functions_scanned") is not None:
        doc.add_paragraph()
        p = doc.add_paragraph()
        p.add_run("Inventory: ").bold = True
        p.add_run(
            f"Handle safety {inv_summary.get('handle_safety_rate', '—')}% · "
            f"{inv_summary.get('unprotected_functions', 0)} unprotected · "
            f"{inv_summary.get('total_functions_scanned', 0)} Java/JS functions scanned"
        )

    doc.add_heading(f"Working checklist ({len(findings)} items)", level=1)
    if not findings:
        doc.add_paragraph("No Java/SSJS/XPages handle findings to checklist for this graph.")
    else:
        for idx, f in enumerate(findings, start=1):
            _add_finding_block(doc, idx, f)

    # Inventory unprotected appendix
    inv_rows = []
    if isinstance(inventory, dict):
        inv_rows = inventory.get("inventory") or []
    unprotected = [
        r
        for r in inv_rows
        if isinstance(r, dict)
        and r.get("status")
        in {"UNPROTECTED_ALLOCATION", "PARTIAL_CLEANUP", "CONDITIONAL_CLEANUP", "ESCAPE_PATH_GAP"}
    ]
    if unprotected:
        doc.add_page_break()
        doc.add_heading(f"Inventory follow-ups ({len(unprotected)} functions)", level=1)
        doc.add_paragraph(
            "Functions that allocate Domino handles without complete .recycle() coverage. "
            "Use alongside the findings above."
        )
        for r in unprotected[:200]:
            status = str(r.get("status") or "").replace("_", " ").title()
            label = (
                f"{r.get('function_name') or 'function'} — {r.get('design_element') or ''} "
                f"[{r.get('language') or ''}] — {status}"
            )
            _add_checkbox_paragraph(doc, label)
            notes = doc.add_paragraph()
            notes.add_run("Notes / owner / date: ").italic = True
            notes.add_run("________________________________")

    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.add_run("Generated by Xer Code Analysis").italic = True

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _add_finding_block(doc: Document, idx: int, f: Finding) -> None:
    prefix = f"[{idx}] {f.severity} · {f.rule_id} · {f.id}  "
    title = f.title or f.rule_id
    _add_checkbox_paragraph(doc, title, bold_prefix=prefix)

    sev = doc.add_paragraph()
    sev_run = sev.add_run(f.severity)
    sev_run.bold = True
    sev_run.font.color.rgb = _sev_color(f.severity)
    sev.add_run(
        f"  ·  {f.language_label or f.language}  ·  "
        f"{f.element_type}:{f.element_name} L{f.line}  ·  conf {f.confidence}%"
    )

    if f.technical_impact or f.problem_breakdown:
        p = doc.add_paragraph()
        p.add_run("Why it matters: ").bold = True
        p.add_run(_safe(f.problem_breakdown or f.technical_impact, 1200))

    action = f.action_required or f.remediation_guide or ""
    if action:
        p = doc.add_paragraph()
        p.add_run("Action: ").bold = True
        p.add_run(_safe(action, 800))

    to_be = f.code_snippet_to_be or f.remediation
    if to_be:
        p = doc.add_paragraph()
        p.add_run("To-Be / remediation:").bold = True
        code = doc.add_paragraph(_safe(to_be, 2500))
        for run in code.runs:
            run.font.name = "Consolas"
            run.font.size = Pt(8)

    as_is = f.code_snippet_as_is or f.evidence
    if as_is:
        p = doc.add_paragraph()
        p.add_run("As-Is (evidence):").bold = True
        code = doc.add_paragraph(_safe(as_is, 1500))
        for run in code.runs:
            run.font.name = "Consolas"
            run.font.size = Pt(8)

    notes = doc.add_paragraph()
    notes.add_run("☐ Fixed   ☐ N/A / accepted risk   Owner: ___________   Date: ___________").font.size = Pt(10)
    notes2 = doc.add_paragraph()
    notes2.add_run("Notes: ").italic = True
    notes2.add_run("_______________________________________________________________")
    doc.add_paragraph()  # spacer


def slug_filename(title: str | None) -> str:
    base = re.sub(r"[^\w\-]+", "_", (title or "xer_code_audit").strip())[:60].strip("_")
    return f"{base or 'xer_code_audit'}_handle_checklist.docx"
