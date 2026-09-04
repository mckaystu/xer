"""Markdown / JSON audit report writers."""

from __future__ import annotations

import json
from pathlib import Path

from analytics.code_auditor.models import AuditReport


def render_markdown(report: AuditReport) -> str:
    counts = report.severity_counts()
    risk = report.risk_score()
    lines: list[str] = []
    lines.append("# Domino DXL Code Analysis & AI Quality Audit Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Source:** `{report.source}`")
    lines.append(f"- **Total Files Scanned:** {report.files_scanned}")
    lines.append(f"- **Code Blocks Scanned:** {report.blocks_scanned}")
    lines.append(f"- **Blocks After Pre-Filter:** {report.blocks_prefiltered}")
    lines.append(
        f"- **Total Vulnerabilities Detected:** {len(report.findings)} "
        f"(Critical: {counts['CRITICAL']}, High: {counts['HIGH']}, "
        f"Medium: {counts['MEDIUM']}, Low: {counts['LOW']})"
    )
    lines.append(f"- **Overall Handle Exhaustion Risk Score:** **{risk}**")
    lines.append(f"- **LLM Enrichment:** {'enabled' if report.llm_enabled else 'disabled (rules-only)'}")
    if report.notes:
        lines.append("- **Notes:**")
        for note in report.notes:
            lines.append(f"  - {note}")
    lines.append("")
    lines.append("## Actionable Findings Matrix")
    lines.append("")
    lines.append("| ID | File / Element | Line | Vulnerability Type | Severity | Confidence | Action Required |")
    lines.append("|----|----------------|------|--------------------|----------|------------|-----------------|")
    if not report.findings:
        lines.append("| — | — | — | No issues detected | — | — | — |")
    else:
        for f in report.findings:
            loc = f"{Path(f.source_file).name} / {f.element_type}:{f.element_name}"
            lines.append(
                f"| {f.id} | {loc} | {f.line} | `{f.rule_id}` {f.title} | "
                f"{f.severity} | {f.confidence}% | {f.action_required} |"
            )
    lines.append("")
    lines.append("## Detailed Findings & Evidence")
    lines.append("")
    if not report.findings:
        lines.append("_No actionable findings. Continue monitoring after major DXL imports._")
        lines.append("")
        return "\n".join(lines)

    for f in report.findings:
        lines.append(f"### [{f.rule_id}] {f.title}")
        lines.append("")
        lines.append(f"**Finding ID:** `{f.id}`  ")
        lines.append(f"**Severity & Confidence:** `{f.severity}` | Confidence: `{f.confidence}%` ({f.confidence_band()})  ")
        lines.append(
            f"**Location:** `{f.source_file}` · element `{f.element_type}:{f.element_name}` · "
            f"language `{f.language}` · line `{f.line}`  "
        )
        lines.append(f"**Category:** {f.category}  ")
        lines.append(f"**Engine:** {f.engine}  ")
        lines.append(f"**Language:** {f.language_label or f.language}")
        lines.append("")
        if f.problem_breakdown:
            lines.append("#### Problem Breakdown")
            lines.append("")
            lines.append(f.problem_breakdown)
            lines.append("")
        if f.remediation_guide:
            lines.append("#### Remediation Guide")
            lines.append("")
            lines.append(f.remediation_guide)
            lines.append("")
        if f.handle_lifecycle_warning:
            lines.append(f"**Handle Lifecycle Warning:** {f.handle_lifecycle_warning}")
            lines.append("")
        lines.append(
            f"**Snippet Lines:** {f.line_number_start or f.line}–{f.line_number_end or f.line} · "
            f"**Highlight:** L{f.highlight_line or f.line}"
        )
        lines.append("")
        lines.append("#### Code Evidence (As Is)")
        lines.append("")
        lines.append("```")
        lines.append((f.code_snippet_as_is or f.evidence).rstrip())
        lines.append("```")
        lines.append("")
        lines.append("#### Technical Impact")
        lines.append("")
        lines.append(f.technical_impact)
        lines.append("")
        lines.append("#### Remediation Code (To Be)")
        lines.append("")
        lines.append("```")
        lines.append((f.code_snippet_to_be or f.remediation).rstrip())
        lines.append("```")
        lines.append("")
        lines.append(f"**Action Required:** {f.action_required}")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def write_reports(report: AuditReport, out_dir: Path, stem: str = "domino_code_audit_report") -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return {"markdown": md_path, "json": json_path}


def console_summary(report: AuditReport) -> str:
    counts = report.severity_counts()
    lines = [
        "=== Domino DXL Code Audit ===",
        f"Source: {report.source}",
        f"Files: {report.files_scanned} | Blocks: {report.blocks_scanned} → prefiltered {report.blocks_prefiltered}",
        f"Findings: {len(report.findings)} "
        f"(C:{counts['CRITICAL']} H:{counts['HIGH']} M:{counts['MEDIUM']} L:{counts['LOW']})",
        f"Handle Exhaustion Risk: {report.risk_score()}",
        f"LLM: {'on' if report.llm_enabled else 'off'}",
    ]
    for f in report.findings[:15]:
        lines.append(
            f"  [{f.severity}] {f.id} {f.rule_id} L{f.line} "
            f"{Path(f.source_file).name}:{f.element_name} ({f.confidence}%)"
        )
    if len(report.findings) > 15:
        lines.append(f"  … {len(report.findings) - 15} more")
    return "\n".join(lines)
