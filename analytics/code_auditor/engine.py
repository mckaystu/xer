"""Orchestrate Domino DXL code audit: extract → prefilter → rules → optional LLM → report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analytics.code_auditor.extractor import (
    apply_prefilter,
    extract_units_from_graph,
    extract_units_from_path,
)
from analytics.code_auditor.llm_engine import enrich_with_llm, llm_available
from analytics.code_auditor.models import AuditReport
from analytics.code_auditor.report import console_summary, render_markdown, write_reports
from analytics.code_auditor.rules import run_rule_engine


def run_audit(
    source: str | Path | None = None,
    *,
    graph: dict[str, Any] | None = None,
    use_llm: bool | None = None,
    max_llm_units: int = 25,
    model: str | None = None,
    out_dir: str | Path | None = None,
    report_stem: str = "domino_code_audit_report",
) -> AuditReport:
    """
    Run a full audit against a DXL/ODP path or an in-memory Xer graph.

    ``use_llm`` defaults to True when OPENAI_API_KEY is present.
    """
    notes: list[str] = []
    if graph is not None:
        units = extract_units_from_graph(graph)
        source_label = source or graph.get("meta", {}).get("input_directory") or "application_graph"
        files_scanned = len({u.source_file for u in units}) or 1
    else:
        if source is None:
            raise ValueError("Provide source path or graph=")
        path = Path(source)
        units = extract_units_from_path(path)
        source_label = str(path)
        if path.is_file():
            files_scanned = 1
        else:
            files_scanned = len({u.source_file for u in units})

    blocks_scanned = len(units)
    filtered = apply_prefilter(units, require_keywords=True)
    # If prefilter drops everything (e.g. LotusScript without keywords), keep language-interesting blocks
    if not filtered and units:
        filtered = apply_prefilter(units, require_keywords=False)
        notes.append("Pre-filter matched no keyword hits; fell back to language-based scan.")

    findings = run_rule_engine(filtered)

    enable_llm = llm_available() if use_llm is None else bool(use_llm)
    if enable_llm:
        findings, llm_notes = enrich_with_llm(
            filtered, findings, max_units=max_llm_units, model=model
        )
        notes.extend(llm_notes)
    else:
        notes.append("Rules-only mode (set OPENAI_API_KEY and pass --llm to enable AI enrichment).")

    report = AuditReport(
        source=str(source_label),
        files_scanned=files_scanned,
        blocks_scanned=blocks_scanned,
        blocks_prefiltered=len(filtered),
        findings=findings,
        llm_enabled=enable_llm and llm_available(),
        notes=notes,
    )

    if out_dir is not None:
        write_reports(report, Path(out_dir), stem=report_stem)

    return report


def audit_as_dict(
    source: str | Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    return run_audit(source, **kwargs).to_dict()


__all__ = [
    "run_audit",
    "audit_as_dict",
    "console_summary",
    "render_markdown",
    "write_reports",
]
