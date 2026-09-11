#!/usr/bin/env python3
"""FastAPI server for Xer graph storage and interactive ERD viewer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

XER_ROOT = Path(__file__).resolve().parent
WEB_DIR = XER_ROOT / "web"

load_dotenv(XER_ROOT / ".env", override=False)

app = FastAPI(title="Xer DXL Graph API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class StoreGraphRequest(BaseModel):
    graph: dict[str, Any]


class TriageOverrideRequest(BaseModel):
    kind: str  # inventory | finding
    id: str
    is_false_positive: bool = True
    reason: str = ""


# Vercel serverless request body limit is ~4.5 MB; keep default just under that.
MAX_DXL_UPLOAD_BYTES = int(float(os.getenv("XER_MAX_UPLOAD_MB", "4.5")) * 1024 * 1024)


@app.get("/api/health")
def health() -> dict[str, str]:
    try:
        from neon_db import get_database_url

        get_database_url()
        return {"status": "ok", "database": "configured"}
    except ValueError:
        return {"status": "ok", "database": "not_configured"}


@app.get("/api/graphs")
def api_list_graphs(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    from neon_db import list_graphs

    try:
        return list_graphs(limit=limit)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/graphs/latest")
def api_latest_graph(nsf_path: str | None = None) -> dict[str, Any]:
    from neon_db import get_latest_graph

    try:
        row = get_latest_graph(nsf_path)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="No graphs found")
    return row


@app.get("/api/graphs/{graph_id}")
def api_get_graph(graph_id: str) -> dict[str, Any]:
    from neon_db import get_graph

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")
    return row


@app.get("/api/graphs/{graph_id}/viz")
def api_graph_viz(graph_id: str) -> dict[str, Any]:
    from neon_db import build_viz_payload, extract_source_dxl, get_graph

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")
    payload = build_viz_payload(row["graph"])
    payload["graphId"] = graph_id
    payload["database_title"] = row.get("database_title")
    payload["nsf_path"] = row.get("nsf_path")
    payload["source_dxl"] = row.get("source_dxl") or extract_source_dxl(
        row.get("graph") if isinstance(row.get("graph"), dict) else None
    )
    return payload


@app.get("/api/graphs/{graph_id}/summary")
def api_graph_summary(graph_id: str, rules_limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    from graph_synthesis import synthesize
    from neon_db import get_graph

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")
    return synthesize(row["graph"], rules_limit=rules_limit)


@app.get("/api/graphs/{graph_id}/analysis")
@app.get("/api/applications/{graph_id}/analysis")
def api_graph_analysis(graph_id: str, refresh: bool = Query(False)) -> dict[str, Any]:
    """Return BusinessRulesCatalog + modernization score for a stored graph."""
    from neon_db import ensure_analysis

    try:
        payload = ensure_analysis(graph_id, force=refresh)
    except (ValueError, ConnectionError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not payload:
        raise HTTPException(status_code=404, detail="Graph not found")
    return payload


@app.get("/api/graphs/{graph_id}/code-audit")
def api_graph_code_audit(
    graph_id: str,
    llm: bool | None = Query(
        None,
        description="AI discrepancy audit: omit to auto-enable when OPENAI_API_KEY is set; true/false to force",
    ),
    refresh: bool = Query(
        False,
        description="Force re-analyze even when a cached Code Analysis result exists",
    ),
) -> dict[str, Any]:
    """Domino handle/memory audit for code stored in the graph.

    Serves Neon cache when present (fast reload). When analysis is computed
    (cache miss, refresh, or rules-only cache with API key), AI discrepancy
    audit runs automatically if ``OPENAI_API_KEY`` is configured.
    """
    from analytics.code_auditor.llm_engine import llm_available
    from neon_db import (
        cached_code_audit_from_row,
        ensure_audit_snapshot,
        get_graph,
    )

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    use_llm = llm_available() if llm is None else bool(llm)

    if not refresh:
        cached = cached_code_audit_from_row(row)
        if cached:
            # Keep fast path; auto-upgrade rules-only cache once AI is configured
            if llm is False or cached.get("llm_enabled") or not use_llm:
                return cached

    try:
        result = ensure_audit_snapshot(
            graph_id,
            force=True,
            use_llm=use_llm,
            include_findings=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Code audit failed: {exc}") from exc

    snap = (result or {}).get("audit_snapshot") or {}
    payload = snap.get("code_audit")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Code audit produced no cacheable payload")
    out = dict(payload)
    out["cached"] = False
    out["cached_at"] = (result or {}).get("audit_snapshot_at") or snap.get("captured_at")
    return out


@app.get("/api/graphs/{graph_id}/function-inventory")
def api_graph_function_inventory(
    graph_id: str,
    refresh: bool = Query(
        False,
        description="Force re-inventory even when a cached result exists",
    ),
    llm: bool | None = Query(
        None,
        description="AI inventory FP review: omit to auto-enable when OPENAI_API_KEY is set",
    ),
) -> dict[str, Any]:
    """Function inventory + recycle coverage for code stored in the graph.

    Serves Neon cache when present; recomputes (with AI when configured) on
    refresh, cache miss, or rules-only upgrade.
    """
    from analytics.code_auditor.llm_engine import llm_available
    from neon_db import (
        cached_function_inventory_from_row,
        ensure_audit_snapshot,
        get_graph,
    )

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    use_llm = llm_available() if llm is None else bool(llm)

    if not refresh:
        cached = cached_function_inventory_from_row(row)
        if cached:
            if llm is False or cached.get("llm_enabled") or not use_llm:
                return cached

    try:
        result = ensure_audit_snapshot(
            graph_id, force=True, use_llm=use_llm, include_findings=True
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Function inventory failed: {exc}") from exc

    snap = (result or {}).get("audit_snapshot") or {}
    payload = snap.get("function_inventory")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Function inventory produced no cacheable payload")
    out = dict(payload)
    out["cached"] = False
    out["cached_at"] = (result or {}).get("audit_snapshot_at") or snap.get("captured_at")
    return out


@app.get("/api/graphs/{graph_id}/code-audit.docx")
def api_graph_code_audit_docx(
    graph_id: str,
    llm: bool | None = Query(
        None,
        description="AI discrepancy: omit to auto-enable when OPENAI_API_KEY is set",
    ),
    refresh: bool = Query(
        False,
        description="Force re-analyze before building the Word checklist",
    ),
) -> Response:
    """Download a Word checklist of Code Analysis findings for developer remediation."""
    from analytics.code_auditor.docx_export import build_code_audit_checklist_docx, slug_filename
    from analytics.code_auditor.llm_engine import llm_available
    from analytics.code_auditor.models import AuditReport, Finding
    from neon_db import (
        cached_code_audit_from_row,
        cached_function_inventory_from_row,
        ensure_audit_snapshot,
        get_graph,
    )

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    use_llm = llm_available() if llm is None else bool(llm)
    cached_audit = cached_code_audit_from_row(row)
    need_compute = (
        refresh
        or not cached_audit
        or (use_llm and not cached_audit.get("llm_enabled") and llm is not False)
    )
    if need_compute:
        try:
            ensure_audit_snapshot(
                graph_id,
                force=True,
                use_llm=use_llm,
                include_findings=True,
            )
            row = get_graph(graph_id) or row
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"Code audit failed: {exc}") from exc

    cached_audit = cached_code_audit_from_row(row)
    inventory = cached_function_inventory_from_row(row)
    if not cached_audit:
        raise HTTPException(status_code=422, detail="No code audit available to export")

    findings: list[Finding] = []
    for fd in cached_audit.get("findings") or []:
        try:
            sev = str(fd.get("severity") or "MEDIUM").upper()
            if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                sev = "MEDIUM"
            findings.append(
                Finding(
                    id=str(fd.get("id") or fd.get("finding_id") or ""),
                    rule_id=str(fd.get("rule_id") or ""),
                    title=str(fd.get("title") or fd.get("issue") or ""),
                    severity=sev,  # type: ignore[arg-type]
                    confidence=int(fd.get("confidence") or 0),
                    source_file=str(fd.get("source_file") or fd.get("file_path") or ""),
                    element_name=str(fd.get("element_name") or ""),
                    element_type=str(fd.get("element_type") or ""),
                    language=str(fd.get("language") or ""),
                    line=int(fd.get("line") or fd.get("line_number") or 0),
                    evidence=str(fd.get("evidence") or ""),
                    technical_impact=str(fd.get("technical_impact") or ""),
                    remediation=str(fd.get("remediation") or ""),
                    action_required=str(fd.get("action_required") or ""),
                    category=str(fd.get("category") or ""),
                    engine=str(fd.get("engine") or "rules"),
                    code_snippet_as_is=str(fd.get("code_snippet_as_is") or ""),
                    code_snippet_to_be=str(fd.get("code_snippet_to_be") or ""),
                    problem_breakdown=str(fd.get("problem_breakdown") or ""),
                    remediation_guide=str(fd.get("remediation_guide") or ""),
                    language_label=str(fd.get("language_label") or ""),
                    is_false_positive=bool(fd.get("is_false_positive")),
                    is_blind_spot=bool(fd.get("is_blind_spot")),
                    ai_validation_status=str(fd.get("ai_validation_status") or ""),
                )
            )
        except Exception:  # noqa: BLE001
            continue

    report = AuditReport(
        source=str(cached_audit.get("source") or row.get("nsf_path") or graph_id),
        files_scanned=int(cached_audit.get("files_scanned") or 0),
        blocks_scanned=int(cached_audit.get("blocks_scanned") or 0),
        blocks_prefiltered=int(cached_audit.get("blocks_prefiltered") or 0),
        findings=findings,
        llm_enabled=bool(cached_audit.get("llm_enabled")),
        notes=list(cached_audit.get("notes") or []),
    )

    try:
        payload = build_code_audit_checklist_docx(
            report,
            database_title=row.get("database_title"),
            nsf_path=row.get("nsf_path"),
            inventory=inventory,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"DOCX export failed: {exc}") from exc

    filename = slug_filename(row.get("database_title") or row.get("nsf_path") or graph_id)
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/code-analysis/rubric.docx")
def api_code_analysis_rubric_docx() -> Response:
    """Download the live Code Analysis search-rules / rubric / AI-inference Word guide."""
    from analytics.code_auditor.docx_export import build_code_analysis_rubric_docx

    try:
        payload = build_code_analysis_rubric_docx()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Rubric DOCX export failed: {exc}") from exc

    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": 'attachment; filename="Xer_Code_Analysis_Rules_Rubric.docx"'
        },
    )


@app.get("/api/graphs/{graph_id}/audit-snapshot")
def api_graph_audit_snapshot(
    graph_id: str,
    refresh: bool = Query(False, description="Force recompute and persist snapshot"),
) -> dict[str, Any]:
    """Persisted handle-safety / finding trend snapshot for a graph."""
    from analytics.code_auditor.llm_engine import llm_available
    from neon_db import ensure_audit_snapshot

    try:
        payload = ensure_audit_snapshot(
            graph_id, force=refresh, use_llm=llm_available() if refresh else False
        )
    except (ValueError, ConnectionError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not payload:
        raise HTTPException(status_code=404, detail="Graph not found")
    return payload


@app.post("/api/graphs/{graph_id}/triage")
def api_graph_triage(graph_id: str, body: TriageOverrideRequest) -> dict[str, Any]:
    """Mark or clear a false-positive on an inventory function or finding (persisted)."""
    from neon_db import get_graph, set_triage_override

    kind = (body.kind or "").strip().lower()
    if kind in {"finding", "findings"}:
        kind = "finding"
    elif kind in {"inventory", "function", "func"}:
        kind = "inventory"
    else:
        raise HTTPException(status_code=400, detail="kind must be 'inventory' or 'finding'")

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    try:
        overrides = set_triage_override(
            graph_id,
            kind=kind,
            item_id=body.id,
            is_false_positive=bool(body.is_false_positive),
            reason=body.reason or "",
            source="human",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {
        "ok": True,
        "graph_id": graph_id,
        "kind": kind,
        "id": body.id,
        "is_false_positive": body.is_false_positive,
        "triage_overrides": overrides,
    }


@app.get("/api/graphs/{graph_id}/audit-trends")
def api_graph_audit_trends(
    graph_id: str,
    limit: int = Query(20, ge=2, le=50),
) -> dict[str, Any]:
    """Handle-safety / CRITICAL trend for this NSF lineage (uploads + snapshot history)."""
    from neon_db import get_graph, list_audit_trends

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")
    try:
        points = list_audit_trends(
            database_title=row.get("database_title"),
            nsf_path=row.get("nsf_path"),
            limit=limit,
        )
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "graph_id": graph_id,
        "database_title": row.get("database_title"),
        "nsf_path": row.get("nsf_path"),
        "points": points,
    }


@app.post("/api/graphs/{graph_id}/runtime-signals")
def api_runtime_signals(graph_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Ingest Domino/OpenLog-style runtime handle warnings (DPOOL bridge stub)."""
    from neon_db import append_runtime_signals

    signals = body.get("signals") if isinstance(body, dict) else None
    if not isinstance(signals, list) or not signals:
        raise HTTPException(status_code=400, detail="Body must include non-empty signals[]")
    try:
        return append_runtime_signals(graph_id, signals)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ConnectionError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/synthesize")
def api_synthesize_local(body: StoreGraphRequest, rules_limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    from graph_synthesis import synthesize

    return synthesize(body.graph, rules_limit=rules_limit)


@app.get("/api/graphs/{graph_id}/edges")
def api_graph_edges(
    graph_id: str,
    edge_type: str | None = None,
    source_name: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
) -> list[dict[str, Any]]:
    from neon_db import query_edges

    try:
        return query_edges(graph_id, edge_type=edge_type, source_name=source_name, limit=limit)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/upload")
async def api_upload_dxl(file: UploadFile = File(...)) -> dict[str, Any]:
    """Parse an uploaded DXL/XML export, store in Neon, return graph id."""
    from dxl_parser import build_graph_from_dxl_bytes
    from graph_synthesis import synthesize
    from neon_db import store_graph

    filename = file.filename or "upload.dxl"
    lower = filename.lower()
    if not lower.endswith((".dxl", ".xml")):
        raise HTTPException(status_code=400, detail="File must be .dxl or .xml")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(content) > MAX_DXL_UPLOAD_BYTES:
        limit_mb = MAX_DXL_UPLOAD_BYTES / (1024 * 1024)
        size_mb = len(content) / (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=(
                f"File is {size_mb:.2f} MB (max {limit_mb:.1f} MB on this deployment). "
                "Parse locally instead: python3 dxl_parser.py --store-neon"
            ),
        )

    try:
        graph = build_graph_from_dxl_bytes(content, filename)
        # Pass raw DXL into scoring so hardcoded path/IP/CN scans see source text
        text = content.decode("utf-8", errors="ignore")
        graph_id = store_graph(graph, dxl_sources=[text])
    except (ValueError, ConnectionError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Parse failed: {exc}") from exc

    totals = graph.get("meta", {}).get("totals", {})
    title = (graph.get("meta", {}).get("source_files") or [{}])[0].get("database_title")
    summary = synthesize(graph, rules_limit=20)
    from neon_db import ensure_analysis

    analysis = ensure_analysis(graph_id) or {}
    audit_snap: dict[str, Any] = {}
    try:
        from neon_db import ensure_audit_snapshot

        audit_snap = ensure_audit_snapshot(graph_id, force=True, use_llm=True) or {}
    except Exception:  # noqa: BLE001
        audit_snap = {}
    return {
        "id": graph_id,
        "filename": filename,
        "database_title": title,
        "totals": totals,
        "errors": graph.get("meta", {}).get("errors", []),
        "capabilities": len(summary.get("capabilities", [])),
        "business_rules": len(summary.get("business_rules", [])),
        "rules_catalog_fields": (analysis.get("business_rules") or {}).get("totals", {}).get("fields"),
        "modernization_score": (analysis.get("modernization_score") or {}).get("score"),
        "risk_rating": (analysis.get("modernization_score") or {}).get("risk_rating"),
        "audit_snapshot": (audit_snap or {}).get("audit_snapshot"),
        "handle_safety_rate": ((audit_snap or {}).get("audit_snapshot") or {})
        .get("inventory", {})
        .get("handle_safety_rate"),
    }


@app.post("/api/graphs")
def api_store_graph(body: StoreGraphRequest) -> dict[str, str]:
    from neon_db import store_graph

    try:
        graph_id = store_graph(body.graph)
    except (ValueError, ConnectionError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"id": graph_id}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def main() -> None:
    import uvicorn

    host = os.getenv("XER_API_HOST", "127.0.0.1")
    port = int(os.getenv("XER_API_PORT", "8765"))
    uvicorn.run("server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
