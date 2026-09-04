#!/usr/bin/env python3
"""FastAPI server for Xer graph storage and interactive ERD viewer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
    from neon_db import build_viz_payload, get_graph

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
    llm: bool = Query(False, description="Enable OpenAI enrichment when OPENAI_API_KEY is configured"),
) -> dict[str, Any]:
    """Static Domino handle/memory anti-pattern audit for code stored in the graph."""
    from analytics.code_auditor import run_audit
    from neon_db import get_graph

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    try:
        report = run_audit(
            row.get("nsf_path") or graph_id,
            graph=row["graph"],
            use_llm=llm,
            out_dir=None,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Code audit failed: {exc}") from exc
    return report.to_dict()


@app.get("/api/graphs/{graph_id}/function-inventory")
def api_graph_function_inventory(graph_id: str) -> dict[str, Any]:
    """Function inventory + recycle coverage rate for code stored in the graph."""
    from analytics.code_auditor import run_function_inventory
    from neon_db import get_graph

    try:
        row = get_graph(graph_id)
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not row:
        raise HTTPException(status_code=404, detail="Graph not found")

    try:
        return run_function_inventory(
            row.get("nsf_path") or graph_id,
            graph=row["graph"],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Function inventory failed: {exc}") from exc


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
