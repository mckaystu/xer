#!/usr/bin/env python3
"""FastAPI server for Xer graph storage and interactive ERD viewer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
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
    uvicorn.run("api:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
