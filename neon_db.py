"""Neon PostgreSQL persistence for Xer application graphs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg2
from psycopg2.extras import Json, RealDictCursor, execute_batch

XER_ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = XER_ROOT / "schema.sql"


def get_database_url() -> str:
    # Prefer NEON_DATABASE_URL when set (Neon Cloud convention)
    url = os.getenv("NEON_DATABASE_URL", "").strip() or os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise ValueError(
            "NEON_DATABASE_URL or DATABASE_URL is required. "
            "Copy your pooled connection string from https://console.neon.tech into xer/.env"
        )
    return url


def connect():
    try:
        return psycopg2.connect(get_database_url())
    except psycopg2.Error as exc:
        raise ConnectionError(f"Failed to connect to Neon: {exc}") from exc


def init_schema(conn=None) -> None:
    """Apply schema.sql (idempotent)."""
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    own_conn = conn is None
    if own_conn:
        conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def _extract_nsf_path(graph: dict[str, Any]) -> str:
    meta = graph.get("meta", {})
    source_files = meta.get("source_files") or []
    if source_files:
        db_path = source_files[0].get("database_path")
        if db_path:
            return str(db_path)
        rel = source_files[0].get("path")
        if rel:
            return str(rel)
    return meta.get("input_directory", "unknown")


def _extract_database_title(graph: dict[str, Any]) -> str | None:
    source_files = graph.get("meta", {}).get("source_files") or []
    if source_files:
        return source_files[0].get("database_title")
    return None


def _compute_analysis(
    graph: dict[str, Any],
    *,
    dxl_sources: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from analytics.rules_extractor import extract_business_rules_catalog
    from analytics.scoring import calculate_modernization_score

    catalog = extract_business_rules_catalog(graph)
    score = calculate_modernization_score(graph, dxl_sources=dxl_sources or [])
    return catalog, score


def store_graph(
    graph: dict[str, Any],
    *,
    init: bool = True,
    dxl_sources: list[str] | None = None,
) -> str:
    """
    Insert a parsed application graph and normalized edges.
    Also computes and stores business_rules + modernization_score.
    Returns the new graph UUID as a string.
    """
    conn = connect()
    try:
        if init:
            init_schema(conn)

        meta = graph.get("meta", {})
        nsf_path = _extract_nsf_path(graph)
        database_title = _extract_database_title(graph)
        parser_version = meta.get("parser_version")
        totals = meta.get("totals", {})
        edges = graph.get("edges", [])
        business_rules, modernization_score = _compute_analysis(graph, dxl_sources=dxl_sources)

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dxl_graphs (
                    nsf_path, database_title, parser_version, totals, graph,
                    business_rules, modernization_score
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    nsf_path,
                    database_title,
                    parser_version,
                    Json(totals),
                    Json(graph),
                    Json(business_rules),
                    Json(modernization_score),
                ),
            )
            graph_id = cur.fetchone()[0]

            if edges:
                rows = [
                    (
                        graph_id,
                        e.get("type", ""),
                        e.get("source", {}).get("element_type", ""),
                        e.get("source", {}).get("name", ""),
                        e.get("target", {}).get("element_type", ""),
                        e.get("target", {}).get("name", ""),
                        e.get("evidence", ""),
                        Json(e.get("metadata") or {}),
                    )
                    for e in edges
                ]
                execute_batch(
                    cur,
                    """
                    INSERT INTO graph_edges
                        (graph_id, edge_type, source_type, source_name,
                         target_type, target_name, evidence, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                    page_size=500,
                )

        conn.commit()
        return str(graph_id)
    except psycopg2.Error as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to store graph: {exc}") from exc
    finally:
        conn.close()


def load_graph_from_file(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def list_graphs(limit: int = 50) -> list[dict[str, Any]]:
    conn = connect()
    try:
        init_schema(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, nsf_path, database_title, parser_version, parsed_at, totals,
                       audit_snapshot, audit_snapshot_at
                FROM dxl_graphs
                ORDER BY parsed_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            snap = row.get("audit_snapshot")
            out.append(
                {
                    "id": str(row["id"]),
                    "nsf_path": row["nsf_path"],
                    "database_title": row["database_title"],
                    "parser_version": row["parser_version"],
                    "parsed_at": row["parsed_at"].isoformat() if row["parsed_at"] else None,
                    "totals": row["totals"],
                    "audit_snapshot": snap,
                    "audit_snapshot_at": row["audit_snapshot_at"].isoformat()
                    if row.get("audit_snapshot_at")
                    else None,
                    "handle_safety_rate": (snap or {}).get("inventory", {}).get("handle_safety_rate")
                    if isinstance(snap, dict)
                    else None,
                    "critical_findings": (snap or {}).get("critical_active")
                    if isinstance(snap, dict)
                    else None,
                }
            )
        return out
    finally:
        conn.close()


def get_graph(graph_id: str) -> dict[str, Any] | None:
    conn = connect()
    try:
        init_schema(conn)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, nsf_path, database_title, parser_version, parsed_at, totals, graph,
                       business_rules, modernization_score, audit_snapshot, audit_snapshot_at
                FROM dxl_graphs
                WHERE id = %s
                """,
                (graph_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "id": str(row["id"]),
            "nsf_path": row["nsf_path"],
            "database_title": row["database_title"],
            "parser_version": row["parser_version"],
            "parsed_at": row["parsed_at"].isoformat() if row["parsed_at"] else None,
            "totals": row["totals"],
            "graph": row["graph"],
            "business_rules": row.get("business_rules"),
            "modernization_score": row.get("modernization_score"),
            "audit_snapshot": row.get("audit_snapshot"),
            "audit_snapshot_at": row["audit_snapshot_at"].isoformat()
            if row.get("audit_snapshot_at")
            else None,
        }
    finally:
        conn.close()

def ensure_analysis(
    graph_id: str,
    *,
    dxl_sources: list[str] | None = None,
    force: bool = False,
) -> dict[str, Any] | None:
    """
    Return analysis payload for a graph, computing and persisting if missing.
    """
    from analytics.rules_extractor import SCHEMA_VERSION

    row = get_graph(graph_id)
    if not row:
        return None

    catalog = row.get("business_rules")
    score = row.get("modernization_score")
    stale = bool(catalog) and catalog.get("schema_version") != SCHEMA_VERSION
    if force or stale or not catalog or not score:
        catalog, score = _compute_analysis(row["graph"], dxl_sources=dxl_sources)
        conn = connect()
        try:
            init_schema(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE dxl_graphs
                    SET business_rules = %s, modernization_score = %s
                    WHERE id = %s
                    """,
                    (Json(catalog), Json(score), UUID(graph_id)),
                )
            conn.commit()
        except psycopg2.Error as exc:
            conn.rollback()
            raise RuntimeError(f"Failed to persist analysis: {exc}") from exc
        finally:
            conn.close()

    return {
        "id": row["id"],
        "nsf_path": row["nsf_path"],
        "database_title": row["database_title"],
        "parsed_at": row["parsed_at"],
        "business_rules": catalog,
        "modernization_score": score,
    }

def get_latest_graph(nsf_path: str | None = None) -> dict[str, Any] | None:
    conn = connect()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if nsf_path:
                cur.execute(
                    """
                    SELECT id FROM dxl_graphs
                    WHERE nsf_path ILIKE %s
                    ORDER BY parsed_at DESC
                    LIMIT 1
                    """,
                    (f"%{nsf_path}%",),
                )
            else:
                cur.execute(
                    """
                    SELECT id FROM dxl_graphs
                    ORDER BY parsed_at DESC
                    LIMIT 1
                    """
                )
            row = cur.fetchone()
        if not row:
            return None
        return get_graph(str(row["id"]))
    finally:
        conn.close()


def query_edges(
    graph_id: str,
    *,
    edge_type: str | None = None,
    source_name: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    conn = connect()
    try:
        clauses = ["graph_id = %s"]
        params: list[Any] = [UUID(graph_id)]

        if edge_type:
            clauses.append("edge_type = %s")
            params.append(edge_type)
        if source_name:
            clauses.append("source_name ILIKE %s")
            params.append(f"%{source_name}%")

        params.append(limit)
        sql = f"""
            SELECT edge_type, source_type, source_name, target_type, target_name, evidence, metadata
            FROM graph_edges
            WHERE {' AND '.join(clauses)}
            ORDER BY edge_type, source_name
            LIMIT %s
        """
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def build_viz_payload(graph: dict[str, Any]) -> dict[str, Any]:
    """Build vis-network nodes/edges from a full application graph."""
    design = graph.get("design_elements", {})
    databases = graph.get("meta", {}).get("databases") or []
    multi_db = len(databases) > 1
    nodes: dict[str, dict[str, Any]] = {}
    node_list: list[dict[str, Any]] = []

    def node_id(element_type: str, name: str, database_id: str | None = None) -> str:
        if multi_db and database_id:
            return f"{database_id}:{element_type}:{name}"
        return f"{element_type}:{name}"

    def add_node(
        nid: str,
        label: str,
        group: str,
        field_count: int = 0,
        database_id: str | None = None,
    ) -> None:
        if nid in nodes:
            return
        display = f"{label}" if not multi_db else f"[{database_id}] {label}" if database_id else label
        nodes[nid] = {
            "id": nid,
            "label": display,
            "group": group,
            "fieldCount": field_count,
            "databaseId": database_id,
        }
        node_list.append(nodes[nid])

    for form in design.get("forms", []):
        db = form.get("database_id")
        nid = node_id("form", form["name"], db)
        add_node(nid, form["name"], "form", len(form.get("fields", [])), db)

    for subform in design.get("subforms", []):
        db = subform.get("database_id")
        nid = node_id("subform", subform["name"], db)
        add_node(nid, subform["name"], "subform", len(subform.get("fields", [])), db)

    for view in design.get("views", []):
        name = view["name"]
        db = view.get("database_id")
        if name.startswith("(") or "lookup" in name.lower() or "lu" in name.lower():
            group = "lookup_view"
        else:
            group = "view"
        nid = node_id("view", name, db)
        add_node(nid, name, group, len(view.get("columns", [])), db)

    for agent in design.get("agents", []):
        db = agent.get("database_id")
        nid = node_id("agent", agent["name"], db)
        add_node(nid, agent["name"], "agent", 0, db)

    for lib in design.get("script_libraries", []):
        db = lib.get("database_id")
        nid = node_id("scriptlibrary", lib["name"], db)
        add_node(nid, lib["name"], "script_library", 0, db)

    edge_list: list[dict[str, Any]] = []
    for edge in graph.get("edges", []):
        src = edge.get("source", {})
        tgt = edge.get("target", {})
        src_id = node_id(src.get("element_type", ""), src.get("name", ""), src.get("database_id"))
        tgt_id = node_id(tgt.get("element_type", ""), tgt.get("name", ""), tgt.get("database_id"))
        tgt_group = "database" if tgt.get("element_type") == "database" else tgt.get("element_type", "unknown")
        if src_id not in nodes:
            add_node(src_id, src.get("name", ""), src.get("element_type", "unknown"), database_id=src.get("database_id"))
        if tgt_id not in nodes:
            add_node(tgt_id, tgt.get("name", ""), tgt_group, database_id=tgt.get("database_id"))
        edge_list.append(
            {
                "from": src_id,
                "to": tgt_id,
                "type": edge.get("type", ""),
                "label": edge.get("type", "").replace("_", " "),
                "title": edge.get("evidence", "")[:200],
            }
        )

    return {
        "nodes": node_list,
        "edges": edge_list,
        "meta": graph.get("meta", {}),
        "multiDatabase": multi_db,
    }


def build_audit_snapshot(
    graph: dict[str, Any],
    *,
    use_llm: bool = False,
    previous: dict[str, Any] | None = None,
    include_findings: bool | None = None,
) -> dict[str, Any]:
    """Run audit + inventory and return a persisted snapshot (with optional history + findings).

    Schema v3 stores full ``code_audit`` and ``function_inventory`` payloads so the UI can
    reload without re-analyzing on every browser open.
    """
    from datetime import datetime, timezone

    from analytics.code_auditor.engine import run_audit
    from analytics.code_auditor.function_inventory import run_function_inventory

    report = run_audit(graph=graph, use_llm=use_llm)
    inventory = run_function_inventory(graph=graph)
    findings = report.findings
    active = [f for f in findings if not f.is_false_positive]
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_prefix: dict[str, int] = {}
    for f in active:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        prefix = (f.rule_id or "OTHER").split("-")[0]
        if f.rule_id.startswith("LS-DOM"):
            prefix = "LS-DOM"
        elif f.rule_id.startswith("DOM-OWN"):
            prefix = "DOM-OWN"
        elif f.rule_id.startswith("DOM-BS"):
            prefix = "DOM-BS"
        elif f.rule_id.startswith("FORM"):
            prefix = "FORM"
        by_prefix[prefix] = by_prefix.get(prefix, 0) + 1
    summary = inventory.get("summary") or {}
    now = datetime.now(timezone.utc).isoformat()
    # Always persist full findings for cache serving (v3). include_findings kept for callers.
    store_findings = True if include_findings is None else bool(include_findings)
    findings_payload = [f.to_dict() for f in findings] if store_findings else []

    code_audit = report.to_dict()
    point = {
        "at": now,
        "handle_safety_rate": summary.get("handle_safety_rate"),
        "recycle_coverage_rate": summary.get("recycle_coverage_rate"),
        "critical_active": by_sev.get("CRITICAL", 0),
        "high_active": by_sev.get("HIGH", 0),
        "findings_active": len(active),
        "llm_enabled": bool(report.llm_enabled),
    }
    history = list((previous or {}).get("history") or [])
    history.append(point)
    history = history[-24:]

    return {
        "schema_version": 3,
        "llm_enabled": bool(report.llm_enabled),
        "findings_total": len(findings),
        "findings_active": len(active),
        "by_severity": by_sev,
        "by_family": by_prefix,
        "critical_active": by_sev.get("CRITICAL", 0),
        "high_active": by_sev.get("HIGH", 0),
        "inventory": {
            "handle_safety_rate": summary.get("handle_safety_rate"),
            "recycle_coverage_rate": summary.get("recycle_coverage_rate"),
            "unprotected_functions": summary.get("unprotected_functions"),
            "functions_partial_cleanup": summary.get("functions_partial_cleanup"),
            "functions_conditional_cleanup": summary.get("functions_conditional_cleanup"),
            "functions_escape_path_gap": summary.get("functions_escape_path_gap"),
            "total_functions_scanned": summary.get("total_functions_scanned"),
        },
        # Full payloads for fast UI reload (avoid re-running rules on every browser open)
        "code_audit": code_audit,
        "function_inventory": inventory,
        "notes": list(report.notes or [])[:8],
        "history": history,
        "findings": findings_payload,
        "captured_at": now,
    }


def cached_code_audit_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Return persisted code-audit payload when schema v3 cache is present."""
    snap = row.get("audit_snapshot")
    if not isinstance(snap, dict) or int(snap.get("schema_version") or 0) < 3:
        return None
    payload = snap.get("code_audit")
    if not isinstance(payload, dict) or "findings" not in payload:
        return None
    out = dict(payload)
    out["cached"] = True
    out["cached_at"] = row.get("audit_snapshot_at") or snap.get("captured_at")
    return out


def cached_function_inventory_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Return persisted function-inventory payload when schema v3 cache is present."""
    snap = row.get("audit_snapshot")
    if not isinstance(snap, dict) or int(snap.get("schema_version") or 0) < 3:
        return None
    payload = snap.get("function_inventory")
    if not isinstance(payload, dict) or "summary" not in payload:
        return None
    out = dict(payload)
    out["cached"] = True
    out["cached_at"] = row.get("audit_snapshot_at") or snap.get("captured_at")
    return out


def ensure_audit_snapshot(
    graph_id: str,
    *,
    force: bool = False,
    use_llm: bool = False,
    include_findings: bool | None = None,
) -> dict[str, Any] | None:
    """Compute and persist audit_snapshot on the graph row when missing or forced."""
    row = get_graph(graph_id)
    if not row:
        return None
    existing = row.get("audit_snapshot")
    if existing and not force:
        return {
            "id": row["id"],
            "audit_snapshot": existing,
            "audit_snapshot_at": row.get("audit_snapshot_at"),
            "cached": True,
        }
    snapshot = build_audit_snapshot(
        row["graph"],
        use_llm=use_llm,
        previous=existing if isinstance(existing, dict) else None,
        include_findings=include_findings,
    )
    conn = connect()
    try:
        init_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dxl_graphs
                SET audit_snapshot = %s, audit_snapshot_at = now()
                WHERE id = %s
                RETURNING audit_snapshot_at
                """,
                (Json(snapshot), str(graph_id)),
            )
            ts = cur.fetchone()[0]
        conn.commit()
    except psycopg2.Error as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to persist audit snapshot: {exc}") from exc
    finally:
        conn.close()
    return {
        "id": graph_id,
        "audit_snapshot": snapshot,
        "audit_snapshot_at": ts.isoformat() if ts else None,
        "cached": False,
    }


def list_audit_trends(
    *,
    database_title: str | None = None,
    nsf_path: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return audit snapshot points for graphs matching title/path (upload lineage)."""
    rows = list_graphs(limit=max(limit, 50))
    out: list[dict[str, Any]] = []
    title_l = (database_title or "").lower()
    path_l = (nsf_path or "").lower()
    for row in rows:
        if title_l and title_l not in (row.get("database_title") or "").lower():
            continue
        if path_l and path_l not in (row.get("nsf_path") or "").lower():
            continue
        snap = row.get("audit_snapshot") or {}
        history = snap.get("history") if isinstance(snap, dict) else None
        if history:
            for point in history:
                out.append(
                    {
                        "graph_id": row["id"],
                        "database_title": row.get("database_title"),
                        "parsed_at": row.get("parsed_at"),
                        **point,
                    }
                )
        elif snap:
            out.append(
                {
                    "graph_id": row["id"],
                    "database_title": row.get("database_title"),
                    "parsed_at": row.get("parsed_at"),
                    "at": row.get("audit_snapshot_at") or row.get("parsed_at"),
                    "handle_safety_rate": (snap.get("inventory") or {}).get("handle_safety_rate"),
                    "critical_active": snap.get("critical_active"),
                    "high_active": snap.get("high_active"),
                    "findings_active": snap.get("findings_active"),
                    "llm_enabled": snap.get("llm_enabled"),
                }
            )
    # Newest last for charting
    out.sort(key=lambda p: p.get("at") or p.get("parsed_at") or "")
    return out[-limit:]


def append_runtime_signals(graph_id: str, signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Append Domino/OpenLog-style runtime handle signals onto the graph row."""
    row = get_graph(graph_id)
    if not row:
        raise ValueError("Graph not found")
    graph = dict(row["graph"] or {})
    meta = dict(graph.get("meta") or {})
    existing = list(meta.get("runtime_signals") or [])
    for sig in signals:
        existing.append(
            {
                "design_element": sig.get("design_element") or sig.get("element"),
                "kind": sig.get("kind") or "handle_warning",
                "message": sig.get("message") or "",
                "at": sig.get("at"),
                "severity": sig.get("severity") or "HIGH",
            }
        )
    meta["runtime_signals"] = existing[-500:]
    graph["meta"] = meta
    conn = connect()
    try:
        init_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE dxl_graphs SET graph = %s WHERE id = %s",
                (Json(graph), UUID(graph_id)),
            )
        conn.commit()
    except psycopg2.Error as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to store runtime signals: {exc}") from exc
    finally:
        conn.close()
    return {"id": graph_id, "runtime_signals": len(meta["runtime_signals"])}
