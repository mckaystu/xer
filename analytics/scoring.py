"""
Modernization readiness / complexity scoring for Domino DXL applications.

Uses NetworkX on the relationship graph plus regex scans of DXL / formula text
for hardcoded paths, IPs, and Domino hierarchical names.
"""

from __future__ import annotations

import re
from typing import Any

import networkx as nx

WEIGHT_COUPLING = 0.30
WEIGHT_CROSS_DB = 0.25
WEIGHT_HARDCODED = 0.25
WEIGHT_ORPHANS = 0.20

RE_WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
RE_UNC_PATH = re.compile(r"\\\\[^\s\"']+")
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_DOMINO_NAME = re.compile(
    r"\bCN=[A-Za-z0-9 _.-]+(?:/(?:O|OU|C)=[A-Za-z0-9 _.-]+)+",
    re.I,
)
RE_NSF_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']+\.nsf|\\\\[^\s\"']+\.nsf|[A-Za-z0-9_.\\/-]+\.nsf", re.I)

CROSS_DB_EDGE_TYPES = {"REFERENCES_DATABASE", "CROSS_DATABASE_LOOKUP"}


def _node_key(element_type: str, name: str, database_id: str | None = None) -> str:
    if database_id:
        return f"{database_id}:{element_type}:{name}"
    return f"{element_type}:{name}"


def build_networkx_graph(graph: dict[str, Any]) -> nx.DiGraph:
    """Build a DiGraph from Xer application_graph design elements + edges."""
    g = nx.DiGraph()
    design = graph.get("design_elements", {})

    for etype, key in (
        ("form", "forms"),
        ("subform", "subforms"),
        ("view", "views"),
        ("agent", "agents"),
        ("scriptlibrary", "script_libraries"),
    ):
        for el in design.get(key, []):
            nid = _node_key(etype, el.get("name", ""), el.get("database_id"))
            g.add_node(
                nid,
                element_type=etype,
                name=el.get("name"),
                database_id=el.get("database_id"),
            )

    for edge in graph.get("edges", []):
        src = edge.get("source") or {}
        tgt = edge.get("target") or {}
        sid = _node_key(src.get("element_type", ""), src.get("name", ""), src.get("database_id"))
        tid = _node_key(tgt.get("element_type", ""), tgt.get("name", ""), tgt.get("database_id"))
        if sid not in g:
            g.add_node(sid, element_type=src.get("element_type"), name=src.get("name"))
        if tid not in g:
            g.add_node(tid, element_type=tgt.get("element_type"), name=tgt.get("name"))
        g.add_edge(sid, tid, edge_type=edge.get("type"), evidence=edge.get("evidence"))

    return g


def _collect_source_text(graph: dict[str, Any], dxl_sources: list[str] | None) -> str:
    parts: list[str] = list(dxl_sources or [])
    for block in graph.get("business_logic", []):
        body = block.get("body")
        if body:
            parts.append(body)
    for edge in graph.get("edges", []):
        ev = edge.get("evidence")
        if ev:
            parts.append(ev)
    design = graph.get("design_elements", {})
    for key in ("forms", "subforms"):
        for form in design.get(key, []):
            for field in form.get("fields", []):
                for attr in ("default_value", "input_validation", "input_translation", "hidewhen"):
                    val = field.get(attr)
                    if val:
                        parts.append(val)
                for formula in field.get("embedded_formulas") or []:
                    parts.append(formula)
    return "\n".join(parts)


def _scan_hardcoded(text: str) -> dict[str, Any]:
    win_paths = sorted(set(RE_WIN_PATH.findall(text)))
    unc_paths = sorted(set(RE_UNC_PATH.findall(text)))
    ips = sorted(set(RE_IP.findall(text)))
    domino_names = sorted(set(RE_DOMINO_NAME.findall(text)))
    # NSF path hits often overlap win/unc; keep distinct samples
    nsf_paths = sorted({m.group(0) for m in RE_NSF_PATH.finditer(text)})[:40]

    samples = {
        "file_paths": (win_paths + unc_paths)[:20],
        "ip_addresses": ips[:20],
        "domino_names": domino_names[:20],
        "nsf_references": nsf_paths[:20],
    }
    count = (
        len(win_paths)
        + len(unc_paths)
        + len(ips)
        + len(domino_names)
        + min(len(nsf_paths), 15)  # cap NSF contribution — common in Domino
    )
    return {"count": count, "samples": samples}


def _risk_rating(score: int) -> str:
    if score <= 33:
        return "Low Complexity"
    if score <= 66:
        return "Moderate Complexity"
    return "High Risk / High Effort"


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def calculate_modernization_score(
    graph: dict[str, Any] | nx.DiGraph,
    dxl_sources: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compute modernization complexity score (0–100) and metric breakdown.

    Parameters
    ----------
    graph:
        Either a Xer application_graph dict or a pre-built NetworkX DiGraph.
        When a DiGraph is passed, pass the original dict via keyword only for
        text scanning by also including formula text in ``dxl_sources``.
    dxl_sources:
        Optional raw DXL/XML strings for anti-pattern scanning.
    """
    app_graph: dict[str, Any]
    if isinstance(graph, nx.DiGraph):
        nx_graph = graph
        app_graph = {}
    else:
        app_graph = graph
        nx_graph = build_networkx_graph(graph)

    n_nodes = nx_graph.number_of_nodes() or 1
    n_edges = nx_graph.number_of_edges()

    degrees = dict(nx_graph.degree())
    max_degree = max(degrees.values()) if degrees else 0
    max_node = max(degrees, key=degrees.get) if degrees else None
    coupling_ratio = _clamp01(max_degree / n_nodes)

    # Cross-DB: REFERENCES_DATABASE (+ lookups that target another database_id)
    cross_db_edges = 0
    total_typed_edges = 0
    edge_list = app_graph.get("edges") if app_graph else None
    if edge_list is not None:
        for edge in edge_list:
            total_typed_edges += 1
            et = edge.get("type")
            if et in CROSS_DB_EDGE_TYPES:
                cross_db_edges += 1
                continue
            if et == "LOOKUP_VIA_VIEW":
                src = edge.get("source") or {}
                tgt = edge.get("target") or {}
                meta = edge.get("metadata") or {}
                if meta.get("database") or (
                    src.get("database_id")
                    and tgt.get("database_id")
                    and src.get("database_id") != tgt.get("database_id")
                ):
                    cross_db_edges += 1
    else:
        for _u, _v, data in nx_graph.edges(data=True):
            total_typed_edges += 1
            if data.get("edge_type") in CROSS_DB_EDGE_TYPES:
                cross_db_edges += 1

    cross_db_ratio = _clamp01(cross_db_edges / total_typed_edges) if total_typed_edges else 0.0

    source_text = _collect_source_text(app_graph, dxl_sources)
    hardcoded = _scan_hardcoded(source_text)
    # Soft saturation so a handful of hits don't immediately max the component
    hardcoded_ratio = _clamp01(hardcoded["count"] / (hardcoded["count"] + 12))

    orphans = [n for n, d in degrees.items() if d == 0]
    orphan_ratio = _clamp01(len(orphans) / n_nodes)

    weighted = (
        WEIGHT_COUPLING * coupling_ratio
        + WEIGHT_CROSS_DB * cross_db_ratio
        + WEIGHT_HARDCODED * hardcoded_ratio
        + WEIGHT_ORPHANS * orphan_ratio
    )
    score = int(round(100 * _clamp01(weighted)))

    top_coupled = sorted(degrees.items(), key=lambda kv: -kv[1])[:8]

    return {
        "score": score,
        "risk_rating": _risk_rating(score),
        "weights": {
            "coupling": WEIGHT_COUPLING,
            "cross_db": WEIGHT_CROSS_DB,
            "hardcoded": WEIGHT_HARDCODED,
            "orphans": WEIGHT_ORPHANS,
        },
        "metrics": {
            "coupling": {
                "ratio": round(coupling_ratio, 4),
                "max_degree": max_degree,
                "max_degree_node": max_node,
                "node_count": n_nodes,
                "weighted_contribution": round(WEIGHT_COUPLING * coupling_ratio * 100, 2),
            },
            "cross_db": {
                "ratio": round(cross_db_ratio, 4),
                "cross_db_edges": cross_db_edges,
                "total_edges": total_typed_edges or n_edges,
                "weighted_contribution": round(WEIGHT_CROSS_DB * cross_db_ratio * 100, 2),
            },
            "hardcoded": {
                "ratio": round(hardcoded_ratio, 4),
                "count": hardcoded["count"],
                "samples": hardcoded["samples"],
                "weighted_contribution": round(WEIGHT_HARDCODED * hardcoded_ratio * 100, 2),
            },
            "orphans": {
                "ratio": round(orphan_ratio, 4),
                "count": len(orphans),
                "examples": orphans[:12],
                "weighted_contribution": round(WEIGHT_ORPHANS * orphan_ratio * 100, 2),
            },
        },
        "top_coupled_nodes": [{"id": nid, "degree": deg} for nid, deg in top_coupled],
    }


# Alias matching the requested signature more closely
def calculate_modernization_score_nx(graph: nx.DiGraph, dxl_sources: list[str]) -> dict:
    return calculate_modernization_score(graph, dxl_sources)
