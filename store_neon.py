#!/usr/bin/env python3
"""Store application_graph.json in Neon PostgreSQL."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

XER_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPH = XER_ROOT / "application_graph.json"

load_dotenv(XER_ROOT / ".env", override=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Store Xer application graph in Neon")
    parser.add_argument(
        "graph_path",
        nargs="?",
        type=Path,
        default=DEFAULT_GRAPH,
        help=f"Path to application_graph.json (default: {DEFAULT_GRAPH})",
    )
    parser.add_argument(
        "--init-schema",
        action="store_true",
        help="Apply schema.sql before storing",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List stored graphs and exit",
    )
    args = parser.parse_args(argv)

    try:
        from neon_db import get_database_url, init_schema, list_graphs, load_graph_from_file, store_graph

        get_database_url()  # validate env early
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.list:
        rows = list_graphs()
        if not rows:
            print("No graphs stored yet.")
            return 0
        for row in rows:
            totals = row.get("totals") or {}
            print(
                f"{row['id']}  {row.get('database_title') or row['nsf_path']}  "
                f"forms={totals.get('forms', '?')} edges={totals.get('edges', '?')}  "
                f"{row['parsed_at']}"
            )
        return 0

    graph_path: Path = args.graph_path
    if not graph_path.exists():
        print(f"Error: graph file not found: {graph_path}", file=sys.stderr)
        return 1

    if args.init_schema:
        init_schema()
        print("Schema initialized.")

    graph = load_graph_from_file(graph_path)
    graph_id = store_graph(graph, init=not args.init_schema)
    totals = graph.get("meta", {}).get("totals", {})
    print(f"Stored graph {graph_id}")
    print(
        f"  NSF: {graph.get('meta', {}).get('source_files', [{}])[0].get('database_path', 'n/a')}"
    )
    print(
        f"  Entities: {totals.get('forms', 0)} forms, {totals.get('views', 0)} views, "
        f"{totals.get('agents', 0)} agents"
    )
    print(f"  Edges: {totals.get('edges', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
