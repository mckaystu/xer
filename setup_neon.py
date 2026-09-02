#!/usr/bin/env python3
"""
One-shot Neon Cloud setup for Xer.

1. Copy your connection string from https://console.neon.tech
2. Paste into xer/.env as DATABASE_URL (use the *pooler* URL)
3. Run: python3 setup_neon.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

XER_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPH = XER_ROOT / "application_graph.json"

load_dotenv(XER_ROOT / ".env", override=False)


def main() -> int:
    print("Xer → Neon Cloud setup\n")

    env_path = XER_ROOT / ".env"
    if not env_path.exists():
        print("Missing xer/.env")
        print("\n1. Go to https://console.neon.tech")
        print("2. Select your project → Connect")
        print("3. Copy the *pooled* connection string (postgresql://…-pooler…)")
        print("4. Run:")
        print(f"   cp {XER_ROOT / '.env.example'} {env_path}")
        print("   # Edit .env and set DATABASE_URL=postgresql://…?sslmode=require")
        return 1

    try:
        from neon_db import connect, get_database_url, init_schema, load_graph_from_file, store_graph

        url = get_database_url()
        # Mask password in log
        safe = url.split("@")[-1] if "@" in url else "(configured)"
        print(f"Connecting to Neon …@{safe}")

        conn = connect()
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            version = cur.fetchone()[0]
        conn.close()
        print(f"Connected: {version[:60]}…\n")

        print("Applying schema (dxl_graphs, graph_edges)…")
        init_schema()
        print("Schema ready.\n")

        if not DEFAULT_GRAPH.exists():
            print(f"No {DEFAULT_GRAPH.name} found. Run: python3 dxl_parser.py")
            return 1

        print(f"Storing {DEFAULT_GRAPH.name}…")
        graph = load_graph_from_file(DEFAULT_GRAPH)
        graph_id = store_graph(graph, init=False)
        totals = graph.get("meta", {}).get("totals", {})
        print(f"\nStored graph: {graph_id}")
        print(f"  Title: {graph.get('meta', {}).get('source_files', [{}])[0].get('database_title', 'n/a')}")
        print(f"  Edges: {totals.get('edges', 0)}")
        print("\nNext: start the explorer")
        print("  uv run uvicorn server:app --host 127.0.0.1 --port 8765")
        print("  Open http://127.0.0.1:8765")
        return 0

    except ValueError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        print("\nNeon tips:")
        print("  • Use the *pooler* host (…-pooler….neon.tech)")
        print("  • Append ?sslmode=require")
        print("  • Create project at https://console.neon.tech if needed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
