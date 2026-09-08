#!/usr/bin/env python3
"""Mine Domino handle API candidates from a stored graph or DXL corpus.

Compares Dim/Get*/Create* tokens found in business_logic against api_catalog
and prints missing types/methods for catalog expansion.

Usage:
  python3 scripts/mine_api_catalog.py application_graph.json
  python3 scripts/mine_api_catalog.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analytics.code_auditor.api_catalog import ALLOC_METHODS, HANDLE_TYPES_JAVA, HANDLE_TYPES_LS

RE_DIM = re.compile(r"(?i)\bDim\s+\w+(?:\s*,\s*\w+)*\s+As\s+(?:New\s+)?(Notes\w+)\b")
RE_METHOD = re.compile(r"\b((?:Get|Create|create|get)[A-Za-z]{3,40})\s*\(")


def mine(graph: dict) -> dict:
    types: set[str] = set()
    methods: set[str] = set()
    for block in graph.get("business_logic") or []:
        body = block.get("body") or ""
        types.update(RE_DIM.findall(body))
        methods.update(RE_METHOD.findall(body))
    known_types = {t.lower() for t in HANDLE_TYPES_LS} | {t.lower() for t in HANDLE_TYPES_JAVA}
    known_methods = {m.lower() for m in ALLOC_METHODS}
    missing_types = sorted(t for t in types if t.lower() not in known_types)
    missing_methods = sorted(m for m in methods if m.lower() not in known_methods)
    return {
        "types_found": sorted(types),
        "methods_found": sorted(methods),
        "missing_types": missing_types,
        "missing_methods": missing_methods[:80],
        "catalog_ls_types": len(HANDLE_TYPES_LS),
        "catalog_alloc_methods": len(ALLOC_METHODS),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("graph", nargs="?", default="application_graph.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    path = Path(args.graph)
    if not path.is_file():
        print(f"Not found: {path}", file=sys.stderr)
        return 1
    result = mine(json.loads(path.read_text(encoding="utf-8")))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Catalog LS types: {result['catalog_ls_types']} · alloc methods: {result['catalog_alloc_methods']}")
        print(f"Missing types ({len(result['missing_types'])}):")
        for t in result["missing_types"][:40]:
            print(f"  {t}")
        print(f"Missing methods ({len(result['missing_methods'])}):")
        for m in result["missing_methods"][:40]:
            print(f"  {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
