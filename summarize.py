#!/usr/bin/env python3
"""Generate high-level application analysis from Xer application_graph.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graph_synthesis import synthesize, to_markdown

XER_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPH = XER_ROOT / "application_graph.json"
DEFAULT_OUTPUT_DIR = XER_ROOT / "analysis"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synthesize capability maps, business rules, and flow from a Xer graph"
    )
    parser.add_argument(
        "graph",
        nargs="?",
        type=Path,
        default=DEFAULT_GRAPH,
        help="Path to application_graph.json",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write Markdown report to this file (default: stdout only)",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Write full synthesis JSON to this file",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help=f"Write application_analysis.md and synthesis.json to directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--rules-limit",
        type=int,
        default=50,
        help="Max business rules to include (default: 50)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    graph_path: Path = args.graph

    if not graph_path.exists():
        print(f"Error: graph not found: {graph_path}", file=sys.stderr)
        return 1

    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    summary = synthesize(graph, rules_limit=args.rules_limit)
    markdown = to_markdown(summary)

    out_dir = args.out_dir
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / "application_analysis.md"
        json_path = out_dir / "synthesis.json"
        md_path.write_text(markdown + "\n", encoding="utf-8")
        json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {md_path}")
        print(f"Wrote {json_path}")

    if args.output:
        args.output.write_text(markdown + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")

    if args.json:
        args.json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {args.json}")

    if not out_dir and not args.output and not args.json:
        print(markdown)

    totals = summary["meta"]["totals"]
    print(
        f"\nSynthesis: {summary['meta']['database_count']} database(s), "
        f"{len(summary['capabilities'])} capability domains, "
        f"{len(summary['business_rules'])} rules, "
        f"{len(summary['document_lifecycles'])} lifecycles, "
        f"{len(summary['application_flow'].get('macro_invocations', []))} macro flows",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
