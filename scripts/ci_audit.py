#!/usr/bin/env python3
"""CI gate for Domino handle / formula / ownership audit.

Usage:
  python3 scripts/ci_audit.py path/to/dxl_or_odp [--max-critical N] [--max-unprotected N]
  python3 scripts/ci_audit.py --graph application_graph.json

Exit 1 when CRITICAL findings or unprotected inventory rows exceed thresholds.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analytics.code_auditor.engine import run_audit
from analytics.code_auditor.function_inventory import run_function_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="Xer Domino audit CI gate")
    parser.add_argument("source", nargs="?", help="DXL/ODP path")
    parser.add_argument("--graph", help="application_graph.json path")
    parser.add_argument("--max-critical", type=int, default=0)
    parser.add_argument("--max-high", type=int, default=50)
    parser.add_argument("--max-unprotected", type=int, default=0)
    parser.add_argument("--max-incomplete", type=int, default=25,
                        help="PARTIAL_CLEANUP + CONDITIONAL_CLEANUP budget")
    parser.add_argument("--json-out", help="Write full summary JSON")
    args = parser.parse_args()

    graph = None
    source = args.source
    if args.graph:
        graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
        source = source or args.graph

    if not source and graph is None:
        parser.error("Provide source path or --graph")

    report = run_audit(source, graph=graph, use_llm=False)
    inventory = run_function_inventory(source, graph=graph)
    active = [f for f in report.findings if not f.is_false_positive]
    critical = sum(1 for f in active if f.severity == "CRITICAL")
    high = sum(1 for f in active if f.severity == "HIGH")
    summary = inventory["summary"]
    unprotected = int(summary.get("unprotected_functions") or 0)
    incomplete = int(summary.get("functions_incomplete_cleanup") or 0)

    payload = {
        "source": str(source),
        "findings_active": len(active),
        "critical": critical,
        "high": high,
        "unprotected_functions": unprotected,
        "incomplete_cleanup": incomplete,
        "handle_safety_rate": summary.get("handle_safety_rate"),
        "recycle_coverage_rate": summary.get("recycle_coverage_rate"),
        "rule_ids": sorted({f.rule_id for f in active}),
    }
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(json.dumps(payload, indent=2))

    failed = False
    if critical > args.max_critical:
        print(f"FAIL: CRITICAL findings {critical} > {args.max_critical}", file=sys.stderr)
        failed = True
    if high > args.max_high:
        print(f"FAIL: HIGH findings {high} > {args.max_high}", file=sys.stderr)
        failed = True
    if unprotected > args.max_unprotected:
        print(f"FAIL: unprotected functions {unprotected} > {args.max_unprotected}", file=sys.stderr)
        failed = True
    if incomplete > args.max_incomplete:
        print(
            f"FAIL: incomplete cleanup {incomplete} > {args.max_incomplete}",
            file=sys.stderr,
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
