#!/usr/bin/env python3
"""
Domino DXL Code Analysis & AI Quality Auditor

Scans DXL exports or On-Disk Project sources for Domino C-API handle leaks,
ODA vs lotus.domino conflicts, static handle lifetime bugs, and expensive
data-access patterns. Emits a console summary plus Markdown/JSON reports.

Setup
-----
  pip install -r requirements.txt
  # Optional AI enrichment:
  export OPENAI_API_KEY=sk-...
  # Optional model override:
  export XER_AUDIT_MODEL=gpt-4o-mini

Examples
--------
  # Rules-only audit of a DXL file
  python3 domino_dxl_auditor.py dxl_input/Order_Entry.nsf.dxl

  # Directory of DXL / ODP sources with report output
  python3 domino_dxl_auditor.py ./dxl_input --out-dir analysis

  # Enable LLM enrichment (requires OPENAI_API_KEY)
  python3 domino_dxl_auditor.py ./dxl_input --llm --out-dir analysis

  # Audit code already stored in a Xer application_graph.json
  python3 domino_dxl_auditor.py --graph application_graph.json --out-dir analysis
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

XER_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(XER_ROOT))
load_dotenv(XER_ROOT / ".env", override=False)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit Domino DXL / ODP code for handle leaks and memory anti-patterns"
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        help="DXL file, directory of DXL/ODP sources, or omit when using --graph",
    )
    parser.add_argument(
        "--graph",
        type=Path,
        help="Path to Xer application_graph.json (audits embedded LotusScript/Java blocks)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("analysis"),
        help="Directory for domino_code_audit_report.md/.json (default: analysis/)",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable OpenAI enrichment (requires OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Force rules-only mode even if OPENAI_API_KEY is set",
    )
    parser.add_argument(
        "--max-llm-units",
        type=int,
        default=25,
        help="Max prefiltered code blocks to send to the LLM (default: 25)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="OpenAI model override (default: env XER_AUDIT_MODEL or gpt-4o-mini)",
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Print full JSON report to stdout instead of the console summary",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.source and not args.graph:
        print("Error: provide a DXL/ODP path or --graph application_graph.json", file=sys.stderr)
        return 2

    from analytics.code_auditor import console_summary, run_audit

    graph = None
    source: Path | None = args.source
    if args.graph:
        graph = json.loads(Path(args.graph).read_text(encoding="utf-8"))
        source = args.graph

    use_llm: bool | None
    if args.no_llm:
        use_llm = False
    elif args.llm:
        use_llm = True
    else:
        use_llm = False  # default CLI is rules-only unless --llm

    try:
        report = run_audit(
            source,
            graph=graph,
            use_llm=use_llm,
            max_llm_units=args.max_llm_units,
            model=args.model,
            out_dir=args.out_dir,
            report_stem="domino_code_audit_report",
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1

    if args.json_stdout:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(console_summary(report))
        print(f"\nWrote {args.out_dir / 'domino_code_audit_report.md'}")
        print(f"Wrote {args.out_dir / 'domino_code_audit_report.json'}")

    # Non-zero when critical findings exist (handy for CI)
    if report.severity_counts()["CRITICAL"] > 0:
        return 10
    if report.severity_counts()["HIGH"] > 0:
        return 11
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
