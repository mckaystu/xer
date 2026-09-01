#!/usr/bin/env python3
"""Validate application_graph.json against audit quality gates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

XER_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPH_PATH = XER_ROOT / "application_graph.json"


def validate(graph_path: Path) -> tuple[bool, list[str]]:
    failures: list[str] = []
    graph = json.loads(graph_path.read_text(encoding="utf-8"))

    edges = graph.get("edges", [])
    agents = graph.get("design_elements", {}).get("agents", [])

    lookup_edges = [edge for edge in edges if edge.get("type") == "LOOKUP_VIA_VIEW"]
    for edge in lookup_edges:
        target_name = edge.get("target", {}).get("name", "")
        if '"' in target_name or ":" in target_name:
            failures.append(
                "LOOKUP_VIA_VIEW target contains invalid characters "
                f"({target_name!r}) — evidence: {edge.get('evidence', '')[:120]}"
            )

    selects_form_count = sum(1 for edge in edges if edge.get("type") == "SELECTS_FORM")
    if selects_form_count < 22:
        failures.append(
            f"Expected at least 22 SELECTS_FORM edges, found {selects_form_count}"
        )

    if agents:
        missing_trigger = [
            agent.get("name", "<unnamed>")
            for agent in agents
            if not agent.get("agent_trigger")
        ]
        if missing_trigger:
            failures.append(
                "Agents missing agent_trigger: " + ", ".join(missing_trigger)
            )
    else:
        failures.append("No agents found in design_elements.agents")

    return len(failures) == 0, failures


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    graph_path = Path(args[0]) if args else DEFAULT_GRAPH_PATH

    if not graph_path.exists():
        print(f"ERROR: {graph_path} not found", file=sys.stderr)
        print("VERDICT: FAIL ❌")
        return 1

    passed, failures = validate(graph_path)

    if passed:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        totals = graph.get("meta", {}).get("totals", {})
        lookup_count = sum(
            1 for edge in graph.get("edges", []) if edge.get("type") == "LOOKUP_VIA_VIEW"
        )
        selects_count = sum(
            1 for edge in graph.get("edges", []) if edge.get("type") == "SELECTS_FORM"
        )
        agents = graph.get("design_elements", {}).get("agents", [])
        fields_with_hidewhen = sum(
            1
            for form in graph.get("design_elements", {}).get("forms", [])
            for field in form.get("fields", [])
            if field.get("hidewhen")
        )

        print(f"Validated {graph_path}")
        print(f"  LOOKUP_VIA_VIEW edges: {lookup_count} (all targets clean)")
        print(f"  SELECTS_FORM edges: {selects_count}")
        print(f"  Agents with agent_trigger: {len(agents)}/{len(agents)}")
        print(f"  Fields with hidewhen: {fields_with_hidewhen}")
        print(f"  Total edges: {totals.get('edges', 'n/a')}")
        print("VERDICT: PASS ✅")
        return 0

    print(f"Validation failed for {graph_path}:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    print("VERDICT: FAIL ❌", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
