"""
Synthesize high-level application understanding from Xer application_graph.json.

Produces capability maps, business rules, document lifecycles, and flow narratives
from parsed DXL design elements, edges, and business_logic blocks.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

# Capability domain inference from design element names
DOMAIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Order Management", re.compile(r"order|line\s*item|shipment|invoice", re.I)),
    ("Quoting", re.compile(r"quote|quotation|bid", re.I)),
    ("Customer", re.compile(r"cust|customer|client|account", re.I)),
    ("Product / Catalog", re.compile(r"product|catalog|item|sku|prefix", re.I)),
    ("Web / Self-Service", re.compile(r"web|portal|self", re.I)),
    ("Administration", re.compile(r"admin|config|setup|profile|user", re.I)),
    ("Reporting", re.compile(r"report|export|print", re.I)),
    ("Integration", re.compile(r"import|sync|api|edi", re.I)),
]

LIFECYCLE_EVENTS = (
    "queryopen",
    "postopen",
    "queryclose",
    "querysave",
    "webquerysave",
    "postsave",
    "presave",
    "inputvalidation",
    "validation",
)

RE_FAILURE_MSG = re.compile(r'@Failure\s*\(\s*"([^"]+)"', re.I)
RE_DBLOOKUP = re.compile(r"@DbLookup\s*\(", re.I)
RE_USERROLES = re.compile(r"@UserRoles", re.I)
RE_ISNEW = re.compile(r"@IsNewDoc", re.I)
RE_COMMAND = re.compile(r"@Command\s*\(\s*\[([^\]]+)\]", re.I)


def infer_domain(name: str) -> str:
    for domain, pattern in DOMAIN_PATTERNS:
        if pattern.search(name):
            return domain
    return "General"


def formula_summary(body: str) -> str:
    """Heuristic plain-English summary of a formula block."""
    text = body.strip()
    if not text:
        return "Empty logic block."

    lower = text.lower()
    parts: list[str] = []

    if RE_FAILURE_MSG.search(text):
        msg = RE_FAILURE_MSG.search(text)
        parts.append(f"Validation error: \"{msg.group(1)}\"" if msg else "Validation rule on save.")
    if RE_DBLOOKUP.search(text):
        parts.append("Resolves a value via @DbLookup from another view/database.")
    if RE_USERROLES.search(text):
        parts.append("Checks current user roles for authorization.")
    if RE_ISNEW.search(text):
        parts.append("Behavior differs for new vs existing documents.")
    if "toolsrunmacro" in lower or "runmacro" in lower:
        parts.append("Invokes a shared macro/agent.")
    if "@command" in lower:
        cmd = RE_COMMAND.search(text)
        if cmd:
            parts.append(f"Runs Domino @Command [{cmd.group(1)}].")
    if "@if" in lower and not parts:
        parts.append("Conditional branching based on field or document state.")
    if text.lower().startswith("sub ") or "sub " in lower[:20]:
        parts.append("LotusScript procedure.")

    if not parts:
        excerpt = text.replace("\n", " ")[:120]
        return f"Formula logic: {excerpt}{'…' if len(text) > 120 else ''}"
    return " ".join(parts)


def _element_database_id(element: dict[str, Any]) -> str:
    return element.get("database_id") or element.get("source_file") or "default"


def _databases_from_graph(graph: dict[str, Any]) -> list[dict[str, Any]]:
    if graph.get("meta", {}).get("databases"):
        return graph["meta"]["databases"]
    sources = graph.get("meta", {}).get("source_files") or []
    dbs: list[dict[str, Any]] = []
    for sf in sources:
        db_id = sf.get("database_id") or sf.get("path", "unknown")
        dbs.append(
            {
                "id": db_id,
                "title": sf.get("database_title"),
                "path": sf.get("database_path"),
                "source_file": sf.get("path"),
                "counts": sf.get("counts", {}),
            }
        )
    return dbs


def build_capability_map(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Group design elements into business capability domains."""
    design = graph.get("design_elements", {})
    domains: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"forms": [], "views": [], "agents": [], "rules_count": 0}
    )

    for form in design.get("forms", []):
        domain = infer_domain(form["name"])
        domains[domain]["forms"].append(
            {"name": form["name"], "database_id": _element_database_id(form), "fields": len(form.get("fields", []))}
        )

    for view in design.get("views", []):
        domain = infer_domain(view["name"])
        domains[domain]["views"].append({"name": view["name"], "database_id": _element_database_id(view)})

    for agent in design.get("agents", []):
        domain = infer_domain(agent["name"])
        domains[domain]["agents"].append(
            {
                "name": agent["name"],
                "trigger": agent.get("agent_trigger"),
                "database_id": _element_database_id(agent),
            }
        )

    bl_by_owner = Counter(b.get("owner_name") for b in graph.get("business_logic", []))
    result = []
    for domain, data in domains.items():
        names = {x["name"] for x in data["forms"] + data["views"] + data["agents"]}
        data["rules_count"] = sum(bl_by_owner.get(n, 0) for n in names)
        data["element_count"] = len(data["forms"]) + len(data["views"]) + len(data["agents"])
        result.append(
            {
                "domain": domain,
                "forms": sorted(data["forms"], key=lambda x: x["name"]),
                "views": sorted(data["views"], key=lambda x: x["name"]),
                "agents": sorted(data["agents"], key=lambda x: x["name"]),
                "rules_count": data["rules_count"],
                "element_count": data["element_count"],
            }
        )
    return sorted(result, key=lambda x: -x["element_count"])


def extract_business_rules(graph: dict[str, Any], *, limit: int = 50) -> list[dict[str, Any]]:
    """Extract prioritized business rules with plain-English summaries."""
    priority = {
        "validation": 0,
        "state_transition": 1,
        "view_selection": 2,
        "lifecycle": 3,
        "conditional_logic": 4,
        "hidewhen": 5,
        "lotusscript_logic": 6,
        "agent_setup": 7,
        "general_formula": 8,
    }

    blocks = graph.get("business_logic", [])
    sorted_blocks = sorted(
        blocks,
        key=lambda b: (priority.get(b.get("category", ""), 9), b.get("owner_name", "")),
    )

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()

    for block in sorted_blocks:
        if block.get("category") in {"agent_setup", "general_formula"} and len(rules) > limit // 2:
            continue
        key = f"{block.get('owner_name')}:{block.get('event')}:{block.get('body', '')[:80]}"
        if key in seen:
            continue
        seen.add(key)

        rule_type = (block.get("category") or "logic").replace("_", " ").title()
        rules.append(
            {
                "id": f"BR-{len(rules) + 1:03d}",
                "title": _rule_title(block),
                "source": f"{block.get('owner_type')}:{block.get('owner_name')}",
                "event": block.get("event"),
                "type": rule_type,
                "category": block.get("category"),
                "context": block.get("context"),
                "summary": formula_summary(block.get("body", "")),
                "formula_excerpt": (block.get("body") or "")[:300],
                "database_id": block.get("database_id"),
            }
        )
        if len(rules) >= limit:
            break

    return rules


def _rule_title(block: dict[str, Any]) -> str:
    owner = block.get("owner_name", "Unknown")
    event = block.get("event") or block.get("category", "logic")
    category = block.get("category", "")
    if category == "validation":
        msg = RE_FAILURE_MSG.search(block.get("body", ""))
        if msg:
            return f"{owner}: {msg.group(1)[:60]}"
    if category == "view_selection":
        return f"{owner} view selection"
    if category == "hidewhen":
        ctx = block.get("context", "")
        field = ctx.split("/field:")[-1] if "/field:" in ctx else "field"
        return f"{owner}: hide {field}"
    return f"{owner} — {event}"


def build_document_lifecycles(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-form document lifecycle: open → validate → save → post-save."""
    lifecycles: list[dict[str, Any]] = []
    blocks_by_form: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for block in graph.get("business_logic", []):
        if block.get("owner_type") in {"form", "subform"}:
            blocks_by_form[block["owner_name"]].append(block)

    for form in graph.get("design_elements", {}).get("forms", []):
        name = form["name"]
        events: dict[str, list[str]] = defaultdict(list)
        for block in blocks_by_form.get(name, []):
            event = (block.get("event") or "").lower()
            if event in LIFECYCLE_EVENTS or block.get("category") in {
                "validation",
                "state_transition",
                "lifecycle",
            }:
                events[event or block["category"]].append(formula_summary(block.get("body", "")))

        if not events:
            continue

        stage_order = ["queryopen", "postopen", "inputvalidation", "validation", "querysave", "webquerysave", "postsave", "presave", "queryclose"]
        stages = [
            {"event": ev, "summaries": events[ev]}
            for ev in stage_order
            if ev in events
        ]
        lifecycles.append(
            {
                "form": name,
                "database_id": _element_database_id(form),
                "stages": stages,
                "field_count": len(form.get("fields", [])),
            }
        )

    return sorted(lifecycles, key=lambda x: -len(x["stages"]))


def build_application_flow(graph: dict[str, Any]) -> dict[str, Any]:
    """Narrative flow: agents, macro invocations, cross-database references."""
    edges = graph.get("edges", [])
    edge_counts = Counter(e.get("type") for e in edges)

    agents = graph.get("design_elements", {}).get("agents", [])
    scheduled = [a for a in agents if (a.get("agent_trigger") or "").startswith("scheduled")]
    interactive = [a for a in agents if a not in scheduled]

    invokes = [e for e in edges if e.get("type") == "INVOKES_AGENT"]
    cross_db = [e for e in edges if e.get("type") in {"REFERENCES_DATABASE", "CROSS_DATABASE_LOOKUP"}]

    macro_flows: list[dict[str, str]] = []
    for edge in invokes:
        macro_flows.append(
            {
                "from": f"{edge['source']['element_type']}:{edge['source']['name']}",
                "to": f"agent:{edge['target']['name']}",
                "evidence": edge.get("evidence", "")[:120],
                "database_id": edge.get("source", {}).get("database_id"),
            }
        )

    lookup_hubs: list[dict[str, Any]] = []
    lookup_targets = Counter(
        e["target"]["name"] for e in edges if e.get("type") == "LOOKUP_VIA_VIEW"
    )
    for view_name, count in lookup_targets.most_common(10):
        lookup_hubs.append({"view": view_name, "incoming_lookups": count})

    return {
        "edge_summary": dict(edge_counts),
        "scheduled_agents": [
            {"name": a["name"], "trigger": a.get("agent_trigger"), "database_id": _element_database_id(a)}
            for a in scheduled
        ],
        "interactive_agents": [
            {"name": a["name"], "trigger": a.get("agent_trigger"), "database_id": _element_database_id(a)}
            for a in interactive
        ],
        "macro_invocations": macro_flows,
        "cross_database_links": [
            {
                "from": f"{e['source']['element_type']}:{e['source']['name']}",
                "target_database": e["target"]["name"],
                "evidence": e.get("evidence", "")[:120],
            }
            for e in cross_db
        ],
        "lookup_hubs": lookup_hubs,
    }


def synthesize(graph: dict[str, Any], *, rules_limit: int = 50) -> dict[str, Any]:
    """Full synthesis payload for API and CLI."""
    meta = graph.get("meta", {})
    totals = meta.get("totals", {})
    databases = _databases_from_graph(graph)

    return {
        "meta": {
            "parser_version": meta.get("parser_version"),
            "generated_at": meta.get("generated_at"),
            "database_count": len(databases),
            "totals": totals,
        },
        "databases": databases,
        "capabilities": build_capability_map(graph),
        "business_rules": extract_business_rules(graph, limit=rules_limit),
        "document_lifecycles": build_document_lifecycles(graph),
        "application_flow": build_application_flow(graph),
        "category_counts": dict(Counter(b.get("category") for b in graph.get("business_logic", []))),
    }


def to_markdown(summary: dict[str, Any]) -> str:
    """Render synthesis as a Markdown report."""
    lines: list[str] = [
        "# Xer Application Analysis",
        "",
        f"**Databases:** {summary['meta']['database_count']}  ",
        f"**Business logic blocks:** {summary['meta']['totals'].get('business_logic_blocks', 'n/a')}  ",
        f"**Edges:** {summary['meta']['totals'].get('edges', 'n/a')}",
        "",
    ]

    if summary["databases"]:
        lines.extend(["## Databases", ""])
        for db in summary["databases"]:
            title = db.get("title") or db.get("id")
            counts = db.get("counts", {})
            lines.append(
                f"- **{title}** (`{db.get('id')}`) — "
                f"{counts.get('forms', 0)} forms, {counts.get('views', 0)} views, "
                f"{counts.get('agents', 0)} agents"
            )
        lines.append("")

    lines.extend(["## Business Capability Map", ""])
    lines.append("| Domain | Forms | Views | Agents | Logic blocks |")
    lines.append("|--------|------:|------:|-------:|-------------:|")
    for cap in summary["capabilities"]:
        lines.append(
            f"| {cap['domain']} | {len(cap['forms'])} | {len(cap['views'])} | "
            f"{len(cap['agents'])} | {cap['rules_count']} |"
        )
    lines.append("")

    flow = summary["application_flow"]
    if flow.get("scheduled_agents") or flow.get("macro_invocations"):
        lines.extend(["## Application Flow", ""])
        if flow.get("scheduled_agents"):
            lines.append("### Scheduled automation")
            for a in flow["scheduled_agents"]:
                lines.append(f"- **{a['name']}** — `{a.get('trigger', 'unknown')}`")
            lines.append("")
        if flow.get("macro_invocations"):
            lines.append("### Macro / agent invocations")
            for m in flow["macro_invocations"][:20]:
                lines.append(f"- `{m['from']}` → `{m['to']}`")
            lines.append("")
        if flow.get("lookup_hubs"):
            lines.append("### Shared lookup views (hubs)")
            for hub in flow["lookup_hubs"][:10]:
                lines.append(f"- **{hub['view']}** — {hub['incoming_lookups']} incoming lookups")
            lines.append("")

    if summary["document_lifecycles"]:
        lines.extend(["## Document Lifecycles", ""])
        for lc in summary["document_lifecycles"][:15]:
            lines.append(f"### {lc['form']}")
            for stage in lc["stages"]:
                lines.append(f"- **{stage['event']}**: {stage['summaries'][0]}")
            lines.append("")

    lines.extend(["## Business Rules (top)", ""])
    for rule in summary["business_rules"][:30]:
        lines.extend(
            [
                f"### {rule['id']}: {rule['title']}",
                f"- **Source:** `{rule['source']}` / `{rule.get('event', '')}`",
                f"- **Type:** {rule['type']}",
                f"- **Summary:** {rule['summary']}",
                "",
            ]
        )

    return "\n".join(lines)
