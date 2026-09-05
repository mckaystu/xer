# Xer Code Analysis & Domino Auditor

What we built for Domino DXL handle lifecycle, performance, security, and AI-assisted code review.

## Overview

Xer audits HCL Domino application code extracted from DXL / On-Disk Projects (and graphs stored in Neon). It surfaces:

- C-API handle leaks and recycle/Delete gaps
- View / NIF performance anti-patterns
- Basic application security issues
- Function-level recycle coverage inventory
- Optional AI discrepancy review (`--llm`)

**Entry points**

| Surface | Path |
|--------|------|
| CLI auditor | `domino_dxl_auditor.py` |
| Language-scoped upgrade scan | `upgrade_scan.py` |
| API | `GET /api/graphs/{id}/code-audit`, `…/function-inventory` |
| UI | Code Analysis tab (`web/app.js`) |
| Engine package | `analytics/code_auditor/` |

---

## Architecture

```text
DXL / ODP / application graph
        │
        ▼
   Extractor (language-tagged code units)
        │
        ▼
   Rule engines ──► DOM-* / LS-DOM-* / PERF-* / SEC-*
        │
        ├── Function Inventory (SAFE / PROTECTED / UNPROTECTED)
        │
        └── Optional LLM (Pass 1 → 2 → 3)
                │
                ▼
   Findings + As-Is / To-Be deep-dives → CLI / API / UI
```

**Loop-aware severity**

- Allocation **inside** a collection loop → **CRITICAL** (handle exhaustion)
- One-shot helpers (e.g. `EncodeBase64`) → **LOW** / **MEDIUM** (routine hygiene)
- Non-loop remediation uses linear `Delete` / `try-finally`, not `GetNextDocument` loop templates

---

## Static rule catalog

### Handle lifecycle — Java / SSJS (`DOM-001` … `DOM-016`)

| ID | Focus |
|----|--------|
| DOM-001 | Inline chained Domino construction |
| DOM-002 | Un-recycled collection iteration |
| DOM-003 / DOM-010 | Missing try/finally recycle scaffolding |
| DOM-004 / DOM-005 | ODA vs `lotus.domino` conflicts |
| DOM-006 / DOM-007 | Static / scoped live handles |
| DOM-008 / DOM-009 | Expensive fetches / `createDateTime` in hot paths |
| DOM-011 … DOM-013 | Parent/child recycle order, conditional recycle, re-assignment |
| DOM-014 | Un-recycled Item / MIME / RichText |
| DOM-015 | Un-recycled ViewNavigator / ViewEntryCollection |
| DOM-016 | `search` / `FTSearch` collection leaks in loops |

### Handle lifecycle — LotusScript (`LS-DOM-001` … `LS-DOM-008`)

| ID | Focus |
|----|--------|
| LS-DOM-001 | Loop iteration without `Delete` |
| LS-DOM-002 | In-loop lookup / `CreateDocument` leaks |
| LS-DOM-003 | Public module-level Notes* handles |
| LS-DOM-004 | `Set … = Nothing` without `Delete` |
| LS-DOM-005 | Item / MIME / RichText without `Delete` |
| LS-DOM-006 | ViewNavigator / ViewEntryCollection without `Delete` |
| LS-DOM-007 | Error handler exits without cleanup |
| LS-DOM-008 | In-loop `Search` / `FTSearch` collection leaks |

### Performance & NIF (`PERF-001` … `PERF-003`)

| ID | Focus |
|----|--------|
| PERF-001 | Missing `view.AutoUpdate = False` in write loops |
| PERF-002 | `getView` / `GetView` inside loops (hoistable) |
| PERF-003 | Unbatched `doc.save` / `Save` per iteration |

### Security (`SEC-001`, `SEC-002`)

| ID | Focus |
|----|--------|
| SEC-001 | Hardcoded credentials + plaintext `http://` |
| SEC-002 | Query-string → `GetDocumentByUNID` without auth checks |

### AI-discovered (`DOM-BS-*`)

| ID | Focus |
|----|--------|
| DOM-BS-001 | Blind-spot handle leak (Pass 2) |
| DOM-BS-002 | Unassigned cross-function handle ownership (Pass 3) |

Catalog lives in `analytics/code_auditor/models.py`. Detectors: `rules.py`, `ls_rules.py`, `perf_rules.py`, `sec_rules.py`. Shared loop helpers: `context.py`.

---

## Function inventory

`analytics/code_auditor/function_inventory.py` inventories every Sub/Function/method and classifies:

| Status | Meaning |
|--------|---------|
| `SAFE_NO_HANDLES` | No Domino allocation signals |
| `PROTECTED` | Allocates + has `Delete` / `.recycle()` |
| `UNPROTECTED_ALLOCATION` | Allocates with no explicit cleanup |

**Metrics**

- **Handle safety rate** (primary UI ring): `(safe + protected) / scanned`
- **Recycle coverage** (secondary): `with_cleanup / allocators`

Inventory deep-dives are also loop-aware: non-loop unprotected helpers show **LOW** severity and linear cleanup templates (not CRITICAL exhaustion messaging).

---

## AI discrepancy audit (`--llm`)

Requires `OPENAI_API_KEY` (optional `XER_AUDIT_MODEL`). Implemented in `llm_engine.py`.

| Pass | Role |
|------|------|
| **Pass 1** | False-positive filter; **`VERIFIED_NON_LOOP`** demotes one-shot helpers to LOW + hygiene note |
| **Pass 2** | Blind spots on handle-allocating units with zero static hits → `DOM-BS-001` |
| **Pass 3** | Cross-module ownership + severity escalation on background/hot paths → `DOM-BS-002` |

---

## `upgrade_scan.py`

Language-scoped DXL upgrade / DB-reference counter:

- LotusScript patterns run only on `<lotusscript>` (and related LS tags)
- Java patterns run only on `<java>` / `<javaproject>`
- Prevents LS `GetDatabase` / `NotesDatabase` from being double-counted as Java `getDatabase`

```bash
python3 upgrade_scan.py dxl_input_fromboss/Code_FrombossRest.dxl
python3 upgrade_scan.py ./dxl_input --json
```

---

## UI (Code Analysis tab)

- Findings table with filters: **Handle Leaks | Performance & NIF | AI Discovered**
- Severity pills and AI validation banners (`VERIFIED`, `FALSE_POSITIVE`, `VERIFIED_NON_LOOP`, blind spots)
- Row deep-dive: Problem Breakdown, Remediation Guide, As-Is (hit line highlight), To-Be template
- PERF findings show a **Performance impact** callout
- Function inventory deep-dives use `risk_severity` / `in_loop` from the API

---

## CLI usage

```bash
# Rules-only
python3 domino_dxl_auditor.py dxl_input_fromboss/Code_FrombossRest.dxl

# With AI passes
python3 domino_dxl_auditor.py ./dxl_input --llm --out-dir analysis

# From stored graph
python3 domino_dxl_auditor.py --graph application_graph.json --out-dir analysis
```

---

## Tests

| Suite | Location |
|-------|----------|
| Handle / rule regression | `tests/test_domino_handle_audit.py` |
| Audit framework + fixtures | `tests/audit/` (rules, PERF, inventory, AI mocks) |
| Loop severity, SEC, upgrade_scan | `tests/test_loop_severity_and_upgrade_scan.py` |
| Annotated samples | `tests/audit/fixtures/*.lss`, `*.java`, `mock_xboss_graph.json` |

```bash
.venv/bin/python -m pytest tests/audit/ tests/test_domino_handle_audit.py tests/test_loop_severity_and_upgrade_scan.py -q
```

---

## Rubric / docs

- `docs/Xer_Code_Analysis_Rubric.docx` — rule catalog + AI pipeline description
- Copy also generated under `~/Downloads/Xer_Code_Analysis_Rubric.docx`

---

## Notable validation (bossrest / FrombossRest)

Against `dxl_input_fromboss/Code_FrombossRest.dxl`:

- **`EncodeBase64`**: `LS-DOM-004` at **LOW**, inventory **LOW**, linear `Delete` To-Be (no loop template)
- **`upgrade_scan`**: LotusScript DB refs only; **0** false Java `getDatabase` counts
- **SEC-001 / SEC-002**: fire on hardcoded HTTP credentials and query-driven UNID lookups where present

---

## Key package layout

```text
xer/
├── domino_dxl_auditor.py
├── upgrade_scan.py
├── analytics/code_auditor/
│   ├── context.py          # loop-aware severity
│   ├── extractor.py
│   ├── rules.py            # DOM-*
│   ├── ls_rules.py         # LS-DOM-*
│   ├── perf_rules.py       # PERF-*
│   ├── sec_rules.py        # SEC-*
│   ├── function_inventory.py
│   ├── llm_engine.py       # Pass 1–3
│   ├── snippets.py         # As-Is / To-Be templates
│   ├── models.py           # RULE_CATALOG, Finding, AuditReport
│   ├── engine.py / report.py
│   └── …
├── web/app.js              # Code Analysis UI
├── tests/audit/
└── docs/Xer_Code_Analysis_Rubric.docx
```
