# Xer Code Analysis & Domino Auditor

What we built for Domino DXL handle lifecycle, performance, security, and AI-assisted code review.

## Overview

Xer audits HCL Domino application code extracted from DXL / On-Disk Projects (and graphs stored in Neon). It surfaces:

- C-API handle leaks and recycle/Delete gaps
- View / NIF performance anti-patterns
- Basic application security issues
- Function-level recycle coverage inventory
- Optional AI discrepancy review (`--llm`)
- Domino **SSJS script libraries** stored as `$ServerJavaScriptLibrary` (decoded from DXL rawitemdata)
- On-disk **`$FileData` notes** (`.java`, `.xsp`, `.jss`) decoded at DXL load so Java classes and XPage SSJS enter `business_logic` / inventory / audit automatically

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
   Rule engines ──► DOM-* / PERF-* / SEC-* / FORM-*  (LS-DOM-* unwired)
        │
        ├── Function Inventory (SAFE / PROTECTED / UNPROTECTED)
        │
        └── Optional LLM (Pass 1 → 2 → 3)
                │
                ▼
   Findings + As-Is / To-Be deep-dives → CLI / API / UI
```

**Loop-aware severity**

- Allocation **inside** a Java/SSJS collection loop → **CRITICAL** (C-API handle exhaustion)
- One-shot Java/SSJS helpers → **LOW** / **MEDIUM** (routine hygiene)
- **LotusScript is out of scope** — `LS-DOM-*` detectors are **not wired**; Handle Exhaustion covers Java / SSJS / XPages only


---

## Static rule catalog

### Handle lifecycle — Java / SSJS (`DOM-001` … `DOM-016`) — *Handle Exhaustion*

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

### LotusScript (`LS-DOM-001` … `LS-DOM-008`) — *disabled*

LotusScript object lifetimes do not map to Java C-API handle-table exhaustion. Detectors remain in `ls_rules.py` for reference but are **not** registered in `run_rule_engine` and do not appear in the UI.

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

Primary Handle Exhaustion inventory covers **Java / SSJS / XPages** only (`handle_exhaustion_scope: java_javascript_xpages`). LotusScript units are skipped (`lotus_script_units_skipped`).

SSJS script libraries in DXL are often stored as `$ServerJavaScriptLibrary` multipart `rawitemdata` (not `<javascript>`). `dxl_ssjs.py` decodes those into `business_logic` / audit units so APIs like `claimsPayments.exportUnprocessed` / `uploadFile` and `blueprism.getAttachment` are inventoried.

Java classes and XPages in ODP-style NSF exports live as `$FileData` notes (`.java` / `.xsp`). `dxl_filedata.py` decodes them at graph build / upload time; XPage `#{javascript:…}` fragments become discrete JavaScript units. **Re-upload DXL** after deploy so Neon graphs pick up the bodies.

| Status | Meaning |
|--------|---------|
| `SAFE_NO_HANDLES` | No Domino allocation signals |
| `PROTECTED` | Allocates + matching `.recycle()` cleanup |
| `PARTIAL_CLEANUP` / `CONDITIONAL_CLEANUP` / `ESCAPE_PATH_GAP` | Incomplete recycle paths |
| `UNPROTECTED_ALLOCATION` | Allocates with no explicit cleanup |

**Handle safety rate** = `(safe + fully protected) / Java-JS scanned` — LS does not inflate or depress this ring.
---

## Deterministic ownership (`DOM-OWN-001`)

Static call-graph ownership lives in `ownership_rules.py`. It flags handle returns/parameters where neither caller nor callee cleans up.

When the application graph is available, callees are scoped to the **same design element** or to **script libraries linked by `USES_SCRIPT_LIBRARY`** / `Use "Lib"`. Ownership analysis runs on **Java / SSJS** units only (LotusScript skipped).

LLM Pass 3 (`DOM-BS-002`) still runs for residual gaps and severity escalation, and **skips elements already covered by `DOM-OWN-001`**.

Inventory also classifies **`ESCAPE_PATH_GAP`** when `Exit Sub` / `GoTo` / early `return` happens after allocation but before cleanup on that path.

---

## Formula quality (`FORM-001` … `FORM-003`)

Formula units are extracted from DXL/graph for a **separate** quality track (not C-API recycle):

| ID | Focus |
|----|--------|
| FORM-001 | Repeated `@DbLookup` / `@DbColumn` |
| FORM-002 | Lookups inside `@While` / `@For` |
| FORM-003 | Hardcoded secrets / plaintext `http://` |

---

## Continuous assurance

| Surface | Path |
|---------|------|
| Persisted snapshot | `dxl_graphs.audit_snapshot` (+ history[] + optional findings) |
| API | `GET …/audit-snapshot`, `GET …/audit-trends` |
| Upload | Recomputes snapshot after DXL store |
| Code-audit GET | Refreshes snapshot; LLM runs persist findings (capped) |
| Overview | Handle Safety Trend strip |
| Runtime bridge | `POST …/runtime-signals` (OpenLog/DPOOL ingest stub) |
| CI gate | `python3 scripts/ci_audit.py <path>` |
| Catalog mining | `python3 scripts/mine_api_catalog.py application_graph.json` |

---

## AI discrepancy audit (`--llm`)

Requires `OPENAI_API_KEY` (optional `XER_AUDIT_MODEL`). Implemented in `llm_engine.py`.

| Pass | Role |
|------|------|
| **Pass 1** | False-positive filter; **`VERIFIED_NON_LOOP`** demotes one-shot helpers to LOW + hygiene note |
| **Pass 2** | Blind spots on handle-allocating units with zero static hits → `DOM-BS-001` |
| **Pass 3** | Cross-module ownership + severity escalation on background/hot paths → `DOM-BS-002` (deduped vs `DOM-OWN-001`) |

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

- **`EncodeBase64`**: no `LS-DOM-*` findings (LotusScript out of Handle Exhaustion scope)
- **`upgrade_scan`**: LotusScript DB refs only; **0** false Java `getDatabase` counts
- **SEC-001 / SEC-002**: fire on hardcoded HTTP credentials and query-driven UNID lookups where present

---

## Key package layout

```text
xer/
├── domino_dxl_auditor.py
├── upgrade_scan.py
├── analytics/code_auditor/
│   ├── api_catalog.py      # Shared Notes*/alloc API catalog
│   ├── ownership_rules.py  # DOM-OWN-001 static ownership
│   ├── form_rules.py       # FORM-001..003 formula quality
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
├── scripts/ci_audit.py     # CI gate (critical / unprotected budgets)
├── web/app.js              # Code Analysis UI
├── tests/audit/
└── docs/Xer_Code_Analysis_Rubric.docx
```
