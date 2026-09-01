# Xer Application Analysis

**Databases:** 1  
**Business logic blocks:** 2999  
**Edges:** 323

## Databases

- **Web Order Entry** (`Order Entry.nsf`) — 28 forms, 58 views, 22 agents

## Business Capability Map

| Domain | Forms | Views | Agents | Logic blocks |
|--------|------:|------:|-------:|-------------:|
| Order Management | 14 | 41 | 9 | 1951 |
| General | 5 | 10 | 8 | 329 |
| Quoting | 3 | 3 | 0 | 326 |
| Product / Catalog | 0 | 2 | 3 | 19 |
| Web / Self-Service | 3 | 0 | 1 | 116 |
| Reporting | 2 | 1 | 0 | 207 |
| Customer | 1 | 1 | 1 | 35 |

## Application Flow

### Scheduled automation
- **Notify CSR of Web Order or Quote** — `scheduled:byminutes`
- **Delete Old Web Orders** — `scheduled:daily`

### Macro / agent invocations
- `form:WebQuoteDetail` → `agent:(CreateWebOrderDetail)`
- `form:Web Order Select Detail` → `agent:(CreateWebOrderDetail)`
- `form:SelectDupeOrder` → `agent:(SelectDupeOrder)`
- `form:Web New Quote Header` → `agent:(CreateNewWebOrder)`
- `form:NewInsertSpecs` → `agent:(CreateConfDetail)`
- `form:Web New Order Header` → `agent:(CreateNewWebOrder)`
- `form:Web New Order Header` → `agent:(LoadHdrItemsWeb)`
- `form:OrderConfirmation` → `agent:(StatusToVerify)`
- `form:Web Lettered Insert Mod` → `agent:(MarkDupeComplete)`
- `form:Order Detail Web` → `agent:(WebDetailMods)`

### Shared lookup views (hubs)
- **(Product Information Lookup)** — 35 incoming lookups
- **(Lookup)** — 32 incoming lookups
- **Keys** — 9 incoming lookups
- **Customers\\by Number** — 5 incoming lookups
- **CustNumber** — 2 incoming lookups
- **(luCustSpecs)** — 2 incoming lookups
- **(luCustNum)** — 2 incoming lookups
- **(DetailstoDupe)** — 2 incoming lookups
- **(Product by Code)** — 2 incoming lookups
- **(luPictogram)** — 2 incoming lookups

## Document Lifecycles

### Order Entry
- **queryopen**: LotusScript procedure.
- **inputvalidation**: Validation error: "Please enter the item prefix before saving."
- **querysave**: LotusScript procedure.

### Order Header
- **queryopen**: LotusScript procedure.
- **inputvalidation**: Validation error: "You must select the correct status for this order."
- **querysave**: LotusScript procedure.

### Web Duped Order Header
- **queryopen**: LotusScript procedure.
- **querysave**: LotusScript procedure.

### Order Detail Profile
- **queryopen**: LotusScript procedure.
- **querysave**: LotusScript procedure.

### Order Detail
- **inputvalidation**: Validation error: "You must indicate a module number for this line item."
- **querysave**: LotusScript procedure.

### WebQuoteDetail
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### (PrintForm)
- **postopen**: LotusScript procedure.

### Web Order Select Detail
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### SelectDupeOrder
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### Web New Quote Header
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### NewInsertSpecs
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### Web New Order Header
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### OrderConfirmation
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### Web Lettered Insert Mod
- **webquerysave**: Invokes a shared macro/agent. Runs Domino @Command [ToolsRunMacro].

### $IPFormatForm
- **queryopen**: LotusScript procedure.

## Business Rules (top)

### BR-001: $DataDictionary: Both field lists must contain the same number of entries.
- **Source:** `form:$DataDictionary` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Both field lists must contain the same number of entries."

### BR-002: Order Detail: You must indicate a module number for this line item.
- **Source:** `form:Order Detail` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "You must indicate a module number for this line item."

### BR-003: Order Entry: Please enter the item prefix before saving.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the item prefix before saving."

### BR-004: Order Entry: Please enter the module number before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the module number before saving this item."

### BR-005: Order Entry: Please enter the quantity before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the quantity before saving this item."

### BR-006: Order Entry: Please enter the frame color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the frame color before saving this item."

### BR-007: Order Entry: Please enter the frame color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the frame color before saving this item."

### BR-008: Order Entry: Please enter the frame shape before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the frame shape before saving this item."

### BR-009: Order Entry: If this frame is ADA Compliant, you must enter the message.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "If this frame is ADA Compliant, you must enter the message."

### BR-010: Order Entry: Please enter the type of lettered strip before saving this i
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the type of lettered strip before saving this item."

### BR-011: Order Entry: Please enter the strip color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the strip color before saving this item."

### BR-012: Order Entry: Please enter the strip color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the strip color before saving this item."

### BR-013: Order Entry: Please enter the strip shape before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the strip shape before saving this item."

### BR-014: Order Entry: If this strip is ADA Compliant, you must enter the message.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "If this strip is ADA Compliant, you must enter the message."

### BR-015: Order Entry: Please enter the blank strip type before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the blank strip type before saving this item."

### BR-016: Order Entry: Please enter the blank strip color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the blank strip color before saving this item."

### BR-017: Order Entry: Please enter the blank strip color before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the blank strip color before saving this item."

### BR-018: Order Entry: Please enter the blank strip shape before saving this item.
- **Source:** `form:Order Entry` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "Please enter the blank strip shape before saving this item."

### BR-019: Order Header: You must select the correct status for this order.
- **Source:** `form:Order Header` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "You must select the correct status for this order."

### BR-020: Order Header: You must enter the date for this order.
- **Source:** `form:Order Header` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "You must enter the date for this order."

### BR-021: Order Header: The delivery date is blank.  Please enter a valid expected d
- **Source:** `form:Order Header` / `inputvalidation`
- **Type:** Validation
- **Summary:** Validation error: "The delivery date is blank.  Please enter a valid expected delivery date."

### BR-022: Order Detail — querysave
- **Source:** `form:Order Detail` / `querysave`
- **Type:** State Transition
- **Summary:** LotusScript procedure.

### BR-023: Order Detail Profile — querysave
- **Source:** `form:Order Detail Profile` / `querysave`
- **Type:** State Transition
- **Summary:** LotusScript procedure.

### BR-024: Order Entry — querysave
- **Source:** `form:Order Entry` / `querysave`
- **Type:** State Transition
- **Summary:** LotusScript procedure.

### BR-025: Order Header — querysave
- **Source:** `form:Order Header` / `querysave`
- **Type:** State Transition
- **Summary:** LotusScript procedure.

### BR-026: Web Duped Order Header — querysave
- **Source:** `form:Web Duped Order Header` / `querysave`
- **Type:** State Transition
- **Summary:** LotusScript procedure.

### BR-027:  Web Orders By Cust No. view selection
- **Source:** `view: Web Orders By Cust No.` / `selection`
- **Type:** View Selection
- **Summary:** Formula logic: SELECT (Form = "OEHeader" & @Left(OHOrdNo ; 3) = "WEB") | @IsResponseDoc

### BR-028: (AllDocs) view selection
- **Source:** `view:(AllDocs)` / `selection`
- **Type:** View Selection
- **Summary:** Formula logic: SELECT @All

### BR-029: (Debug View) view selection
- **Source:** `view:(Debug View)` / `selection`
- **Type:** View Selection
- **Summary:** Formula logic: SELECT Form = "WOHSelectOD"

### BR-030: (Details by Item Number) view selection
- **Source:** `view:(Details by Item Number)` / `selection`
- **Type:** View Selection
- **Summary:** Formula logic: SELECT Form = "OEDtl"

