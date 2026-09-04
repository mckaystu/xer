const GROUP_LEVEL = {
  form: 0,
  subform: 1,
  lookup_view: 2,
  view: 3,
  agent: 4,
  script_library: 5,
};

const NETWORK_GROUPS = {
  form: {
    color: {
      background: "#1e3a5f",
      border: "#4a90d9",
      highlight: { background: "#2a5080", border: "#7ab8ff" },
    },
    font: { color: "#e8eaed", size: 13, face: "system-ui, sans-serif" },
    shape: "box",
    margin: 12,
    borderWidth: 2,
    shapeProperties: { borderRadius: 6 },
  },
  subform: {
    color: {
      background: "#2d2450",
      border: "#9b7bd4",
      highlight: { background: "#3d3470", border: "#b89ef0" },
    },
    font: { color: "#e8eaed", size: 12 },
    shape: "box",
    margin: 10,
    borderWidth: 2,
    shapeProperties: { borderRadius: 6 },
  },
  lookup_view: {
    color: {
      background: "#3d3418",
      border: "#c9a227",
      highlight: { background: "#524820", border: "#e0bc40" },
    },
    font: { color: "#f5e6b8", size: 11 },
    shape: "diamond",
    margin: 14,
    borderWidth: 2,
    size: 22,
  },
  view: {
    color: {
      background: "#1e3d2f",
      border: "#6abf69",
      highlight: { background: "#2a5540", border: "#8ee08c" },
    },
    font: { color: "#e8eaed", size: 12 },
    shape: "box",
    margin: 10,
    borderWidth: 2,
    shapeProperties: { borderRadius: 6 },
  },
  agent: {
    color: {
      background: "#3d1e1e",
      border: "#c06060",
      highlight: { background: "#552828", border: "#e08080" },
    },
    font: { color: "#f0d0d0", size: 11 },
    shape: "ellipse",
    margin: 10,
    borderWidth: 2,
  },
  script_library: {
    color: {
      background: "#2a2a2a",
      border: "#888",
      highlight: { background: "#3a3a3a", border: "#aaa" },
    },
    font: { color: "#ccc", size: 11 },
    shape: "box",
    margin: 8,
    borderWidth: 1,
    shapeProperties: { borderRadius: 4 },
  },
};

const EDGE_COLORS = {
  LOOKUP_VIA_VIEW: "#c9a227",
  SELECTS_FORM: "#5b9fd4",
  ACCESSES_VIEW: "#6abf69",
  INCLUDES_SUBFORM: "#9b7bd4",
  USES_SCRIPT_LIBRARY: "#888",
  PARENT_CHILD_REF: "#c06060",
  INVOKES_AGENT: "#e07b39",
  REFERENCES_DATABASE: "#a0a0a0",
  CROSS_DATABASE_LOOKUP: "#d4a574",
};

const FOCUS_GROUPS = new Set(["form", "subform", "agent", "view", "lookup_view", "script_library"]);

let network = null;
let currentViz = null;
let currentSummary = null;
let currentAnalysis = null;
let currentCodeAudit = null;
let currentFunctionInventory = null;
let auditFindingFilter = "all"; // all | verified | false_positive | blind_spot
let fullGraph = null;
let activeView = "focus";
let focusNodeId = null;
let focusTargetId = null;

const graphSelect = document.getElementById("graphSelect");
const edgeFilter = document.getElementById("edgeFilter");
const focusSelect = document.getElementById("focusSelect");
const layoutDirection = document.getElementById("layoutDirection");
const aggregateEdges = document.getElementById("aggregateEdges");
const detailPanel = document.getElementById("detailPanel");
const refreshBtn = document.getElementById("refreshBtn");
const zoomInBtn = document.getElementById("zoomInBtn");
const zoomOutBtn = document.getElementById("zoomOutBtn");
const fitBtn = document.getElementById("fitBtn");
const graphPanel = document.getElementById("graphPanel");
const overviewPanel = document.getElementById("overviewPanel");
const overviewContent = document.getElementById("overviewContent");
const codeAnalysisPanel = document.getElementById("codeAnalysisPanel");
const codeAnalysisContent = document.getElementById("codeAnalysisContent");
const rulesPanel = document.getElementById("rulesPanel");
const rulesContent = document.getElementById("rulesContent");
const rulesSearch = document.getElementById("rulesSearch");
const rulesFormFilter = document.getElementById("rulesFormFilter");
const rulesValidationOnly = document.getElementById("rulesValidationOnly");
const rulesLookupsOnly = document.getElementById("rulesLookupsOnly");
const rulesCount = document.getElementById("rulesCount");
const matrixPanel = document.getElementById("matrixPanel");
const lookupMatrix = document.getElementById("lookupMatrix");
const matrixHideEmpty = document.getElementById("matrixHideEmpty");
const graphCaption = document.getElementById("graphCaption");
const legend = document.getElementById("legend");
const focusSelectLabel = document.getElementById("focusSelectLabel");
const edgeFilterLabel = document.getElementById("edgeFilterLabel");
const layoutLabel = document.getElementById("layoutLabel");
const aggregateLabel = document.getElementById("aggregateLabel");
const zoomControls = document.getElementById("zoomControls");
const viewTabs = document.querySelectorAll(".view-tabs .tab");
const dxlUpload = document.getElementById("dxlUpload");
const uploadStatus = document.getElementById("uploadStatus");

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function showError(msg) {
  detailPanel.innerHTML = `<p class="error">${msg}</p>`;
}

function truncateLabel(label, max = 32) {
  return label.length > max ? label.slice(0, max - 1) + "…" : label;
}

function nodeName(nodeId) {
  return nodeId.split(":").slice(1).join(":");
}

function isFormLike(nodeId) {
  return nodeId.startsWith("form:") || nodeId.startsWith("subform:");
}

function countEdgesForNode(nodeId) {
  if (!currentViz) return 0;
  return currentViz.edges.filter((e) => e.from === nodeId || e.to === nodeId).length;
}

function populateFocusSelect() {
  if (!currentViz) return;
  const candidates = currentViz.nodes
    .filter((n) => FOCUS_GROUPS.has(n.group))
    .sort((a, b) => countEdgesForNode(b.id) - countEdgesForNode(a.id));

  focusSelect.innerHTML = "";
  candidates.forEach((n) => {
    const opt = document.createElement("option");
    opt.value = n.id;
    const count = countEdgesForNode(n.id);
    opt.textContent = `${n.label} (${count})`;
    focusSelect.appendChild(opt);
  });

  if (!focusNodeId || !candidates.some((n) => n.id === focusNodeId)) {
    const preferred = candidates.find((n) => n.label === "Order Entry") || candidates[0];
    focusNodeId = preferred?.id || null;
  }
  if (focusNodeId) {
    focusSelect.value = focusNodeId;
  }
}

function syncEdgeFilterForGraph() {
  if (!currentViz || !edgeFilter) return;

  const counts = {};
  currentViz.edges.forEach((e) => {
    counts[e.type] = (counts[e.type] || 0) + 1;
  });

  const preferred = [
    "",
    "LOOKUP_VIA_VIEW",
    "SELECTS_FORM",
    "ACCESSES_VIEW",
    "INCLUDES_SUBFORM",
    "USES_SCRIPT_LIBRARY",
    "INVOKES_AGENT",
    "REFERENCES_DATABASE",
    "PARENT_CHILD_REF",
    "CROSS_DATABASE_LOOKUP",
  ];
  const present = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const options = [""];
  preferred.slice(1).forEach((t) => {
    if (counts[t]) options.push(t);
  });
  present.forEach((t) => {
    if (!options.includes(t)) options.push(t);
  });

  const previous = edgeFilter.value;
  edgeFilter.innerHTML = options
    .map((t) => {
      const label = t ? `${t} (${counts[t] || 0})` : `All types (${currentViz.edges.length})`;
      return `<option value="${t}">${label}</option>`;
    })
    .join("");

  // Keep prior filter only if this graph actually has those edges
  if (previous && counts[previous]) {
    edgeFilter.value = previous;
  } else if (previous && !counts[previous]) {
    edgeFilter.value = "";
  } else {
    edgeFilter.value = "";
  }
}

function getFilteredEdges() {
  if (!currentViz) return [];
  const typeFilter = edgeFilter.value;

  if (activeView === "focus" && focusNodeId) {
    let edges = currentViz.edges.filter((e) => e.from === focusNodeId || e.to === focusNodeId);
    if (typeFilter) edges = edges.filter((e) => e.type === typeFilter);
    if (focusTargetId) {
      edges = edges.filter((e) => e.from === focusTargetId || e.to === focusTargetId);
    }
    return edges;
  }

  let edges = typeFilter ? currentViz.edges.filter((e) => e.type === typeFilter) : currentViz.edges;
  return edges;
}

function aggregateEdgeList(edges) {
  if (!aggregateEdges.checked) return edges.map((e) => ({ ...e, count: 1 }));

  const map = new Map();
  edges.forEach((e) => {
    const key = `${e.from}|${e.to}|${e.type}`;
    if (!map.has(key)) {
      map.set(key, { ...e, count: 1, titles: e.title ? [e.title] : [] });
    } else {
      const agg = map.get(key);
      agg.count += 1;
      if (e.title) agg.titles.push(e.title);
    }
  });
  return Array.from(map.values());
}

function nodeLevel(group, filter, isFocus) {
  if (isFocus || filter === "LOOKUP_VIA_VIEW") {
    if (group === "form" || group === "subform" || group === "agent") return 0;
    if (group === "lookup_view") return 1;
    if (group === "view") return 2;
    if (group === "script_library") return 3;
  }
  return GROUP_LEVEL[group] ?? 3;
}

function buildNetwork() {
  if (!currentViz || activeView === "matrix") return;

  const container = document.getElementById("network");
  const filter = edgeFilter.value;
  const direction = layoutDirection.value;
  const isHorizontal = direction === "LR";
  const isFocus = activeView === "focus";

  const rawEdges = getFilteredEdges();
  const edges = aggregateEdgeList(rawEdges);

  const connected = new Set();
  if (isFocus && focusNodeId) connected.add(focusNodeId);
  edges.forEach((e) => {
    connected.add(e.from);
    connected.add(e.to);
  });

  let visibleNodes;
  if (isFocus) {
    visibleNodes = currentViz.nodes.filter((n) => connected.has(n.id));
  } else {
    visibleNodes = currentViz.nodes.filter((n) => !filter || connected.has(n.id));
  }

  const nodes = new vis.DataSet(
    visibleNodes.map((n) => ({
      id: n.id,
      label: truncateLabel(n.label),
      title: `${n.label}\nType: ${n.group}\nFields: ${n.fieldCount || 0}`,
      group: n.group,
      level: nodeLevel(n.group, filter, isFocus),
      widthConstraint: { minimum: 90, maximum: 200 },
      borderWidth: n.id === focusNodeId ? 3 : 2,
    }))
  );

  const edgeData = new vis.DataSet(
    edges
      .filter((e) => nodes.get(e.from) && nodes.get(e.to))
      .map((e, i) => {
        const label = e.count > 1 ? `×${e.count}` : isFocus || filter ? "" : truncateLabel(e.type.replace(/_/g, " "), 14);
        const tooltip =
          e.count > 1
            ? `${e.type} (${e.count} references)\n${(e.titles || []).slice(0, 3).join("\n")}`
            : e.title || e.type;
        return {
          id: i,
          from: e.from,
          to: e.to,
          label,
          title: tooltip,
          arrows: { to: { enabled: true, scaleFactor: 0.6 } },
          color: {
            color: EDGE_COLORS[e.type] || "#5b9fd4",
            highlight: "#ffffff",
            opacity: 0.85,
          },
          width: Math.min(1 + (e.count || 1) * 0.3, 4),
          dashes: e.type === "LOOKUP_VIA_VIEW" ? [6, 4] : false,
        };
      })
  );

  const data = { nodes, edges: edgeData };
  const options = {
    groups: NETWORK_GROUPS,
    layout: {
      hierarchical: {
        enabled: true,
        direction,
        sortMethod: "directed",
        levelSeparation: isHorizontal ? 280 : 160,
        nodeSpacing: isHorizontal ? 90 : 120,
        treeSpacing: isHorizontal ? 100 : 180,
        blockShifting: true,
        edgeMinimization: true,
        parentCentralization: true,
        shakeTowards: isHorizontal ? "roots" : "leaves",
      },
    },
    physics: { enabled: false },
    interaction: {
      hover: true,
      tooltipDelay: 80,
      zoomView: true,
      dragView: true,
      dragNodes: false,
    },
    edges: {
      font: { size: 10, color: "#e8eaed", strokeWidth: 0, align: "middle" },
      smooth: {
        enabled: true,
        type: isHorizontal ? "horizontal" : "vertical",
        forceDirection: isHorizontal ? "horizontal" : "vertical",
        roundness: 0.15,
      },
    },
    nodes: {
      chosen: {
        node(values) {
          values.borderWidth = 4;
        },
      },
    },
  };

  if (network) network.destroy();
  network = new vis.Network(container, data, options);

  // Empty-state hint when filter matches nothing
  let emptyHint = container.querySelector(".graph-empty-hint");
  if (!emptyHint) {
    emptyHint = document.createElement("div");
    emptyHint.className = "graph-empty-hint";
    container.appendChild(emptyHint);
  }
  if (nodes.length === 0) {
    const filterLabel = filter || "All types";
    emptyHint.textContent =
      `No relationships match “${filterLabel}” for this graph. ` +
      `Try “All types” or another relationship in the dropdown.`;
    emptyHint.classList.remove("hidden");
  } else {
    emptyHint.classList.add("hidden");
  }

  network.once("afterDrawing", () => {
    network.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
  });
  network.on("click", (params) => {
    if (params.nodes.length) {
      showNodeDetail(params.nodes[0]);
    }
  });

  updateCaption();
}

function updateCaption() {
  if (activeView === "focus" && focusNodeId) {
    const name = nodeName(focusNodeId);
    const edgeCount = getFilteredEdges().length;
    const aggCount = aggregateEdgeList(getFilteredEdges()).length;
    const suffix = focusTargetId ? ` → ${nodeName(focusTargetId)}` : "";
    graphCaption.textContent = `Focus: ${name}${suffix} · ${edgeCount} refs · ${aggCount} edges shown`;
  } else if (activeView === "graph") {
    const filter = edgeFilter.value;
    const edgeCount = getFilteredEdges().length;
    if (!edgeCount && filter) {
      graphCaption.textContent = `No “${filter}” edges in this graph — switch Relationships to All types`;
    } else {
      graphCaption.textContent = `Full graph · ${edgeCount} edges shown · use filters to reduce noise`;
    }
  }
}

function buildLookupMatrix() {
  if (!currentViz) return;

  const lookupEdges = currentViz.edges.filter((e) => e.type === "LOOKUP_VIA_VIEW");
  const rowTotals = new Map();
  const colTotals = new Map();
  const cells = new Map();

  lookupEdges.forEach((e) => {
    let formId = isFormLike(e.from) ? e.from : isFormLike(e.to) ? e.to : null;
    let viewId = e.from.startsWith("view:") ? e.from : e.to.startsWith("view:") ? e.to : null;
    if (!formId || !viewId) return;

    const key = `${formId}|${viewId}`;
    cells.set(key, (cells.get(key) || 0) + 1);
    rowTotals.set(formId, (rowTotals.get(formId) || 0) + 1);
    colTotals.set(viewId, (colTotals.get(viewId) || 0) + 1);
  });

  let rows = [...rowTotals.entries()].sort((a, b) => b[1] - a[1]);
  let cols = [...colTotals.entries()].sort((a, b) => b[1] - a[1]);

  if (matrixHideEmpty.checked) {
    rows = rows.filter(([, total]) => total > 0);
    cols = cols.filter(([, total]) => total > 0);
  }

  const maxCell = Math.max(1, ...cells.values());

  let html = "<thead><tr><th class='corner'>Form ↓ / Lookup view →</th>";
  cols.forEach(([viewId, total]) => {
    html += `<th class="col-header" title="${nodeName(viewId)} (${total})">${truncateLabel(nodeName(viewId), 18)}</th>`;
  });
  html += "<th class='row-total'>Total</th></tr></thead><tbody>";

  rows.forEach(([formId, rowTotal]) => {
    html += `<tr><th class="row-header" data-form="${formId}" title="${nodeName(formId)}">${truncateLabel(nodeName(formId), 24)}</th>`;
    cols.forEach(([viewId]) => {
      const count = cells.get(`${formId}|${viewId}`) || 0;
      const intensity = count ? Math.ceil((count / maxCell) * 4) : 0;
      html += `<td class="heat-${intensity}${count ? " clickable" : ""}" data-form="${formId}" data-view="${viewId}" title="${count ? count + " @DbLookup refs" : ""}">${count || ""}</td>`;
    });
    html += `<td class="row-total">${rowTotal}</td></tr>`;
  });

  html += "</tbody>";
  lookupMatrix.innerHTML = html;

  lookupMatrix.querySelectorAll("td.clickable").forEach((td) => {
    td.addEventListener("click", () => {
      focusNodeId = td.dataset.form;
      focusTargetId = td.dataset.view;
      edgeFilter.value = "LOOKUP_VIA_VIEW";
      setActiveView("focus");
    });
  });

  lookupMatrix.querySelectorAll("th.row-header").forEach((th) => {
    th.addEventListener("click", () => {
      focusNodeId = th.dataset.form;
      focusTargetId = null;
      edgeFilter.value = "LOOKUP_VIA_VIEW";
      setActiveView("focus");
    });
  });
}

function scoreRiskClass(rating) {
  if (!rating) return "risk-unknown";
  if (rating.startsWith("Low")) return "risk-low";
  if (rating.startsWith("Moderate")) return "risk-moderate";
  return "risk-high";
}

function renderModernizationCard(scoreObj) {
  if (!scoreObj) {
    return `<section class="overview-section"><h2>Modernization Readiness</h2><p class="placeholder">Score not available yet.</p></section>`;
  }
  const m = scoreObj.metrics || {};
  const coupling = m.coupling || {};
  const cross = m.cross_db || {};
  const hard = m.hardcoded || {};
  const orphans = m.orphans || {};
  const riskClass = scoreRiskClass(scoreObj.risk_rating);
  const pct = (ratio) => Math.round((ratio || 0) * 100);

  return `
    <section class="overview-section score-section">
      <h2>Modernization Readiness</h2>
      <div class="score-card ${riskClass}">
        <div class="score-main">
          <div class="score-ring" data-score="${scoreObj.score}">
            <span class="score-value">${scoreObj.score}</span>
            <span class="score-max">/ 100</span>
          </div>
          <div class="score-copy">
            <p class="score-rating">${escapeHtml(scoreObj.risk_rating || "")}</p>
            <p class="score-hint">Higher = more modernization effort (coupling, cross-DB, hardcoded refs, orphans).</p>
          </div>
        </div>
        <div class="score-metrics">
          <div class="metric">
            <div class="metric-head"><span>Max Coupling</span><strong>${coupling.max_degree ?? "—"} deg</strong></div>
            <div class="metric-bar"><i style="width:${pct(coupling.ratio)}%"></i></div>
            <p class="metric-sub">${escapeHtml(coupling.max_degree_node || "—")}</p>
          </div>
          <div class="metric">
            <div class="metric-head"><span>Cross-DB Links</span><strong>${cross.cross_db_edges ?? 0} / ${cross.total_edges ?? 0}</strong></div>
            <div class="metric-bar"><i style="width:${pct(cross.ratio)}%"></i></div>
          </div>
          <div class="metric">
            <div class="metric-head"><span>Hardcoded Refs</span><strong>${hard.count ?? 0}</strong></div>
            <div class="metric-bar"><i style="width:${pct(hard.ratio)}%"></i></div>
          </div>
          <div class="metric">
            <div class="metric-head"><span>Orphaned Artifacts</span><strong>${orphans.count ?? 0}</strong></div>
            <div class="metric-bar"><i style="width:${pct(orphans.ratio)}%"></i></div>
          </div>
        </div>
      </div>
    </section>
  `;
}

function flattenRulesRows(catalog) {
  const rows = [];
  for (const form of catalog?.forms || []) {
    for (const field of form.fields || []) {
      const validation = field.input_validation?.formula || "";
      const failures = (field.input_validation?.failure_messages || []).join("; ");
      const lookups = field.lookups || [];
      const lookupText = lookups
        .map((l) => [l.function, l.target_database, l.target_view, l.lookup_key].filter(Boolean).join(" "))
        .join(" | ");
      rows.push({
        form: form.form,
        element_type: form.element_type,
        database_id: form.database_id,
        field: field.name,
        label: field.label || field.name,
        data_type: field.data_type,
        kind: field.kind || "",
        business_summary: field.business_summary || "",
        default_value: field.default_value || "",
        default_summary: field.default_summary || "",
        validation,
        validation_summary: field.input_validation?.summary || "",
        failures,
        translation: field.input_translation || "",
        hide_when: field.hide_when || "",
        hide_summary: field.hide_summary || "",
        lookups,
        lookupText,
        lookup_summary: field.lookup_summary || "",
        hasValidation: Boolean(validation),
        hasLookup: lookups.length > 0,
      });
    }
  }
  return rows;
}

function renderBizCell(summary, formula, extraHtml = "") {
  if (!summary && !formula) return "—";
  const summaryHtml = summary ? `<p class="biz-summary">${escapeHtml(summary)}</p>` : "";
  const formulaHtml = formula
    ? `<details class="formula-details"><summary>Show formula</summary><pre>${escapeHtml(formula)}</pre></details>`
    : "";
  return `${summaryHtml}${extraHtml}${formulaHtml}` || "—";
}

function populateRulesFormFilter(catalog) {
  if (!rulesFormFilter) return;
  const current = rulesFormFilter.value;
  const names = (catalog?.forms || []).map((f) => f.form);
  rulesFormFilter.innerHTML =
    `<option value="">All forms</option>` +
    names.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join("");
  if (names.includes(current)) rulesFormFilter.value = current;
}

function renderRulesCatalog() {
  if (!rulesContent) return;
  const catalog = currentAnalysis?.business_rules;
  if (!catalog) {
    rulesContent.innerHTML = `<p class="placeholder">No business rules catalog available.</p>`;
    return;
  }

  populateRulesFormFilter(catalog);
  const q = (rulesSearch?.value || "").trim().toLowerCase();
  const formFilter = rulesFormFilter?.value || "";
  const validationOnly = Boolean(rulesValidationOnly?.checked);
  const lookupsOnly = Boolean(rulesLookupsOnly?.checked);

  let rows = flattenRulesRows(catalog);
  rows = rows.filter((r) => {
    if (formFilter && r.form !== formFilter) return false;
    if (validationOnly && !r.hasValidation) return false;
    if (lookupsOnly && !r.hasLookup) return false;
    if (!q) return true;
    const hay = [
      r.form,
      r.field,
      r.label,
      r.data_type,
      r.business_summary,
      r.default_value,
      r.default_summary,
      r.validation,
      r.validation_summary,
      r.failures,
      r.translation,
      r.hide_when,
      r.hide_summary,
      r.lookupText,
      r.lookup_summary,
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });

  if (rulesCount) {
    rulesCount.textContent = `${rows.length} fields · ${catalog.totals?.fields_with_validation || 0} validations · ${catalog.totals?.lookups || 0} lookups`;
  }

  if (!rows.length) {
    rulesContent.innerHTML = `<p class="placeholder">No fields match the current filters.</p>`;
    return;
  }

  const byForm = new Map();
  for (const row of rows) {
    if (!byForm.has(row.form)) byForm.set(row.form, []);
    byForm.get(row.form).push(row);
  }

  const sections = [...byForm.entries()]
    .map(([formName, formRows]) => {
      const body = formRows
        .map((r) => {
          const lookupHtml = (r.lookups || [])
            .map(
              (l) =>
                `<li><code>${escapeHtml(l.function || "")}</code> → <strong>${escapeHtml(l.target_view || "—")}</strong>${
                  l.target_database ? ` <span class="muted">(${escapeHtml(l.target_database)})</span>` : ""
                }${l.lookup_key ? ` key=<code>${escapeHtml(String(l.lookup_key))}</code>` : ""}</li>`
            )
            .join("");
          const lookupCell = r.lookup_summary
            ? `<p class="biz-summary">${escapeHtml(r.lookup_summary)}</p>${lookupHtml ? `<ul class="lookup-mini">${lookupHtml}</ul>` : ""}`
            : lookupHtml
              ? `<ul class="lookup-mini">${lookupHtml}</ul>`
              : "—";
          return `<tr>
            <td>
              <div class="field-label">${escapeHtml(r.label || r.field)}</div>
              <code class="field-tech">${escapeHtml(r.field)}</code>
              <div class="field-meta">${escapeHtml(r.data_type)}${r.kind ? ` · ${escapeHtml(r.kind)}` : ""}</div>
            </td>
            <td class="formula-cell">${renderBizCell(r.business_summary || r.default_summary, r.default_value)}</td>
            <td class="formula-cell">${renderBizCell(
              r.validation_summary,
              r.validation,
              r.failures ? `<p class="failure-msg">${escapeHtml(r.failures)}</p>` : ""
            )}</td>
            <td class="formula-cell">${renderBizCell(r.hide_summary, r.hide_when)}</td>
            <td class="formula-cell">${lookupCell}</td>
          </tr>`;
        })
        .join("");
      return `<details class="rules-group" open>
        <summary><strong>${escapeHtml(formName)}</strong> <span class="muted">${formRows.length} fields</span></summary>
        <table class="rules-table">
          <thead><tr><th>Field</th><th>What it does</th><th>Validation</th><th>When hidden</th><th>Data dependencies</th></tr></thead>
          <tbody>${body}</tbody>
        </table>
      </details>`;
    })
    .join("");

  rulesContent.innerHTML = sections;
}

function inventoryStatusClass(status) {
  if (status === "UNPROTECTED_ALLOCATION") return "status-unprotected";
  if (status === "PROTECTED") return "status-protected";
  return "status-safe";
}

function inventoryStatusLabel(status) {
  if (status === "UNPROTECTED_ALLOCATION") return "Unprotected";
  if (status === "PROTECTED") return "Protected";
  return "Safe (no handles)";
}

function coverageRiskClass(rate) {
  if (rate < 40) return "risk-high";
  if (rate < 75) return "risk-moderate";
  return "risk-low";
}

function renderFunctionInventoryCard(inventory) {
  if (!inventory?.summary) {
    return `<section class="overview-section"><h2>Function &amp; Recycle Inventory</h2><p class="placeholder">Inventory not available for this graph.</p></section>`;
  }
  const s = inventory.summary;
  const scanned = s.total_functions_scanned || 0;
  const allocating = s.functions_allocating_handles || 0;
  const withCleanup = s.functions_with_cleanup || 0;
  const unprotected = s.unprotected_functions || 0;
  const safeNoHandles =
    typeof s.functions_safe_no_handles === "number"
      ? s.functions_safe_no_handles
      : Math.max(0, scanned - allocating);
  // Primary ring: overall handle safety (safe + protected) / scanned
  const safetyRate =
    typeof s.handle_safety_rate === "number"
      ? s.handle_safety_rate
      : scanned
        ? Math.round(((safeNoHandles + withCleanup) / scanned) * 1000) / 10
        : 100;
  // Secondary: cleanup only among allocators
  const recycleAmongAllocators =
    typeof s.recycle_coverage_rate === "number"
      ? s.recycle_coverage_rate
      : allocating
        ? Math.round((withCleanup / allocating) * 1000) / 10
        : 100;
  const riskClass = coverageRiskClass(safetyRate);
  const rows = (inventory.inventory || [])
    .map(
      (f, idx) =>
        `<tr class="inventory-row ${inventoryStatusClass(f.status)}" data-inventory-idx="${idx}" role="button" tabindex="0">
          <td><code>${escapeHtml(f.id)}</code></td>
          <td><code>${escapeHtml(f.function_name)}</code></td>
          <td>${escapeHtml(f.design_element)}</td>
          <td>${escapeHtml(f.language)}</td>
          <td>${f.allocates_handles ? "Yes" : "No"}</td>
          <td>${f.recycle_call_count}</td>
          <td><span class="status-pill ${inventoryStatusClass(f.status)}">${escapeHtml(inventoryStatusLabel(f.status))}</span></td>
          <td>${f.loc}</td>
        </tr>`
    )
    .join("");

  const rateExplainer = `
    <div class="coverage-explainer">
      <p>
        <strong>Handle safety ${safetyRate}%</strong> =
        (<strong>${safeNoHandles}</strong> safe with no handles
        + <strong>${withCleanup}</strong> allocate-and-cleanup)
        ÷ <strong>${scanned}</strong> scanned
        × 100.
      </p>
      <p class="coverage-sub">
        Of the <strong>${allocating}</strong> functions that actually allocate Domino handles,
        <strong>${withCleanup}</strong> clean up (<strong>${recycleAmongAllocators}%</strong> recycle coverage)
        and <strong>${unprotected}</strong> are unprotected.
        ${
          unprotected > 0
            ? ` Open an <strong>Unprotected</strong> row below to see the missing <code>Delete</code> / <code>.recycle()</code>.`
            : ""
        }
      </p>
    </div>`;

  return `
    <section class="overview-section score-section" id="functionInventorySection">
      <h2>Function &amp; Recycle Inventory</h2>
      <div class="score-card ${riskClass}">
        <div class="score-main">
          <div class="score-ring" aria-label="Handle safety rate">
            <span class="score-value">${safetyRate}</span>
            <span class="score-max">%</span>
          </div>
          <div class="score-copy">
            <p class="score-rating">Handle Safety Rate</p>
            <p class="score-hint">
              Share of <em>all</em> scanned functions that are either handle-free or that allocate
              and also call <code>Delete</code> / <code>.recycle()</code>.
            </p>
            <div class="score-metrics inventory-metrics">
              <div class="metric"><span class="metric-label">Functions scanned</span><strong>${scanned}</strong></div>
              <div class="metric"><span class="metric-label">Safe (no handles)</span><strong>${safeNoHandles}</strong></div>
              <div class="metric"><span class="metric-label">Allocate handles</span><strong>${allocating}</strong></div>
              <div class="metric"><span class="metric-label">With cleanup</span><strong>${withCleanup}</strong></div>
              <div class="metric"><span class="metric-label">Unprotected</span><strong>${unprotected}</strong></div>
              <div class="metric"><span class="metric-label">Recycle among allocators</span><strong>${recycleAmongAllocators}%</strong></div>
            </div>
          </div>
        </div>
        ${rateExplainer}
        <p class="score-hint coverage-hint">Click a table row for As-Is / To-Be deep-dive with the allocation line highlighted.</p>
        ${
          rows
            ? `<table class="overview-table inventory-table"><thead><tr><th>ID</th><th>Function</th><th>Design element</th><th>Lang</th><th>Allocates</th><th>Recycles</th><th>Status</th><th>LOC</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<p class="placeholder">No functions extracted from stored script blocks.</p>`
        }
        <div id="inventoryDeepDive" class="audit-deep-dive hidden"></div>
      </div>
    </section>
  `;
}

function renderInventoryDeepDive(fn) {
  if (!fn) return "";
  const status = fn.status || "";
  const statusLabel = inventoryStatusLabel(status);
  const lang = fn.language_label || fn.language || "";
  const hitLine = fn.highlight_line || fn.start_line || 1;
  const lineRange =
    fn.line_number_start && fn.line_number_end
      ? `L${fn.line_number_start}–${fn.line_number_end}`
      : `L${fn.start_line || hitLine}`;
  const problem = fn.problem_breakdown || "";
  const guide = fn.remediation_guide || "";
  const warning = fn.handle_lifecycle_warning || "";
  const toBe = fn.code_snippet_to_be || "";
  const severity =
    status === "UNPROTECTED_ALLOCATION" ? "CRITICAL" : status === "PROTECTED" ? "LOW" : "MEDIUM";

  return `
    <div class="deep-dive-header">
      <div>
        <h3>${escapeHtml(fn.id)} · ${escapeHtml(fn.function_name)} — ${escapeHtml(statusLabel)}</h3>
        <p class="score-hint">
          <span class="status-pill ${inventoryStatusClass(status)}">${escapeHtml(statusLabel)}</span>
          · <span class="sev-pill sev-${severity}">${severity}</span>
          · ${escapeHtml(lang)} · ${escapeHtml(fn.design_element || "")} · ${escapeHtml(lineRange)}
          · hit <strong>L${escapeHtml(String(hitLine))}</strong>
          · recycles: ${fn.recycle_call_count ?? 0} · LOC ${fn.loc ?? "—"}
        </p>
      </div>
      <button type="button" class="deep-dive-close" id="inventoryDeepDiveClose">Close</button>
    </div>

    <div class="deep-dive-guides">
      <div class="guide-card problem">
        <h4>Problem Breakdown</h4>
        <p>${escapeHtml(problem)}</p>
      </div>
      <div class="guide-card fix">
        <h4>Remediation Guide</h4>
        <p>${escapeHtml(guide)}</p>
      </div>
    </div>

    ${warning ? `<p class="lifecycle-warning">${escapeHtml(warning)}</p>` : ""}

    <div class="diff-grid">
      <div class="diff-pane">
        <div class="diff-label as-is">As-Is · highlight = L${escapeHtml(String(hitLine))}</div>
        ${renderAsIsSnippet(fn)}
      </div>
      <div class="diff-pane">
        <div class="diff-label to-be">To-Be (${escapeHtml(lang || "safe cleanup")})</div>
        <pre class="diff-code">${escapeHtml(toBe)}</pre>
      </div>
    </div>
  `;
}

function wireInventoryDeepDive() {
  const section = document.getElementById("functionInventorySection");
  const dive = document.getElementById("inventoryDeepDive");
  if (!section || !dive || !currentFunctionInventory?.inventory?.length) return;

  const openFn = (idx) => {
    const fn = currentFunctionInventory.inventory[idx];
    if (!fn) return;
    dive.innerHTML = renderInventoryDeepDive(fn);
    dive.classList.remove("hidden");
    document.getElementById("inventoryDeepDiveClose")?.addEventListener("click", () => {
      dive.classList.add("hidden");
      dive.innerHTML = "";
    });
    dive.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };

  section.querySelectorAll(".inventory-row").forEach((row) => {
    const handler = () => openFn(Number(row.dataset.inventoryIdx));
    row.addEventListener("click", handler);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handler();
      }
    });
  });
}

function findingFilterBucket(f) {
  if (f.is_blind_spot || f.ai_validation_status === "BLIND_SPOT" || f.rule_id === "DOM-BS-001") {
    return "blind_spot";
  }
  if (f.is_false_positive || f.ai_validation_status === "FALSE_POSITIVE") {
    return "false_positive";
  }
  if (f.ai_validation_status === "VERIFIED") {
    return "verified";
  }
  return "all";
}

function filterAuditFindings(findings, filter) {
  const list = findings || [];
  if (filter === "all") return list.map((f, idx) => ({ f, idx }));
  return list
    .map((f, idx) => ({ f, idx }))
    .filter(({ f }) => {
      const bucket = findingFilterBucket(f);
      if (filter === "verified") return bucket === "verified";
      if (filter === "false_positive") return bucket === "false_positive";
      if (filter === "blind_spot") return bucket === "blind_spot";
      return true;
    });
}

function aiValidationBanner(finding) {
  const status = finding.ai_validation_status || "";
  const reasoning = finding.ai_validation_reasoning || "";
  if (!status && !reasoning) return "";
  let title = "AI Validation Note";
  let cls = "ai-note";
  if (status === "FALSE_POSITIVE" || finding.is_false_positive) {
    title = "AI Validation Note — Flagged False Positive";
    cls += " ai-note-fp";
  } else if (status === "BLIND_SPOT" || finding.is_blind_spot) {
    title = "AI Validation Note — Blind Spot Discovered";
    cls += " ai-note-blind";
  } else if (status === "VERIFIED") {
    title = "AI Validation Note — Verified Leak";
    cls += " ai-note-verified";
  }
  return `
    <div class="${cls}" role="status">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(reasoning || "AI discrepancy audit reviewed this finding.")}</p>
    </div>
  `;
}

function renderCodeAuditCard(audit) {
  if (!audit) {
    return `<section class="overview-section"><h2>Code Quality Review</h2><p class="placeholder">Audit not available for this graph.</p></section>`;
  }
  const counts = audit.severity_counts || {};
  const risk = audit.handle_exhaustion_risk || "LOW";
  const riskClass =
    risk === "CRITICAL" || risk === "HIGH" ? "risk-high" : risk === "MEDIUM" ? "risk-moderate" : "risk-low";
  const findings = audit.findings || [];
  const aiSum = audit.ai_discrepancy_summary || {};
  const filtered = filterAuditFindings(findings, auditFindingFilter);
  const rows = filtered
    .map(({ f, idx }) => {
      const bucket = findingFilterBucket(f);
      const badges = [];
      if (bucket === "blind_spot") badges.push(`<span class="ai-badge ai-badge-blind">Blind Spot</span>`);
      else if (bucket === "false_positive") badges.push(`<span class="ai-badge ai-badge-fp">False Positive</span>`);
      else if (bucket === "verified") badges.push(`<span class="ai-badge ai-badge-verified">AI Verified</span>`);
      return `<tr class="audit-row" data-finding-idx="${idx}" data-filter-bucket="${bucket}" role="button" tabindex="0">
          <td><code>${escapeHtml(f.finding_id || f.id)}</code></td>
          <td><span class="sev-pill sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td><code>${escapeHtml(f.rule_id)}</code> ${escapeHtml(f.issue || f.title)} ${badges.join(" ")}</td>
          <td>${escapeHtml(f.language_label || f.language || "")}</td>
          <td>${escapeHtml(f.location || `${f.element_type}:${f.element_name} L${f.line}`)}</td>
          <td>${typeof f.confidence === "number" && f.confidence <= 1 ? Math.round(f.confidence * 100) : f.confidence}%</td>
        </tr>`;
    })
    .join("");

  const filterBtn = (id, label, count) => {
    const active = auditFindingFilter === id ? "active" : "";
    const countHtml = typeof count === "number" ? ` <span class="filter-count">${count}</span>` : "";
    return `<button type="button" class="findings-filter ${active}" data-findings-filter="${id}">${label}${countHtml}</button>`;
  };

  const verifiedCount =
    typeof aiSum.ai_verified === "number"
      ? aiSum.ai_verified
      : findings.filter((f) => findingFilterBucket(f) === "verified").length;
  const fpCount =
    typeof aiSum.false_positives === "number"
      ? aiSum.false_positives
      : findings.filter((f) => findingFilterBucket(f) === "false_positive").length;
  const blindCount =
    typeof aiSum.blind_spots === "number"
      ? aiSum.blind_spots
      : findings.filter((f) => findingFilterBucket(f) === "blind_spot").length;

  return `
    <section class="overview-section score-section" id="codeAuditSection">
      <h2>Handle &amp; Memory Findings</h2>
      <div class="score-card ${riskClass}">
        <div class="score-copy" style="margin-bottom:12px">
          <p class="score-rating">Handle Exhaustion Risk: ${escapeHtml(risk)}</p>
          <p class="score-hint">${findings.length} findings ·
            C:${counts.CRITICAL || 0} H:${counts.HIGH || 0} M:${counts.MEDIUM || 0} L:${counts.LOW || 0}
            · scanned ${audit.blocks_prefiltered || 0}/${audit.blocks_scanned || 0} code blocks
            · ${audit.llm_enabled ? "AI discrepancy on" : "rules-only"}
            · click a row for As-Is / To-Be deep-dive</p>
          <div class="findings-filter-bar" role="toolbar" aria-label="Findings filters">
            ${filterBtn("all", "All Findings", findings.length)}
            ${filterBtn("verified", "AI Verified", verifiedCount)}
            ${filterBtn("false_positive", "Flagged False Positives", fpCount)}
            ${filterBtn("blind_spot", "AI Discovered Blind Spots", blindCount)}
          </div>
          <div class="ai-actions">
            <button type="button" class="ai-run-btn" id="runAiValidationBtn" ${
              audit.llm_enabled ? "disabled" : ""
            }>${audit.llm_enabled ? "AI Validation Complete" : "Run AI Discrepancy Audit"}</button>
            <span class="score-hint" id="aiValidationStatus">${
              audit.llm_enabled
                ? `Verified ${verifiedCount} · FP ${fpCount} · Blind spots ${blindCount}`
                : "Uses OpenAI to filter false positives and find blind-spot leaks (requires API key on server)."
            }</span>
          </div>
        </div>
        ${
          rows
            ? `<table class="overview-table audit-table"><thead><tr><th>ID</th><th>Sev</th><th>Issue</th><th>Lang</th><th>Location</th><th>Conf</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<p class="placeholder">${
                findings.length
                  ? "No findings match this filter."
                  : "No handle-leak / memory anti-patterns detected in stored script blocks."
              }</p>`
        }
        <div id="auditDeepDive" class="audit-deep-dive hidden"></div>
      </div>
    </section>
  `;
}

function renderCodeAuditTeaser(audit, inventory) {
  if (!audit && !inventory?.summary) {
    return `<section class="overview-section"><h2>Code Quality</h2><p class="placeholder">No code audit yet.</p></section>`;
  }
  const counts = audit?.severity_counts || {};
  const risk = audit?.handle_exhaustion_risk || "LOW";
  const rate = inventory?.summary?.handle_safety_rate ?? inventory?.summary?.recycle_coverage_rate;
  const riskClass =
    risk === "CRITICAL" || risk === "HIGH" || (typeof rate === "number" && rate < 40)
      ? "risk-high"
      : risk === "MEDIUM" || (typeof rate === "number" && rate < 75)
        ? "risk-moderate"
        : "risk-low";
  const n = audit?.findings?.length || 0;
  const unprot = inventory?.summary?.unprotected_functions;
  return `
    <section class="overview-section score-section">
      <h2>Code Quality (summary)</h2>
      <div class="score-card ${riskClass}">
        <div class="score-copy">
          <p class="score-rating">Handle Exhaustion Risk: ${escapeHtml(risk)}</p>
          <p class="score-hint">${n} findings · C:${counts.CRITICAL || 0} H:${counts.HIGH || 0} M:${counts.MEDIUM || 0} L:${counts.LOW || 0}${
            typeof rate === "number"
              ? ` · recycle coverage ${rate}% (${unprot || 0} unprotected)`
              : ""
          }</p>
          <p class="overview-sub"><a href="#" id="openCodeTab">Open Code Analysis for inventory &amp; deep-dive →</a></p>
        </div>
      </div>
    </section>
  `;
}

function renderCodeAnalysis() {
  if (!codeAnalysisContent) return;
  if (!currentCodeAudit && !currentFunctionInventory) {
    codeAnalysisContent.innerHTML = `<div class="overview-header"><h2>Code Analysis</h2><p class="overview-sub">Static review of Domino handle leaks, recycle coverage, and remediation templates.</p></div><p class="placeholder">Loading code quality audit…</p>`;
    if (graphSelect.value) loadSummary(graphSelect.value);
    return;
  }
  codeAnalysisContent.innerHTML = `
    <div class="overview-header">
      <h2>Code Analysis</h2>
      <p class="overview-sub">Function inventory with recycle coverage, plus C-API handle findings — click a finding for As-Is / To-Be remediation. Optionally run AI discrepancy audit for false positives and blind spots.</p>
    </div>
    ${renderFunctionInventoryCard(currentFunctionInventory)}
    ${renderCodeAuditCard(currentCodeAudit)}
  `;
  wireInventoryDeepDive();
  wireCodeAuditDeepDive();
  wireAuditFindingFilters();
  wireAiValidationButton();
}

function renderAsIsSnippet(finding) {
  const lines = finding.code_snippet_lines;
  if (Array.isArray(lines) && lines.length) {
    return `<div class="diff-code snippet-lines" role="region" aria-label="As-Is code">${lines
      .map((row) => {
        const cls = row.highlight ? "snippet-line is-highlight" : "snippet-line";
        return `<div class="${cls}"><span class="snippet-ln">${row.line}</span><span class="snippet-tx">${escapeHtml(row.text || "")}</span></div>`;
      })
      .join("")}</div>`;
  }
  // Fallback: plain text with ▶ marker styling via CSS on containing pre
  const asIs = finding.code_snippet_as_is || finding.evidence || "";
  return `<pre class="diff-code">${escapeHtml(asIs)}</pre>`;
}

function renderAuditDeepDive(finding) {
  if (!finding) return "";
  const conf =
    typeof finding.confidence === "number" && finding.confidence <= 1
      ? Math.round(finding.confidence * 100)
      : finding.confidence;
  const toBe = finding.code_snippet_to_be || finding.remediation || "";
  const warning = finding.handle_lifecycle_warning || finding.technical_impact || "";
  const problem = finding.problem_breakdown || warning;
  const guide = finding.remediation_guide || finding.action_required || "";
  const lang = finding.language_label || finding.language || "";
  const lineRange =
    finding.line_number_start && finding.line_number_end
      ? `L${finding.line_number_start}–${finding.line_number_end}`
      : `L${finding.line_number || finding.line}`;
  const hitLine = finding.highlight_line || finding.line_number || finding.line;

  return `
    <div class="deep-dive-header">
      <div>
        <h3>${escapeHtml(finding.finding_id || finding.id)} · [${escapeHtml(finding.rule_id)}] ${escapeHtml(finding.issue || finding.title)}</h3>
        <p class="score-hint">
          <span class="sev-pill sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          · Confidence ${conf}% · ${escapeHtml(lang)} · ${escapeHtml(finding.location || "")} · ${escapeHtml(lineRange)}
          · hit <strong>L${escapeHtml(String(hitLine))}</strong>
        </p>
      </div>
      <button type="button" class="deep-dive-close" id="auditDeepDiveClose">Close</button>
    </div>

    <div class="deep-dive-guides">
      <div class="guide-card problem">
        <h4>Problem Breakdown</h4>
        <p>${escapeHtml(problem)}</p>
      </div>
      <div class="guide-card fix">
        <h4>Remediation Guide</h4>
        <p>${escapeHtml(guide)}</p>
      </div>
    </div>

    ${warning ? `<p class="lifecycle-warning">${escapeHtml(warning)}</p>` : ""}

    ${aiValidationBanner(finding)}

    <div class="diff-grid">
      <div class="diff-pane">
        <div class="diff-label as-is">As-Is (vulnerable) · highlight = L${escapeHtml(String(hitLine))}</div>
        ${renderAsIsSnippet(finding)}
      </div>
      <div class="diff-pane">
        <div class="diff-label to-be">To-Be (${escapeHtml(lang || "safe recycle")})</div>
        <pre class="diff-code">${escapeHtml(toBe)}</pre>
      </div>
    </div>
    <p class="score-hint"><strong>Action:</strong> ${escapeHtml(finding.action_required || "")}</p>
  `;
}

function wireCodeAuditDeepDive() {
  const section = document.getElementById("codeAuditSection");
  const dive = document.getElementById("auditDeepDive");
  if (!section || !dive || !currentCodeAudit?.findings?.length) return;

  const openFinding = (idx) => {
    const finding = currentCodeAudit.findings[idx];
    if (!finding) return;
    dive.innerHTML = renderAuditDeepDive(finding);
    dive.classList.remove("hidden");
    document.getElementById("auditDeepDiveClose")?.addEventListener("click", () => {
      dive.classList.add("hidden");
      dive.innerHTML = "";
    });
    dive.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };

  section.querySelectorAll(".audit-row").forEach((row) => {
    const handler = () => openFinding(Number(row.dataset.findingIdx));
    row.addEventListener("click", handler);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handler();
      }
    });
  });
}

function wireAuditFindingFilters() {
  document.querySelectorAll("[data-findings-filter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      auditFindingFilter = btn.dataset.findingsFilter || "all";
      renderCodeAnalysis();
    });
  });
}

async function wireAiValidationButton() {
  const btn = document.getElementById("runAiValidationBtn");
  if (!btn || btn.disabled) return;
  btn.addEventListener("click", async () => {
    const graphId = graphSelect.value;
    if (!graphId) return;
    const status = document.getElementById("aiValidationStatus");
    btn.disabled = true;
    btn.textContent = "Running AI audit…";
    if (status) status.textContent = "Pass 1 false-positive filter + Pass 2 blind-spot detector…";
    try {
      const audit = await fetchJson(`/api/graphs/${graphId}/code-audit?llm=true`);
      currentCodeAudit = audit;
      auditFindingFilter = "all";
      renderCodeAnalysis();
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Run AI Discrepancy Audit";
      if (status) status.textContent = `AI audit failed: ${err.message}`;
      showError(err.message);
    }
  });
}

function renderOverview(summary) {
  if (!summary) {
    overviewContent.innerHTML = `<p class="placeholder">No analysis available.</p>`;
    return;
  }

  const caps = summary.capabilities || [];
  const flow = summary.application_flow || {};
  const rules = summary.business_rules || [];
  const lifecycles = summary.document_lifecycles || [];
  const dbs = summary.databases || [];
  const scoreCard = renderModernizationCard(currentAnalysis?.modernization_score);
  const codeTeaser = renderCodeAuditTeaser(currentCodeAudit, currentFunctionInventory);

  const dbHtml = dbs.length
    ? `<section class="overview-section"><h2>Databases (${dbs.length})</h2><ul class="overview-list">${dbs
        .map(
          (d) =>
            `<li><strong>${d.title || d.id}</strong> <code>${d.id}</code> — ${d.counts?.forms || 0} forms, ${d.counts?.views || 0} views, ${d.counts?.agents || 0} agents</li>`
        )
        .join("")}</ul></section>`
    : "";

  const capRows = caps
    .map(
      (c) =>
        `<tr><td>${c.domain}</td><td>${c.forms.length}</td><td>${c.views.length}</td><td>${c.agents.length}</td><td>${c.rules_count}</td></tr>`
    )
    .join("");

  const macroHtml = (flow.macro_invocations || [])
    .slice(0, 15)
    .map((m) => `<li><code>${m.from}</code> → <code>${m.to}</code></li>`)
    .join("");

  const agentHtml = (flow.scheduled_agents || [])
    .map((a) => `<li><strong>${a.name}</strong> — <code>${a.trigger || "manual"}</code></li>`)
    .join("");

  const hubHtml = (flow.lookup_hubs || [])
    .slice(0, 8)
    .map((h) => `<li><strong>${h.view}</strong> — ${h.incoming_lookups} lookups</li>`)
    .join("");

  const rulesHtml = rules
    .slice(0, 12)
    .map(
      (r) =>
        `<details class="rule-item"><summary><span class="rule-id">${r.id}</span> ${r.title}</summary><p class="rule-meta"><code>${r.source}</code> · ${r.type}</p><p>${r.summary}</p></details>`
    )
    .join("");

  const lcHtml = lifecycles
    .slice(0, 8)
    .map(
      (lc) =>
        `<details class="lifecycle-item"><summary>${lc.form} (${lc.stages.length} events)</summary><ul>${lc.stages
          .map((s) => `<li><strong>${s.event}</strong>: ${s.summaries[0]}</li>`)
          .join("")}</ul></details>`
    )
    .join("");

  const edgeSummary = Object.entries(flow.edge_summary || {})
    .map(([k, v]) => `<span class="edge-pill">${k.replace(/_/g, " ")}: ${v}</span>`)
    .join("");

  const catalogTotals = currentAnalysis?.business_rules?.totals;
  const catalogHint = catalogTotals
    ? `<p class="overview-sub"><a href="#" id="openRulesTab">${catalogTotals.fields || 0} cataloged fields</a> · ${catalogTotals.fields_with_validation || 0} validations · ${catalogTotals.lookups || 0} lookups</p>`
    : "";

  overviewContent.innerHTML = `
    <div class="overview-header">
      <h2>Executive Overview</h2>
      <p class="overview-sub">High-level application posture — modernization readiness, capabilities, and flow. Use <strong>Code Analysis</strong> for handle-leak deep-dives.</p>
      <p class="overview-sub">${summary.meta?.totals?.business_logic_blocks || 0} logic blocks · ${summary.meta?.totals?.edges || 0} dependency edges</p>
      ${catalogHint}
      <div class="edge-pills">${edgeSummary}</div>
    </div>
    ${scoreCard}
    ${codeTeaser}
    ${dbHtml}
    <section class="overview-section">
      <h2>Business Capabilities</h2>
      <table class="overview-table">
        <thead><tr><th>Domain</th><th>Forms</th><th>Views</th><th>Agents</th><th>Logic</th></tr></thead>
        <tbody>${capRows}</tbody>
      </table>
    </section>
    <section class="overview-section">
      <h2>Application Flow</h2>
      ${agentHtml ? `<h3>Scheduled agents</h3><ul class="overview-list">${agentHtml}</ul>` : ""}
      ${macroHtml ? `<h3>Macro / agent invocations</h3><ul class="overview-list">${macroHtml}</ul>` : ""}
      ${hubHtml ? `<h3>Lookup hubs</h3><ul class="overview-list">${hubHtml}</ul>` : ""}
    </section>
    <section class="overview-section">
      <h2>Business Rules (synthesis)</h2>
      <div class="rules-list">${rulesHtml}</div>
    </section>
    <section class="overview-section">
      <h2>Document Lifecycles</h2>
      <div class="lifecycle-list">${lcHtml}</div>
    </section>
  `;

  document.getElementById("openRulesTab")?.addEventListener("click", (e) => {
    e.preventDefault();
    setActiveView("rules");
  });
  document.getElementById("openCodeTab")?.addEventListener("click", (e) => {
    e.preventDefault();
    setActiveView("code");
  });
}

async function loadSummary(graphId) {
  try {
    overviewContent.innerHTML = `<p class="placeholder">Loading application analysis…</p>`;
    const [summary, analysis, codeAudit, functionInventory] = await Promise.all([
      fetchJson(`/api/graphs/${graphId}/summary`),
      fetchJson(`/api/graphs/${graphId}/analysis`).catch(() => null),
      fetchJson(`/api/graphs/${graphId}/code-audit`).catch(() => null),
      fetchJson(`/api/graphs/${graphId}/function-inventory`).catch(() => null),
    ]);
    currentSummary = summary;
    currentAnalysis = analysis;
    currentCodeAudit = codeAudit;
    currentFunctionInventory = functionInventory;
    if (activeView === "overview") renderOverview(currentSummary);
    if (activeView === "code") renderCodeAnalysis();
    if (activeView === "rules") renderRulesCatalog();
  } catch (err) {
    currentSummary = null;
    currentAnalysis = null;
    currentCodeAudit = null;
    currentFunctionInventory = null;
    auditFindingFilter = "all";
    if (activeView === "overview") {
      overviewContent.innerHTML = `<p class="error">Could not load analysis: ${err.message}. Restart the API server to pick up the latest code.</p>`;
    }
    if (activeView === "code" && codeAnalysisContent) {
      codeAnalysisContent.innerHTML = `<p class="error">Could not load code audit: ${err.message}</p>`;
    }
    if (activeView === "rules") {
      rulesContent.innerHTML = `<p class="error">Could not load rules: ${err.message}</p>`;
    }
  }
}

function showOverviewError(msg) {
  overviewContent.innerHTML = `<p class="error">${msg}</p>`;
}

function setActiveView(view) {
  activeView = view;
  viewTabs.forEach((tab) => {
    const isActive = tab.dataset.view === view;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", isActive ? "true" : "false");
  });

  const isMatrix = view === "matrix";
  const isOverview = view === "overview";
  const isRules = view === "rules";
  const isCode = view === "code";
  const hideGraph = isMatrix || isOverview || isRules || isCode;
  graphPanel.classList.toggle("hidden", hideGraph);
  matrixPanel.classList.toggle("hidden", !isMatrix);
  overviewPanel.classList.toggle("hidden", !isOverview);
  codeAnalysisPanel?.classList.toggle("hidden", !isCode);
  rulesPanel?.classList.toggle("hidden", !isRules);
  legend?.classList.toggle("hidden", hideGraph);

  focusSelectLabel.classList.toggle("hidden", view !== "focus");
  edgeFilterLabel.classList.toggle("hidden", hideGraph);
  layoutLabel.classList.toggle("hidden", hideGraph);
  aggregateLabel.classList.toggle("hidden", hideGraph);
  zoomControls.classList.toggle("hidden", hideGraph);

  if (isOverview) {
    if (currentSummary) renderOverview(currentSummary);
    else if (graphSelect.value) loadSummary(graphSelect.value);
  } else if (isCode) {
    renderCodeAnalysis();
  } else if (isRules) {
    if (currentAnalysis) renderRulesCatalog();
    else if (graphSelect.value) loadSummary(graphSelect.value);
  } else if (isMatrix) {
    buildLookupMatrix();
  } else {
    if (view === "graph") focusTargetId = null;
    if (focusNodeId) focusSelect.value = focusNodeId;
    buildNetwork();
  }
}

function findDesignElement(nodeId) {
  if (!fullGraph?.graph?.design_elements) return null;
  const [type, ...nameParts] = nodeId.split(":");
  const name = nameParts.join(":");
  const de = fullGraph.graph.design_elements;
  const map = {
    form: de.forms,
    subform: de.subforms,
    view: de.views,
    agent: de.agents,
    scriptlibrary: de.script_libraries,
  };
  const list = map[type] || [];
  return list.find((x) => x.name === name) || null;
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderFormulaBlock(label, body) {
  if (!body) return "";
  return `
    <div class="formula-block">
      <div class="formula-label">${escapeHtml(label)}</div>
      <pre class="formula-code">${escapeHtml(body)}</pre>
    </div>`;
}

function getBusinessLogicForOwner(ownerName) {
  const blocks = fullGraph?.graph?.business_logic || [];
  return blocks.filter((b) => b.owner_name === ownerName);
}

function renderFieldsSection(fields) {
  if (!fields?.length) return "";

  const items = fields
    .map((f) => {
      const badges = [
        f.type && `<span class="badge">${escapeHtml(f.type)}</span>`,
        f.kind && `<span class="badge">${escapeHtml(f.kind)}</span>`,
        f.is_ref && `<span class="badge badge-ref">$REF</span>`,
        f.hidewhen && `<span class="badge badge-hw">hidewhen</span>`,
        f.embedded_formulas?.length &&
          `<span class="badge badge-formula">${f.embedded_formulas.length} formula</span>`,
      ]
        .filter(Boolean)
        .join("");

      const drill = [
        f.hidewhen ? renderFormulaBlock("Hide-when", f.hidewhen) : "",
        ...(f.embedded_formulas || []).map((formula, i) =>
          renderFormulaBlock(
            f.embedded_formulas.length > 1 ? `Formula ${i + 1}` : "Field formula",
            formula
          )
        ),
      ].join("");

      const hasDrill = Boolean(drill);
      return `
        <details class="field-item${hasDrill ? " has-formula" : ""}"${hasDrill ? " open" : ""}>
          <summary>
            <span class="field-name">${escapeHtml(f.name)}</span>
            <span class="field-badges">${badges}</span>
          </summary>
          ${hasDrill ? `<div class="field-drill">${drill}</div>` : `<p class="field-empty">No formulas captured for this field.</p>`}
        </details>`;
    })
    .join("");

  return `
    <h3>Fields (${fields.length})</h3>
    <p class="section-hint">Expand a field to see @Formula, hide-when, and computed logic.</p>
    <input type="search" class="field-search" id="fieldSearch" placeholder="Search fields…" />
    <div class="field-list" id="fieldList">${items}</div>`;
}

function renderCodeEventsSection(codeEvents, title = "Events & code") {
  if (!codeEvents?.length) return "";

  const items = codeEvents
    .map(
      (ev) => `
      <details class="logic-item">
        <summary>
          <span class="logic-event">${escapeHtml(ev.event || "code")}</span>
          <span class="badge">${escapeHtml(ev.language || "formula")}</span>
        </summary>
        ${renderFormulaBlock(ev.event || "body", ev.body)}
      </details>`
    )
    .join("");

  return `<h3>${title} (${codeEvents.length})</h3><div class="logic-list">${items}</div>`;
}

function renderBusinessLogicSection(ownerName) {
  const blocks = getBusinessLogicForOwner(ownerName);
  if (!blocks.length) return "";

  const byCategory = {};
  blocks.forEach((b) => {
    const cat = b.category || "other";
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(b);
  });

  const categories = Object.entries(byCategory)
    .sort((a, b) => b[1].length - a[1].length)
    .map(([cat, items]) => {
      const inner = items
        .map(
          (b) => `
          <details class="logic-item">
            <summary>
              <span class="logic-event">${escapeHtml(b.event || b.context || cat)}</span>
              <span class="badge">${escapeHtml(b.language || "")}</span>
            </summary>
            ${renderFormulaBlock(b.event || cat, b.body)}
          </details>`
        )
        .join("");
      return `
        <details class="category-group">
          <summary>${escapeHtml(cat.replace(/_/g, " "))} (${items.length})</summary>
          <div class="logic-list">${inner}</div>
        </details>`;
    })
    .join("");

  return `
    <h3>Business logic (${blocks.length})</h3>
    <p class="section-hint">Parsed formula &amp; script blocks from DXL.</p>
    <div class="category-list">${categories}</div>`;
}

function renderViewSection(element) {
  let html = "";
  if (element.selection_formula) {
    html += `<h3>Selection formula</h3>${renderFormulaBlock("selection", element.selection_formula)}`;
  }
  if (element.columns?.length) {
    const rows = element.columns
      .map((c) => `<tr><td>${escapeHtml(c.name || c.title || "—")}</td><td>${escapeHtml(c.type || "—")}</td></tr>`)
      .join("");
    html += `
      <h3>Columns (${element.columns.length})</h3>
      <table><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  html += renderCodeEventsSection(element.code_events, "View actions");
  return html;
}

function renderAgentSection(element) {
  let html = "";
  if (element.agent_trigger) {
    html += `<div class="meta-grid"><div><span>Trigger</span> ${escapeHtml(element.agent_trigger)}</div></div>`;
  }
  html += renderCodeEventsSection(element.code_events, "Agent code");
  return html;
}

function wireFieldSearch() {
  const search = document.getElementById("fieldSearch");
  const list = document.getElementById("fieldList");
  if (!search || !list) return;
  search.addEventListener("input", () => {
    const q = search.value.toLowerCase();
    list.querySelectorAll(".field-item").forEach((item) => {
      const name = item.querySelector(".field-name")?.textContent.toLowerCase() || "";
      item.classList.toggle("hidden", q.length > 0 && !name.includes(q));
    });
  });
}

function showNodeDetail(nodeId) {
  const vizNode = currentViz.nodes.find((n) => n.id === nodeId);
  const element = findDesignElement(nodeId);
  if (!vizNode) return;

  const related = currentViz.edges.filter((e) => e.from === nodeId || e.to === nodeId);
  const byType = {};
  related.forEach((e) => {
    byType[e.type] = (byType[e.type] || 0) + 1;
  });

  let fieldsHtml = "";
  let logicHtml = "";

  if (element?.fields?.length) {
    fieldsHtml = renderFieldsSection(element.fields);
  } else if (vizNode.group === "view" && element) {
    fieldsHtml = renderViewSection(element);
  } else if (vizNode.group === "agent" && element) {
    fieldsHtml = renderAgentSection(element);
  }

  if (element?.name) {
    logicHtml = renderBusinessLogicSection(element.name);
  }

  const typeSummary = Object.entries(byType)
    .map(([t, c]) => `<li><strong>${t}</strong> ×${c}</li>`)
    .join("");

  const edgesHtml = related.length
    ? `<h3>Relationships (${related.length})</h3><ul class="edge-list">${typeSummary}</ul>`
    : "";

  const focusBtn =
    activeView !== "matrix"
      ? `<button type="button" class="btn-focus" data-focus="${nodeId}">Focus on this</button>`
      : "";

  detailPanel.innerHTML = `
    <span class="pill pill-${vizNode.group}">${vizNode.group.replace(/_/g, " ")}</span>
    <h2>${vizNode.label}</h2>
    <div class="meta-grid">
      <div><span>Node ID</span> ${nodeId}</div>
      <div><span>Fields</span> ${vizNode.fieldCount ?? 0}</div>
      <div><span>Edges</span> ${related.length}</div>
    </div>
    ${focusBtn}
    ${fieldsHtml}
    ${logicHtml}
    ${edgesHtml}
  `;

  detailPanel.querySelector(".btn-focus")?.addEventListener("click", () => {
    focusNodeId = nodeId;
    focusTargetId = null;
    focusSelect.value = nodeId;
    setActiveView("focus");
  });
  wireFieldSearch();
}

async function loadGraphList() {
  const graphs = await fetchJson("/api/graphs");
  graphSelect.innerHTML = "";
  if (!graphs.length) {
    graphSelect.innerHTML = '<option value="">No graphs in Neon — run store_neon.py</option>';
    showError("No graphs stored. Run: python3 store_neon.py");
    return;
  }
  graphs.forEach((g) => {
    const opt = document.createElement("option");
    opt.value = g.id;
    const title = g.database_title || g.nsf_path;
    const totals = g.totals || {};
    opt.textContent = `${title} (${totals.edges || 0} edges) — ${g.parsed_at?.slice(0, 16) || ""}`;
    graphSelect.appendChild(opt);
  });
}

async function loadSelectedGraph() {
  const id = graphSelect.value;
  if (!id) return;
  const [viz, graph] = await Promise.all([
    fetchJson(`/api/graphs/${id}/viz`),
    fetchJson(`/api/graphs/${id}`),
  ]);
  currentViz = viz;
  fullGraph = graph;
  focusNodeId = null;
  focusTargetId = null;
  currentSummary = null;
  currentAnalysis = null;
  currentCodeAudit = null;
  currentFunctionInventory = null;
  auditFindingFilter = "all";
  syncEdgeFilterForGraph();
  populateFocusSelect();
  loadSummary(id).catch(() => {});
  if (activeView === "overview" || activeView === "rules" || activeView === "code") {
    /* render when summary/analysis returns */
  } else if (activeView === "matrix") {
    buildLookupMatrix();
  } else {
    buildNetwork();
  }
  const edgeTypes = [...new Set((viz.edges || []).map((e) => e.type))];
  detailPanel.innerHTML = `
    <h2>${viz.database_title || "Application"}</h2>
    <div class="meta-grid">
      <div><span>NSF</span> ${viz.nsf_path || "—"}</div>
      <div><span>Nodes</span> ${viz.nodes.length}</div>
      <div><span>Edges</span> ${viz.edges.length}</div>
      <div><span>Lookups</span> ${viz.edges.filter((e) => e.type === "LOOKUP_VIA_VIEW").length}</div>
    </div>
    <p class="section-hint">Relationship types: ${edgeTypes.length ? edgeTypes.map((t) => t.replace(/_/g, " ")).join(", ") : "none"}</p>
    <p class="placeholder">Click a node, then expand fields in the sidebar to see formulas and business logic.</p>
  `;
}

graphSelect.addEventListener("change", () => loadSelectedGraph().catch(showError));
edgeFilter.addEventListener("change", () => {
  focusTargetId = null;
  activeView === "matrix" ? buildLookupMatrix() : buildNetwork();
});
focusSelect.addEventListener("change", () => {
  focusNodeId = focusSelect.value;
  focusTargetId = null;
  buildNetwork();
});
layoutDirection.addEventListener("change", () => buildNetwork());
aggregateEdges.addEventListener("change", () => buildNetwork());
matrixHideEmpty.addEventListener("change", () => buildLookupMatrix());
zoomInBtn.addEventListener("click", () => network?.moveTo({ scale: network.getScale() * 1.25, animation: true }));
zoomOutBtn.addEventListener("click", () => network?.moveTo({ scale: network.getScale() * 0.8, animation: true }));
fitBtn.addEventListener("click", () => network?.fit({ animation: true }));

dxlUpload?.addEventListener("change", async () => {
  const file = dxlUpload.files?.[0];
  if (!file) return;

  const lower = (file.name || "").toLowerCase();
  if (!lower.endsWith(".dxl") && !lower.endsWith(".xml")) {
    const msg = "File must be a .dxl or .xml Domino export";
    uploadStatus.textContent = msg;
    uploadStatus.className = "upload-status error";
    showError(msg);
    dxlUpload.value = "";
    return;
  }

  const sizeMb = file.size / (1024 * 1024);
  uploadStatus.textContent = `Uploading ${file.name} (${sizeMb.toFixed(2)} MB)…`;
  uploadStatus.className = "upload-status";

  // Soft client hint — Vercel body limit is ~4.5 MB including multipart overhead
  if (file.size > 4.4 * 1024 * 1024) {
    const msg =
      `File is ${sizeMb.toFixed(2)} MB — too large for cloud upload (~4.5 MB max). ` +
      `Ingest locally instead: python3 dxl_parser.py --input "${file.name}" --store-neon`;
    uploadStatus.textContent = msg;
    uploadStatus.className = "upload-status error";
    showError(msg);
    dxlUpload.value = "";
    return;
  }

  const form = new FormData();
  form.append("file", file);

  try {
    const res = await fetch("/api/upload", { method: "POST", body: form });
    const body = await res.json().catch(() => ({}));
    const detail = typeof body.detail === "string" ? body.detail : body.detail ? JSON.stringify(body.detail) : res.statusText;
    if (!res.ok) throw new Error(detail || res.statusText);

    uploadStatus.textContent = `Stored: ${body.database_title || file.name} (${body.totals?.edges || 0} edges)`;
    uploadStatus.className = "upload-status success";

    await loadGraphList();
    graphSelect.value = body.id;
    currentSummary = null;
    currentAnalysis = null;
    await loadSelectedGraph();
    setActiveView("overview");
  } catch (e) {
    uploadStatus.textContent = e.message;
    uploadStatus.className = "upload-status error";
    showError(e.message);
  } finally {
    dxlUpload.value = "";
  }
});

refreshBtn.addEventListener("click", async () => {
  try {
    await loadGraphList();
    await loadSelectedGraph();
  } catch (e) {
    showError(e.message);
  }
});

viewTabs.forEach((tab) => {
  tab.addEventListener("click", () => setActiveView(tab.dataset.view));
});

function onRulesFilterChange() {
  if (activeView === "rules") renderRulesCatalog();
}
rulesSearch?.addEventListener("input", onRulesFilterChange);
rulesFormFilter?.addEventListener("change", onRulesFilterChange);
rulesValidationOnly?.addEventListener("change", onRulesFilterChange);
rulesLookupsOnly?.addEventListener("change", onRulesFilterChange);

(async () => {
  try {
    await loadGraphList();
    if (graphSelect.value) {
      await loadSelectedGraph();
    }
  } catch (e) {
    showError(`API error: ${e.message}. Start the server with: uvicorn server:app`);
  }
})();
