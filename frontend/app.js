const AUTO_REFRESH_MS = 10000;

let currentEditId = null;
let currentIncidentId = null;
let currentIncident = null;
let incidentRecords = [];
let refreshTimer = null;
let isSyncing = false;
let drawerReturnFocus = null;
let pageScrollY = 0;

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  syncData();
  startLiveUpdates();

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) syncData({ silent: true });
  });
});

function bindEvents() {
  document.getElementById("new-incident-btn").addEventListener("click", openCreateForm);
  document.getElementById("create-close-btn").addEventListener("click", closeCreateForm);
  document.getElementById("create-cancel-btn").addEventListener("click", closeCreateForm);
  document.getElementById("create-form").addEventListener("submit", submitCreateForm);
  document.getElementById("refresh-btn").addEventListener("click", () => syncData());
  document.getElementById("retry-btn").addEventListener("click", () => syncData());
  document.getElementById("clear-filters-btn").addEventListener("click", clearFilters);

  ["search-filter", "severity-filter", "status-filter", "sort-filter"].forEach((id) => {
    document.getElementById(id).addEventListener(id === "search-filter" ? "input" : "change", renderIncidents);
  });

  document.getElementById("analyze-logs-btn").addEventListener("click", submitAnalyzeLogs);
  document.getElementById("drawer-close-btn").addEventListener("click", closeIncidentDrawer);
  document.addEventListener("click", handleOutsideDrawerClick, true);
  document.addEventListener("keydown", handleDrawerKeyboard);
  document.getElementById("incidents-list").addEventListener("click", (event) => {
    const row = event.target.closest(".incident-row");
    if (row) openIncidentDrawer(row.dataset.incidentId, row);
  });
  document.getElementById("drawer-content").addEventListener("click", handleDrawerActionClick);
  document.getElementById("drawer-content").addEventListener("submit", handleDrawerFormSubmit);
}

function startLiveUpdates() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => syncData({ silent: true }), AUTO_REFRESH_MS);
}

async function syncData() {
  if (isSyncing) return;
  isSyncing = true;
  setPageError(null);

  try {
    await runEscalationCheck();
    const [dashboard, incidents] = await Promise.all([fetchDashboard(), fetchIncidents()]);
    renderDashboard(dashboard);
    incidentRecords = Array.isArray(incidents) ? incidents : [];
    renderIncidents();
    document.getElementById("last-refresh").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
    document.getElementById("incidents-list").setAttribute("aria-busy", "false");
    if (currentIncidentId) await refreshOpenIncident();
  } catch (error) {
    setPageError("The dashboard data could not be loaded. Check your connection and admin sign-in, then try again.");
    document.getElementById("health-banner").className = "health-pill health-loading";
    document.getElementById("health-label").textContent = "Health unavailable";
    document.getElementById("last-refresh").textContent = "Update failed";
    document.getElementById("incidents-list").setAttribute("aria-busy", "false");
    if (!incidentRecords.length) renderListFailure();
  } finally {
    isSyncing = false;
  }
}

function renderDashboard(dashboard) {
  const score = dashboard?.healthScore || {};
  const healthLabel = typeof score.label === "string" ? score.label : "Unavailable";
  const normalizedHealth = healthLabel.toLowerCase().replace(/\s+/g, "-");
  const healthBanner = document.getElementById("health-banner");
  healthBanner.className = `health-pill health-${["healthy", "degraded", "at-risk", "critical"].includes(normalizedHealth) ? normalizedHealth : "loading"}`;
  document.getElementById("health-label").textContent = healthLabel === "Unavailable" ? "Health unavailable" : `System ${healthLabel.toLowerCase()}`;

  document.getElementById("stat-total").textContent = displayCount(dashboard?.total);
  document.getElementById("stat-open").textContent = displayCount(dashboard?.open);
  document.getElementById("stat-critical").textContent = displayCount(dashboard?.critical);
  document.getElementById("stat-resolved").textContent = displayCount(dashboard?.resolved);
  document.getElementById("stat-health-label").textContent = healthLabel;
  document.getElementById("stat-health-score").textContent = Number.isFinite(score.value) ? `Health score ${score.value}` : "Score unavailable";
}

function displayCount(value) {
  return Number.isFinite(value) ? String(value) : "—";
}

function clearFilters() {
  document.getElementById("search-filter").value = "";
  document.getElementById("severity-filter").value = "";
  document.getElementById("status-filter").value = "";
  document.getElementById("sort-filter").value = "date";
  renderIncidents();
}

function getVisibleIncidents() {
  const query = document.getElementById("search-filter").value.trim().toLowerCase();
  const severity = document.getElementById("severity-filter").value;
  const status = document.getElementById("status-filter").value;
  const sort = document.getElementById("sort-filter").value;
  const weight = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

  return incidentRecords
    .filter((incident) => !severity || incident.severity === severity)
    .filter((incident) => !status || incident.status === status)
    .filter((incident) => {
      if (!query) return true;
      const findingText = (incident.findingRefs || []).map((finding) => [finding.type, finding.summary, finding.ruleId, finding.detectorType].join(" ")).join(" ");
      const searchable = [incident.incidentId, incident.title, incident.description, incident.assignedTo, findingText].join(" ").toLowerCase();
      return searchable.includes(query);
    })
    .sort((left, right) => sort === "severity"
      ? (weight[right.severity] || 0) - (weight[left.severity] || 0) || dateValue(right.createdAt) - dateValue(left.createdAt)
      : dateValue(right.createdAt) - dateValue(left.createdAt));
}

function renderIncidents() {
  const container = document.getElementById("incidents-list");
  const incidents = getVisibleIncidents();
  document.getElementById("incident-count").textContent = incidentRecords.length === incidents.length
    ? String(incidents.length)
    : `${incidents.length} / ${incidentRecords.length}`;
  container.innerHTML = "";

  if (!incidentRecords.length) {
    container.innerHTML = `<div class="empty-state"><span class="empty-icon" aria-hidden="true">✓</span><h3>No security incidents</h3><p>Your environment currently has no recorded incidents.</p></div>`;
    return;
  }
  if (!incidents.length) {
    container.innerHTML = `<div class="empty-state"><span class="empty-icon" aria-hidden="true">⌕</span><h3>No incidents match</h3><p>Try changing or clearing your search and filters.</p><button id="empty-clear-filters" class="button button-quiet" type="button">Clear filters</button></div>`;
    document.getElementById("empty-clear-filters").addEventListener("click", clearFilters);
    return;
  }

  incidents.forEach((incident) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `incident-row${currentIncidentId === incident.incidentId ? " is-selected" : ""}`;
    row.dataset.incidentId = incident.incidentId;
    row.setAttribute("aria-haspopup", "dialog");
    row.setAttribute("aria-label", `${incident.title || "Incident"}, ${incident.severity || "severity unavailable"}, ${statusLabel(incident.status)}. Open details.`);
    const overdue = incident.status !== "RESOLVED" && Number.isFinite(dateValue(incident.slaDeadline)) && dateValue(incident.slaDeadline) < Date.now();
    const findingCount = Array.isArray(incident.findingRefs) ? incident.findingRefs.length : 0;
    row.innerHTML = `
      <span class="incident-main"><span class="incident-title-line"><span class="incident-title">${escapeHtml(incident.title || "Untitled incident")}</span><span class="row-chevron" aria-hidden="true">›</span></span>
        <span class="incident-meta"><span class="mono">${escapeHtml(incident.incidentId)}</span><span>${escapeHtml(formatShortDate(incident.createdAt))}</span>${findingCount ? `<span>${findingCount} finding${findingCount === 1 ? "" : "s"}</span>` : ""}</span></span>
      <span class="row-cell"><span class="column-mobile-label">Severity</span><span class="badge ${severityClass(incident.severity)}"><span class="badge-mark" aria-hidden="true"></span>${escapeHtml(incident.severity || "Unknown")}</span></span>
      <span class="row-cell"><span class="column-mobile-label">Status</span><span class="badge ${statusClass(incident.status)}">${escapeHtml(statusLabel(incident.status))}</span></span>
      <span class="row-cell assignee-cell"><span class="column-mobile-label">Assigned to</span><span class="assignee"><span class="avatar" aria-hidden="true">${escapeHtml(initials(incident.assignedTo))}</span>${escapeHtml(incident.assignedTo || "Unassigned")}</span></span>
      <span class="row-cell sla-cell${overdue ? " overdue-sla" : ""}"><span class="column-mobile-label">SLA deadline</span><span>${escapeHtml(formatShortDateTime(incident.slaDeadline))}</span>${overdue ? `<span class="overdue-label">Overdue</span>` : ""}</span>
      <span class="row-open-label">View details <span aria-hidden="true">→</span></span>`;
    container.appendChild(row);
  });
}

function renderListFailure() {
  const container = document.getElementById("incidents-list");
  container.innerHTML = `<div class="empty-state"><span class="empty-icon empty-error" aria-hidden="true">!</span><h3>Incidents are unavailable</h3><p>We could not load the incident list. Try refreshing the dashboard.</p><button class="button button-quiet list-retry" type="button">Try again</button></div>`;
  container.querySelector(".list-retry").addEventListener("click", () => syncData());
}

function setPageError(message) {
  const banner = document.getElementById("page-error");
  banner.hidden = !message;
  if (message) document.getElementById("page-error-message").textContent = message;
}

function openCreateForm() {
  document.getElementById("create-error").hidden = true;
  document.getElementById("create-dialog").showModal();
  document.getElementById("create-title").focus();
}

function closeCreateForm() {
  const dialog = document.getElementById("create-dialog");
  if (dialog.open) dialog.close();
  document.getElementById("create-form").reset();
  document.getElementById("create-error").hidden = true;
}

async function submitCreateForm(event) {
  event.preventDefault();
  const errorElement = document.getElementById("create-error");
  errorElement.hidden = true;
  const payload = {
    title: document.getElementById("create-title").value.trim(),
    description: document.getElementById("create-description").value.trim(),
    severity: document.getElementById("create-severity").value,
    assignedTo: document.getElementById("create-assigned-to").value.trim()
  };

  try {
    await createIncident(payload);
    closeCreateForm();
    await syncData();
  } catch (error) {
    errorElement.textContent = error?.message || "Incident could not be created. Try again.";
    errorElement.hidden = false;
  }
}

async function submitAnalyzeLogs() {
  const logs = document.getElementById("log-input").value.trim();
  const resultBox = document.getElementById("log-analysis-result");
  if (!logs) return showLogAnalysisError("Please enter logs before analyzing.");

  resultBox.innerHTML = `<div class="analysis-pending"><span class="loader" aria-hidden="true"></span>Analyzing logs…</div>`;
  resultBox.className = "analysis-output";
  try {
    const response = await analyzeLogs(logs);
    renderLogAnalysisResult(response);
    await syncData();
  } catch (error) {
    showLogAnalysisError(error?.message || "Unable to analyze logs.");
  }
}

function renderLogAnalysisResult(result) {
  const resultBox = document.getElementById("log-analysis-result");
  const detection = result?.detection || {};
  const threatDetected = detection.status === "threat_detected";
  const incidentMessage = result?.incident ? `Incident created: ${result.incident.incidentId}` : "No incident created.";
  const cards = (Array.isArray(detection.matchedRules) ? detection.matchedRules : []).map((rule) => `
    <article class="rule-card"><div class="finding-card-heading"><strong>${escapeHtml(rule.id || rule.pattern || "Detection rule")}</strong><span class="badge ${severityClass(rule.severity)}">${escapeHtml(rule.severity || "Unknown")}</span></div>
      <p>${escapeHtml(rule.description || rule.pattern || "Rule matched")}</p><small>${escapeHtml(rule.type || "Detection")} · ${escapeHtml(String(rule.count || 1))} match${rule.count === 1 ? "" : "es"}</small></article>`).join("");
  resultBox.innerHTML = `<div class="analysis-summary"><p class="analysis-result-title ${threatDetected ? "text-high" : "text-good"}">${threatDetected ? "Threat detected" : "No threat detected"}</p>
    <p><strong>Type</strong><span>${escapeHtml(detection.type || "Unknown")}</span></p><p><strong>Severity</strong><span>${escapeHtml(detection.severity || "Unknown")}</span></p><p><strong>Result</strong><span>${escapeHtml(incidentMessage)}</span></p></div>
    ${cards ? `<div class="matched-rules">${cards}</div>` : `<p class="muted-copy">No detection rules matched.</p>`}`;
  resultBox.className = `analysis-output ${threatDetected ? "analysis-warning" : "analysis-success"}`;
}

function showLogAnalysisError(message) {
  const resultBox = document.getElementById("log-analysis-result");
  resultBox.innerHTML = `<p class="analysis-error-message">${escapeHtml(message)}</p>`;
  resultBox.className = "analysis-output analysis-error";
}

async function openIncidentDrawer(id, trigger = null) {
  const layer = document.getElementById("drawer-layer");
  const wasOpen = !layer.hidden;
  if (!wasOpen) {
    drawerReturnFocus = trigger || document.activeElement;
    pageScrollY = window.scrollY;
    document.body.style.position = "fixed";
    document.body.style.top = `-${pageScrollY}px`;
    document.body.style.width = "100%";
    layer.hidden = false;
  } else if (trigger) {
    drawerReturnFocus = trigger;
  }

  currentIncidentId = id;
  currentIncident = null;
  currentEditId = null;
  renderIncidents();
  renderDrawerLoading();
  document.getElementById("drawer-incident-id").textContent = id;
  document.getElementById("drawer-title").textContent = "Loading incident…";
  setDrawerSeverity(null);
  document.getElementById("drawer-close-btn").focus();

  try {
    const incident = await fetchIncidentById(id);
    if (!incident) throw new Error("This incident is no longer available.");
    if (currentIncidentId !== id) return;
    currentIncident = incident;
    renderIncidentDetails(incident);
  } catch (error) {
    if (currentIncidentId !== id) return;
    document.getElementById("drawer-content").innerHTML = `<div class="drawer-error"><span class="empty-icon empty-error" aria-hidden="true">!</span><h3>Incident details unavailable</h3><p>We could not load this incident. Refresh the dashboard or try again.</p><button id="drawer-retry-btn" class="button button-quiet" type="button">Try again</button></div>`;
    document.getElementById("drawer-retry-btn").addEventListener("click", () => openIncidentDrawer(id));
  }
}

function renderDrawerLoading() {
  document.getElementById("drawer-content").innerHTML = `<div class="loading-state drawer-loading"><span class="loader" aria-hidden="true"></span><span>Loading incident…</span></div>`;
}

function closeIncidentDrawer() {
  const layer = document.getElementById("drawer-layer");
  if (layer.hidden) return;
  const restoreIncidentId = currentIncidentId;
  layer.hidden = true;
  currentIncidentId = null;
  currentIncident = null;
  currentEditId = null;
  document.body.style.position = "";
  document.body.style.top = "";
  document.body.style.width = "";
  window.scrollTo(0, pageScrollY);
  renderIncidents();
  const currentRow = [...document.querySelectorAll(".incident-row")].find((row) => row.dataset.incidentId === restoreIncidentId);
  const focusTarget = drawerReturnFocus?.isConnected ? drawerReturnFocus : currentRow;
  if (focusTarget) focusTarget.focus();
  drawerReturnFocus = null;
}

function handleOutsideDrawerClick(event) {
  const layer = document.getElementById("drawer-layer");
  if (layer.hidden || document.getElementById("incident-drawer").contains(event.target)) return;
  if (event.target.closest(".incident-row")) return;
  event.preventDefault();
  event.stopPropagation();
  closeIncidentDrawer();
}

function handleDrawerKeyboard(event) {
  const layer = document.getElementById("drawer-layer");
  if (layer.hidden) return;
  if (event.key === "Escape") {
    event.preventDefault();
    closeIncidentDrawer();
    return;
  }
  if (event.key !== "Tab") return;
  const drawer = document.getElementById("incident-drawer");
  const focusable = [...drawer.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], summary, [tabindex]:not([tabindex="-1"])')]
    .filter((element) => !element.hidden && element.offsetParent !== null);
  if (!focusable.length) {
    event.preventDefault();
    drawer.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && (document.activeElement === first || !drawer.contains(document.activeElement))) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && (document.activeElement === last || !drawer.contains(document.activeElement))) {
    event.preventDefault();
    first.focus();
  }
}

function renderIncidentDetails(incident) {
  const id = incident.incidentId || "Unknown";
  document.getElementById("drawer-incident-id").textContent = id;
  document.getElementById("drawer-title").textContent = incident.title || "Untitled incident";
  setDrawerSeverity(incident.severity);
  document.getElementById("drawer-content").innerHTML = `
    <section class="drawer-hero" aria-label="Incident summary">
      <div class="hero-badges"><span class="badge ${statusClass(incident.status)}">${escapeHtml(statusLabel(incident.status))}</span><span class="assignee"><span class="avatar" aria-hidden="true">${escapeHtml(initials(incident.assignedTo))}</span>${escapeHtml(incident.assignedTo || "Unassigned")}</span></div>
      ${incident.description ? `<p class="hero-description">${escapeHtml(incident.description)}</p>` : ""}
    </section>

    <section class="drawer-section"><div class="drawer-section-heading"><div><p class="eyebrow">Case context</p><h3>Overview</h3></div></div>
      <dl class="overview-grid">
        ${detailField("Incident ID", id, true)}${detailField("Threat type", incident.title || "Unavailable")}
        ${detailField("Severity", incident.severity || "Unavailable")}${detailField("Status", statusLabel(incident.status))}
        ${detailField("Assigned to", incident.assignedTo || "Unassigned")}${detailField("Created", formatTimestamp(incident.createdAt))}
        ${detailField("Last updated", formatTimestamp(incident.updatedAt))}${detailField("SLA deadline", formatTimestamp(incident.slaDeadline), false, isOverdue(incident))}
      </dl>
    </section>

    <section class="drawer-section"><div class="drawer-section-heading"><div><p class="eyebrow">Signals</p><h3>Associated findings</h3></div><span class="section-count">${Array.isArray(incident.findingRefs) ? incident.findingRefs.length : 0}</span></div>
      <div id="drawer-findings" class="finding-list"></div>
    </section>

    <section class="drawer-section"><div class="drawer-section-heading"><div><p class="eyebrow">Response history</p><h3>Timeline</h3></div></div><div id="timeline-body" class="timeline-list"></div></section>

    <section class="drawer-section"><div class="drawer-section-heading"><div><p class="eyebrow">Supporting context</p><h3>Investigation details</h3></div></div>
      <div id="drawer-evidence" class="evidence-summary"></div>
    </section>

    <section class="drawer-section admin-actions"><div class="drawer-section-heading"><div><p class="eyebrow">Response controls</p><h3>Admin actions</h3></div></div>
      <div class="action-buttons"><button id="drawer-edit-toggle" class="button button-secondary" type="button">Edit incident</button><button id="drawer-delete-btn" class="button button-danger" type="button">Delete incident</button></div>
      <form id="drawer-edit-form" class="edit-form" hidden>
        <div class="form-grid"><div><label for="drawer-edit-status">Status</label><select id="drawer-edit-status" required><option value="OPEN">Open</option><option value="IN_PROGRESS">In progress</option><option value="RESOLVED">Resolved</option></select></div><div><label for="drawer-edit-assigned">Assigned to</label><input id="drawer-edit-assigned" type="text" required /></div></div>
        <p id="drawer-edit-error" class="form-error" role="alert" hidden></p>
        <div class="dialog-actions"><button id="drawer-edit-cancel" class="button button-quiet" type="button">Cancel</button><button class="button button-primary" type="submit">Save changes</button></div>
      </form>
    </section>`;

  renderFindingRefs(incident.findingRefs || []);
  renderTimelineEntries(incident.timeline || []);
  renderIncidentEvidence(incident);
}

function detailField(label, value, mono = false, warning = false) {
  return `<div class="overview-field"><dt>${escapeHtml(label)}</dt><dd class="${mono ? "mono" : ""}${warning ? " overdue-sla" : ""}">${escapeHtml(value)}</dd></div>`;
}

function setDrawerSeverity(severity) {
  const badge = document.getElementById("drawer-severity");
  badge.className = `badge ${severityClass(severity)}`;
  badge.innerHTML = `<span class="badge-mark" aria-hidden="true"></span>${escapeHtml(severity || "Unknown")}`;
}

function renderFindingRefs(findings) {
  const body = document.getElementById("drawer-findings");
  if (!Array.isArray(findings) || findings.length === 0) {
    body.innerHTML = `<div class="empty-inline"><span class="empty-icon" aria-hidden="true">·</span><p>No detection findings are associated with this incident.</p></div>`;
    return;
  }

  body.innerHTML = findings.map((finding) => {
    const identity = [finding.ruleId, finding.detectorType, finding.detectorId].filter((value) => typeof value === "string" && value).join(" · ");
    const count = Number.isFinite(finding.count) ? `<span class="finding-count">${finding.count} events</span>` : "";
    return `<article class="finding-card"><div class="finding-card-heading"><h4>${escapeHtml(finding.type || "Finding")}</h4><span class="badge ${severityClass(finding.severity)}"><span class="badge-mark" aria-hidden="true"></span>${escapeHtml(finding.severity || "MEDIUM")}</span></div>
      ${identity ? `<details class="finding-technical"><summary>Rule / detector details <span class="technical-chevron" aria-hidden="true">⌄</span></summary><p class="finding-identity">${escapeHtml(identity)}</p></details>` : ""}<p class="finding-summary">${escapeHtml(finding.summary || "Finding detected")}</p>
      <div class="finding-meta"><time>${escapeHtml(formatTimestamp(finding.detectedAt))}</time>${count}</div></article>`;
  }).join("");
}

function renderTimelineEntries(entries) {
  const body = document.getElementById("timeline-body");
  if (!Array.isArray(entries) || entries.length === 0) {
    body.innerHTML = `<div class="empty-inline"><span class="empty-icon" aria-hidden="true">·</span><p>No timeline entries are available.</p></div>`;
    return;
  }

  body.innerHTML = entries.map((entry) => {
    const action = timelineAction(entry.action);
    const transition = entry.from && entry.to ? `<p class="timeline-transition">${escapeHtml(statusLabel(entry.from))} <span aria-hidden="true">→</span> ${escapeHtml(statusLabel(entry.to))}</p>` : "";
    return `<article class="timeline-item"><span class="timeline-marker" aria-hidden="true"></span><div class="timeline-content"><time>${escapeHtml(formatTimestamp(entry.timestamp))}</time><h4>${escapeHtml(action)}</h4>${transition}<p class="timeline-actor">${entry.by ? `By ${escapeHtml(entry.by)}` : "Actor unavailable"}</p></div></article>`;
  }).join("");
}

function timelineAction(action) {
  return ({ CREATED: "Incident created", STATUS_CHANGE: "Status changed", REASSIGNED: "Assignment updated", ESCALATED: "Incident escalated", FINDINGS_ASSOCIATED: "Findings associated" })[action] || String(action || "Incident updated").replaceAll("_", " ");
}

function renderIncidentEvidence(incident) {
  const body = document.getElementById("drawer-evidence");
  const eventIds = Array.isArray(incident.eventIds) ? incident.eventIds.filter((id) => typeof id === "string" && id) : [];
  const findings = Array.isArray(incident.findingRefs) ? incident.findingRefs : [];
  const summaries = findings.map((finding) => finding.summary).filter(Boolean);
  const identifiers = eventIds.length ? `<details class="technical-details"><summary><span>Event identifiers (${eventIds.length})</span><span class="technical-chevron" aria-hidden="true">⌄</span></summary><ul>${eventIds.map((id) => `<li class="mono">${escapeHtml(id)}</li>`).join("")}</ul></details>` : "";
  body.innerHTML = `${summaries.length ? `<p class="evidence-copy">${summaries.length} finding summary${summaries.length === 1 ? "" : "ies"} available above.</p>` : `<p class="muted-copy">No additional evidence available for this incident.</p>`}${identifiers}`;
}

function handleDrawerActionClick(event) {
  const action = event.target.closest("button");
  if (!action || !currentIncident) return;
  if (action.id === "drawer-edit-toggle") {
    const form = document.getElementById("drawer-edit-form");
    form.hidden = false;
    document.getElementById("drawer-edit-status").value = currentIncident.status || "OPEN";
    document.getElementById("drawer-edit-assigned").value = currentIncident.assignedTo || "";
    document.getElementById("drawer-edit-status").focus();
  } else if (action.id === "drawer-edit-cancel") {
    document.getElementById("drawer-edit-form").hidden = true;
    document.getElementById("drawer-edit-error").hidden = true;
  } else if (action.id === "drawer-delete-btn") {
    handleDelete(currentIncident.incidentId);
  }
}

async function handleDrawerFormSubmit(event) {
  if (event.target.id !== "drawer-edit-form") return;
  event.preventDefault();
  if (!currentIncident) return;
  currentEditId = currentIncident.incidentId;
  const errorElement = document.getElementById("drawer-edit-error");
  errorElement.hidden = true;
  try {
    await updateIncident(currentEditId, {
      status: document.getElementById("drawer-edit-status").value,
      assignedTo: document.getElementById("drawer-edit-assigned").value.trim(),
      by: "UI User"
    });
    document.getElementById("drawer-edit-form").hidden = true;
    currentEditId = null;
    await syncData();
  } catch (error) {
    errorElement.textContent = error?.message || "Changes could not be saved.";
    errorElement.hidden = false;
  }
}

async function handleDelete(id) {
  if (!window.confirm(`Delete incident ${id}? This action cannot be undone.`)) return;
  try {
    await deleteIncident(id);
    closeIncidentDrawer();
    await syncData();
  } catch (error) {
    const content = document.getElementById("drawer-content");
    const notice = document.createElement("p");
    notice.className = "form-error drawer-action-error";
    notice.setAttribute("role", "alert");
    notice.textContent = error?.message || "Incident could not be deleted.";
    content.prepend(notice);
  }
}

async function refreshOpenIncident() {
  const id = currentIncidentId;
  try {
    const incident = await fetchIncidentById(id);
    if (!incident) {
      closeIncidentDrawer();
      return;
    }
    if (currentIncidentId === id) {
      const previousSnapshot = currentIncident ? JSON.stringify(currentIncident) : "";
      currentIncident = incident;
      renderIncidents();
      if (JSON.stringify(incident) !== previousSnapshot) {
        const content = document.getElementById("drawer-content");
        const scrollTop = content.scrollTop;
        const editForm = document.getElementById("drawer-edit-form");
        const editDraft = editForm && !editForm.hidden
          ? { status: document.getElementById("drawer-edit-status").value, assignedTo: document.getElementById("drawer-edit-assigned").value }
          : null;
        renderIncidentDetails(incident);
        const refreshedContent = document.getElementById("drawer-content");
        refreshedContent.scrollTop = scrollTop;
        if (editDraft) {
          const refreshedForm = document.getElementById("drawer-edit-form");
          refreshedForm.hidden = false;
          document.getElementById("drawer-edit-status").value = editDraft.status;
          document.getElementById("drawer-edit-assigned").value = editDraft.assignedTo;
        }
      }
    }
  } catch {
    // Keep the open drawer intact during a temporary refresh failure.
  }
}

function isOverdue(incident) {
  const due = dateValue(incident.slaDeadline);
  return incident.status !== "RESOLVED" && Number.isFinite(due) && due < Date.now();
}

function severityClass(severity) {
  return ({ LOW: "badge-low", MEDIUM: "badge-medium", HIGH: "badge-high", CRITICAL: "badge-critical" })[severity] || "badge-unknown";
}

function statusClass(status) {
  return ({ OPEN: "status-open", IN_PROGRESS: "status-progress", RESOLVED: "status-resolved" })[status] || "status-unknown";
}

function statusLabel(status) {
  return ({ OPEN: "Open", IN_PROGRESS: "In progress", RESOLVED: "Resolved" })[status] || String(status || "Unknown").replaceAll("_", " ");
}

function initials(value) {
  const parts = String(value || "?").trim().split(/\s+/).filter(Boolean);
  return parts.length > 1 ? `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase() : (parts[0] || "?").slice(0, 2).toUpperCase();
}

function dateValue(value) {
  const time = Date.parse(value || "");
  return Number.isFinite(time) ? time : Number.NEGATIVE_INFINITY;
}

function formatTimestamp(value) {
  const time = dateValue(value);
  return Number.isFinite(time) ? new Date(time).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "Time unavailable";
}

function formatShortDate(value) {
  const time = dateValue(value);
  return Number.isFinite(time) ? new Date(time).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" }) : "Date unavailable";
}

function formatShortDateTime(value) {
  const time = dateValue(value);
  return Number.isFinite(time) ? new Date(time).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "Not set";
}

function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
