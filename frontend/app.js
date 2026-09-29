const AUTO_REFRESH_MS = 10000;

let currentEditId = null;
let currentTimelineId = null;
let refreshTimer = null;
let isSyncing = false;

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  syncData();
  startLiveUpdates();

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      syncData({ silent: true });
    }
  });
});

function bindEvents() {
  document.getElementById("new-incident-btn").addEventListener("click", openCreateForm);
  document.getElementById("create-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitCreateForm();
  });
  document.getElementById("create-cancel-btn").addEventListener("click", hideCreateForm);

  document.getElementById("edit-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitEditForm();
  });
  document.getElementById("edit-cancel-btn").addEventListener("click", hideEditForm);

  document.getElementById("severity-filter").addEventListener("change", () => loadIncidents());
  document.getElementById("status-filter").addEventListener("change", () => loadIncidents());
  document.getElementById("sort-filter").addEventListener("change", () => loadIncidents());
  document.getElementById("analyze-logs-btn").addEventListener("click", submitAnalyzeLogs);
}

function startLiveUpdates() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }

  refreshTimer = setInterval(() => {
    syncData({ silent: true });
  }, AUTO_REFRESH_MS);
}

function isMissingIncidentError(error) {
  const message = String(error?.message || "").toLowerCase();
  return message.includes("not found") || message.includes("does not exist");
}

async function syncData(options = {}) {
  const { silent = false } = options;

  if (isSyncing) {
    return;
  }

  isSyncing = true;

  try {
    await runEscalationCheck();
    await Promise.all([loadDashboard(), loadIncidents()]);
    await refreshTimelineIfOpen();

    if (!silent) {
      document.getElementById("last-refresh").textContent = `Live sync ${new Date().toLocaleTimeString()}`;
    }
  } catch (error) {
    console.error("Live sync failed:", error);
    document.getElementById("last-refresh").textContent = `Sync failed ${new Date().toLocaleTimeString()}`;
  } finally {
    isSyncing = false;
  }
}

async function loadDashboard() {
  const dashboard = await fetchDashboard();
  const healthBanner = document.getElementById("health-banner");
  const score = dashboard.healthScore;

  healthBanner.className = "health-banner reveal";
  if (score.label === "Healthy") {
    healthBanner.classList.add("health-healthy");
  } else if (score.label === "Degraded") {
    healthBanner.classList.add("health-degraded");
  } else if (score.label === "At Risk") {
    healthBanner.classList.add("health-at-risk");
  } else {
    healthBanner.classList.add("health-critical");
  }
  healthBanner.textContent = `System Health: ${score.label} (Score: ${score.value})`;

  document.getElementById("stat-total").textContent = dashboard.total;
  document.getElementById("stat-open").textContent = dashboard.open;
  document.getElementById("stat-critical").textContent = dashboard.critical;
  document.getElementById("stat-resolved").textContent = dashboard.resolved;
  document.getElementById("last-refresh").textContent = `Synced ${new Date().toLocaleTimeString()}`;
}

async function loadIncidents() {
  const filters = {
    severity: document.getElementById("severity-filter").value,
    status: document.getElementById("status-filter").value,
    sort: document.getElementById("sort-filter").value
  };

  const incidents = await fetchIncidents(filters);
  renderIncidents(incidents);
}

function renderIncidents(incidents) {
  const tbody = document.getElementById("incidents-body");
  tbody.innerHTML = "";

  incidents.forEach((incident) => {
    const row = document.createElement("tr");
    row.addEventListener("click", () => showTimeline(incident.incidentId));

    const severityClass = {
      LOW: "badge-low",
      MEDIUM: "badge-medium",
      HIGH: "badge-high",
      CRITICAL: "badge-critical"
    }[incident.severity];

    const statusClass = {
      OPEN: "status-open",
      IN_PROGRESS: "status-in_progress",
      RESOLVED: "status-resolved"
    }[incident.status];

    const overdue = incident.status !== "RESOLVED" && new Date(incident.slaDeadline).getTime() < Date.now();

    row.innerHTML = `
      <td>${incident.incidentId}</td>
      <td>${escapeHtml(incident.title)}</td>
      <td><span class="badge ${severityClass}">${incident.severity}</span></td>
      <td><span class="badge ${statusClass}">${incident.status}</span></td>
      <td>${escapeHtml(incident.assignedTo)}</td>
      <td class="${overdue ? "overdue-sla" : ""}">${formatTimestamp(incident.slaDeadline)}</td>
      <td>
        <button class="btn btn-primary edit-btn">Edit</button>
        <button class="btn btn-danger delete-btn">Delete</button>
      </td>
    `;

    row.querySelector(".edit-btn").addEventListener("click", (event) => {
      event.stopPropagation();
      handleEdit(incident.incidentId);
    });

    row.querySelector(".delete-btn").addEventListener("click", (event) => {
      event.stopPropagation();
      handleDelete(incident.incidentId);
    });

    tbody.appendChild(row);
  });

  if (incidents.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-state">No incidents match current filters.</td>
      </tr>
    `;
  }
}

function openCreateForm() {
  document.getElementById("create-panel").style.display = "block";
}

function hideCreateForm() {
  document.getElementById("create-panel").style.display = "none";
  document.getElementById("create-form").reset();
}

async function submitCreateForm() {
  const payload = {
    title: document.getElementById("create-title").value.trim(),
    description: document.getElementById("create-description").value.trim(),
    severity: document.getElementById("create-severity").value,
    assignedTo: document.getElementById("create-assigned-to").value.trim()
  };

  await createIncident(payload);
  hideCreateForm();
  await syncData();
}

async function submitAnalyzeLogs() {
  const logs = document.getElementById("log-input").value.trim();
  const resultBox = document.getElementById("log-analysis-result");

  if (!logs) {
    return showLogAnalysisError("Please enter logs before analyzing.");
  }

  resultBox.textContent = "Analyzing logs...";
  resultBox.className = "analysis-output";

  try {
    const response = await analyzeLogs(logs);
    renderLogAnalysisResult(response);
    await syncData({ silent: true });
  } catch (err) {
    showLogAnalysisError(err.message || "Unable to analyze logs.");
  }
}

function renderLogAnalysisResult(result) {
  const resultBox = document.getElementById("log-analysis-result");
  const detection = result.detection || {};
  const status = detection.status === "threat_detected" ? "Threat Found" : "Clean";
  const incidentMessage = result.incident
    ? `Incident created: ${result.incident.incidentId}`
    : "No incident created.";

  const ruleCards = (detection.matchedRules || [])
    .map((rule) => `
      <div class="rule-card">
        <div class="rule-header">
          <span class="rule-id">${escapeHtml(rule.id || rule.pattern)}</span>
          <span class="rule-badge">${escapeHtml(rule.type)} • ${escapeHtml(rule.severity)}</span>
        </div>
        <p class="rule-description">${escapeHtml(rule.description || rule.pattern)}</p>
        <p class="rule-pattern"><code>${escapeHtml(rule.pattern)}</code></p>
        <p class="rule-count">Matches: ${rule.count || 1}</p>
      </div>
    `)
    .join("");

  resultBox.innerHTML = `
    <div class="analysis-summary">
      <p><strong>Status:</strong> ${status}</p>
      <p><strong>Threat:</strong> ${escapeHtml(detection.type)}</p>
      <p><strong>Severity:</strong> ${escapeHtml(detection.severity)}</p>
      <p><strong>Incident:</strong> ${escapeHtml(incidentMessage)}</p>
    </div>
    ${ruleCards.length ? `<div class="matched-rules">${ruleCards}</div>` : `<div class="analysis-note">No detection rules matched.</div>`}
  `;
  resultBox.className = "analysis-output analysis-success";
}

function showLogAnalysisError(message) {
  const resultBox = document.getElementById("log-analysis-result");
  resultBox.innerHTML = `<div class="analysis-note">${escapeHtml(message)}</div>`;
  resultBox.className = "analysis-output analysis-error";
}

async function handleEdit(id) {
  try {
    const incident = await fetchIncidentById(id);
    if (!incident) {
      window.alert("This incident no longer exists. The list will refresh now.");
      await syncData({ silent: true });
      return;
    }

    currentEditId = id;

    document.getElementById("edit-status").value = incident.status;
    document.getElementById("edit-assigned-to").value = incident.assignedTo;
    document.getElementById("edit-panel").style.display = "block";
  } catch (error) {
    if (isMissingIncidentError(error)) {
      window.alert("This incident no longer exists. The list will refresh now.");
      await syncData({ silent: true });
      return;
    }
    throw error;
  }
}

function hideEditForm() {
  currentEditId = null;
  document.getElementById("edit-panel").style.display = "none";
  document.getElementById("edit-form").reset();
}

async function submitEditForm() {
  if (!currentEditId) {
    return;
  }

  try {
    const updated = await updateIncident(currentEditId, {
      status: document.getElementById("edit-status").value,
      assignedTo: document.getElementById("edit-assigned-to").value.trim(),
      by: "UI User"
    });

    if (!updated || updated.message === "Incident no longer exists") {
      window.alert("This incident no longer exists. The list will refresh now.");
      hideEditForm();
      await syncData({ silent: true });
      return;
    }
  } catch (error) {
    if (isMissingIncidentError(error)) {
      window.alert("This incident no longer exists. The list will refresh now.");
      hideEditForm();
      await syncData({ silent: true });
      return;
    }
    throw error;
  }

  hideEditForm();
  await syncData();
}

async function handleDelete(id) {
  const confirmed = window.confirm("Are you sure you want to delete this incident?");
  if (!confirmed) {
    return;
  }

  try {
    await deleteIncident(id);
  } catch (error) {
    if (isMissingIncidentError(error)) {
      window.alert("This incident was already removed. Refreshing list.");
      await syncData({ silent: true });
      return;
    }
    throw error;
  }

  if (currentTimelineId === id) {
    currentTimelineId = null;
    document.getElementById("timeline-panel").style.display = "none";
  }

  await syncData();
}

async function showTimeline(id) {
  currentTimelineId = id;

  const incident = await fetchIncidentById(id);
  if (!incident) {
    currentTimelineId = null;
    document.getElementById("timeline-panel").style.display = "none";
    await syncData({ silent: true });
    return;
  }

  const panel = document.getElementById("timeline-panel");

  renderTimelineEntries(incident.timeline || []);
  panel.style.display = "block";
}

async function refreshTimelineIfOpen() {
  if (!currentTimelineId) {
    return;
  }

  try {
    const incident = await fetchIncidentById(currentTimelineId);
    renderTimelineEntries(incident.timeline || []);
  } catch {
    currentTimelineId = null;
    document.getElementById("timeline-panel").style.display = "none";
  }
}

function renderTimelineEntries(entries) {
  const body = document.getElementById("timeline-body");

  if (entries.length === 0) {
    body.innerHTML = "<p class=\"empty-state\">No timeline entries.</p>";
    return;
  }

  body.innerHTML = entries
    .map(
      (entry) =>
        `<div class="timeline-entry">${formatTimestamp(entry.timestamp)} | ${escapeHtml(entry.action)} | ${escapeHtml(entry.from || "-")} → ${escapeHtml(entry.to || "-")} | ${escapeHtml(entry.by || "-")}</div>`
    )
    .join("");
}

function formatTimestamp(value) {
  return new Date(value).toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
