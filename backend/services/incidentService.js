const db = require("../db");
const { generateId } = require("../utils/idGenerator");
const { calculateSLADeadline } = require("../utils/sla");
const { HttpError } = require("../utils/httpError");
const timelineService = require("./timelineService");

const SEVERITIES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const STATUSES = new Set(["OPEN", "IN_PROGRESS", "RESOLVED"]);
const INCIDENT_ID_PATTERN = /^INC-\d{4}-\d{4,}$/;
const CREATE_FIELDS = new Set(["title", "description", "severity", "assignedTo"]);
const UPDATE_FIELDS = new Set(["status", "assignedTo", "by"]);
const GROUPING_WINDOW_MS = 30 * 60 * 1000;
const MAX_FINDING_REFS = 50;
const MAX_EVENT_IDS = 200;
const MAX_FINDING_SUMMARY_LENGTH = 500;
let createQueue = Promise.resolve();

function requireObject(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Request body must be a JSON object");
  }
}

function requireText(value, field) {
  if (typeof value !== "string" || !value.trim()) {
    throw new HttpError(400, `${field} must be a non-empty string`);
  }
  return value.trim();
}

function validateId(id) {
  if (!INCIDENT_ID_PATTERN.test(id)) throw new HttpError(400, "Invalid incident ID");
}

function createIncident(body) {
  const result = createQueue.then(() => createIncidentInQueue(body));
  createQueue = result.catch(() => {});
  return result;
}

async function createIncidentInQueue(body, internalContext = {}) {
  requireObject(body);
  const unexpected = Object.keys(body).filter((field) => !CREATE_FIELDS.has(field));
  if (unexpected.length) throw new HttpError(400, `Unsupported create field: ${unexpected[0]}`);

  const title = requireText(body.title, "title");
  const assignedTo = requireText(body.assignedTo, "assignedTo");
  const severity = requireText(body.severity, "severity").toUpperCase();
  if (!SEVERITIES.has(severity)) throw new HttpError(400, "severity must be LOW, MEDIUM, HIGH, or CRITICAL");
  if (body.description !== undefined && typeof body.description !== "string") {
    throw new HttpError(400, "description must be a string");
  }

  const now = new Date().toISOString();
  const allIncidents = await db.getAllIncidents();
  const incidentId = generateId(allIncidents);
  const incident = {
    incidentId,
    title,
    description: body.description || "",
    severity,
    status: "OPEN",
    assignedTo,
    slaDeadline: calculateSLADeadline(severity, now),
    escalated: false,
    timeline: [{ timestamp: now, action: "CREATED", from: null, to: "OPEN", by: assignedTo }],
    createdAt: now,
    updatedAt: now,
    ...internalContext
  };

  return db.createIncident(incident);
}

function normalizedEventIds(values) {
  if (!Array.isArray(values)) return [];
  return [...new Set(values
    .filter((value) => typeof value === "string")
    .map((value) => value.trim())
    .filter((value) => value.length > 0 && value.length <= 128))];
}

function toFindingRef(finding) {
  if (!finding || typeof finding !== "object") return null;
  const findingId = typeof finding.findingId === "string" ? finding.findingId.trim().slice(0, 128) : "";
  if (!findingId) return null;

  const detectedAt = typeof finding.detectedAt === "string" && Number.isFinite(Date.parse(finding.detectedAt))
    ? finding.detectedAt
    : undefined;
  const reference = {
    findingId,
    type: typeof finding.type === "string" ? finding.type.slice(0, 128) : "Unknown",
    severity: SEVERITIES.has(String(finding.severity || "").toUpperCase())
      ? String(finding.severity).toUpperCase()
      : "MEDIUM",
    summary: typeof finding.summary === "string"
      ? finding.summary.slice(0, MAX_FINDING_SUMMARY_LENGTH)
      : "Finding detected"
  };
  if (detectedAt) reference.detectedAt = detectedAt;
  for (const field of ["ruleId", "detectorType", "detectorId"]) {
    if (typeof finding[field] === "string" && finding[field].trim()) {
      reference[field] = finding[field].trim().slice(0, 128);
    }
  }
  return reference;
}

function highestSeverity(...severities) {
  const weight = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  return severities
    .map((severity) => String(severity || "MEDIUM").toUpperCase())
    .filter((severity) => SEVERITIES.has(severity))
    .sort((left, right) => weight[right] - weight[left])[0] || "MEDIUM";
}

function latestFindingTime(findings) {
  const times = findings
    .map((finding) => Date.parse(finding.detectedAt))
    .filter(Number.isFinite);
  return times.length ? Math.max(...times) : null;
}

function lastIncidentFindingTime(incident) {
  const recorded = Date.parse(incident.lastFindingAt || "");
  if (Number.isFinite(recorded)) return recorded;
  return latestFindingTime(Array.isArray(incident.findingRefs) ? incident.findingRefs : []);
}

function prepareFindingBatch(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.map((finding) => ({
    reference: toFindingRef(finding),
    eventIds: normalizedEventIds(finding?.eventIds),
    detectedAt: typeof finding?.detectedAt === "string" && Number.isFinite(Date.parse(finding.detectedAt))
      ? finding.detectedAt
      : undefined,
    severity: String(finding?.severity || "MEDIUM").toUpperCase()
  })).filter((entry) => entry.reference);
}

function findEligibleIncident(incidents, preparedFindings) {
  // Require event IDs on every finding in this analysis. A finding without IDs
  // must not be pulled into an existing case by another finding in its batch.
  if (!preparedFindings.length || preparedFindings.some((entry) => !entry.eventIds.length || !entry.detectedAt)) {
    return null;
  }
  const incomingEventIds = new Set(preparedFindings.flatMap((entry) => entry.eventIds));
  const incomingTime = latestFindingTime(preparedFindings);
  if (incomingTime === null) return null;

  return incidents
    .filter((incident) => incident.status === "OPEN" || incident.status === "IN_PROGRESS")
    .filter((incident) => Array.isArray(incident.eventIds) && incident.eventIds.some((id) => incomingEventIds.has(id)))
    .map((incident) => ({ incident, lastFindingTime: lastIncidentFindingTime(incident) }))
    .filter(({ lastFindingTime }) => {
      if (lastFindingTime === null) return false;
      const difference = incomingTime - lastFindingTime;
      return difference >= 0 && difference <= GROUPING_WINDOW_MS;
    })
    .sort((left, right) => right.lastFindingTime - left.lastFindingTime ||
      right.incident.incidentId.localeCompare(left.incident.incidentId))[0]?.incident || null;
}

function appendUniqueBounded(existing, incoming, maximum) {
  const result = [];
  const seen = new Set();
  for (const value of [...(Array.isArray(existing) ? existing : []), ...incoming]) {
    if (typeof value !== "string" || !value || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
    if (result.length === maximum) break;
  }
  return result;
}

function appendBoundedFindingRefs(existing, incoming) {
  const refs = Array.isArray(existing) ? existing.slice(0, MAX_FINDING_REFS) : [];
  const seen = new Set(refs.map((reference) => reference?.findingId).filter(Boolean));
  for (const reference of incoming) {
    if (seen.has(reference.findingId)) continue;
    seen.add(reference.findingId);
    if (refs.length < MAX_FINDING_REFS) refs.push(reference);
  }
  return refs;
}

function createIncidentFromFindings(input) {
  const result = createQueue.then(() => createOrAttachIncidentInQueue(input));
  createQueue = result.catch(() => {});
  return result;
}

async function createOrAttachIncidentInQueue(input) {
  requireObject(input);
  const preparedFindings = prepareFindingBatch(input.findings);
  const findingRefs = preparedFindings.map((entry) => entry.reference);
  const eventIds = normalizedEventIds(preparedFindings.flatMap((entry) => entry.eventIds));
  const latestFindingAt = latestFindingTime(preparedFindings);
  const allIncidents = await db.getAllIncidents();
  const candidate = findEligibleIncident(allIncidents, preparedFindings);

  if (candidate) {
    const timeline = Array.isArray(candidate.timeline) ? candidate.timeline.slice() : [];
    const associatedAt = new Date().toISOString();
    timeline.push({
      timestamp: associatedAt,
      action: "FINDINGS_ASSOCIATED",
      from: null,
      to: `${findingRefs.length} finding(s) associated`,
      by: "Detection Pipeline"
    });
    return db.updateIncident(candidate.incidentId, {
      findingRefs: appendBoundedFindingRefs(candidate.findingRefs, findingRefs),
      eventIds: appendUniqueBounded(candidate.eventIds, eventIds, MAX_EVENT_IDS),
      lastFindingAt: latestFindingAt === null ? candidate.lastFindingAt : new Date(latestFindingAt).toISOString(),
      severity: highestSeverity(candidate.severity, ...preparedFindings.map((entry) => entry.severity)),
      timeline
      // Deliberately omit slaDeadline and escalated: grouping preserves both.
    });
  }

  const safeRefs = findingRefs.slice(0, MAX_FINDING_REFS);
  const safeEventIds = eventIds.slice(0, MAX_EVENT_IDS);
  const now = new Date().toISOString();
  const fallback = {
    title: input.title,
    description: input.description,
    severity: highestSeverity(input.severity, ...preparedFindings.map((entry) => entry.severity)),
    assignedTo: input.assignedTo
  };
  return createIncidentInQueue(fallback, {
    findingRefs: safeRefs,
    eventIds: safeEventIds,
    ...(latestFindingAt === null ? {} : { lastFindingAt: new Date(latestFindingAt).toISOString() })
  });
}

async function getAllIncidents(query = {}) {
  const severity = query.severity ? String(query.severity).toUpperCase() : "";
  const status = query.status ? String(query.status).toUpperCase() : "";
  if (severity && !SEVERITIES.has(severity)) throw new HttpError(400, "Invalid severity filter");
  if (status && !STATUSES.has(status)) throw new HttpError(400, "Invalid status filter");
  if (query.sort && !["severity", "date"].includes(query.sort)) throw new HttpError(400, "sort must be severity or date");

  let incidents = await db.getAllIncidents();
  if (severity) incidents = incidents.filter((incident) => incident.severity === severity);
  if (status) incidents = incidents.filter((incident) => incident.status === status);

  if (query.sort === "severity") {
    const weight = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    incidents = incidents.slice().sort((a, b) => (weight[b.severity] || 0) - (weight[a.severity] || 0));
  } else if (query.sort === "date") {
    incidents = incidents.slice().sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }
  return incidents;
}

async function getIncidentById(id) {
  validateId(id);
  const incident = await db.getIncidentById(id);
  if (!incident) throw new HttpError(404, "Incident not found");
  return incident;
}

async function updateIncident(id, body) {
  validateId(id);
  requireObject(body);
  const unexpected = Object.keys(body).filter((field) => !UPDATE_FIELDS.has(field));
  if (unexpected.length) throw new HttpError(400, `Unsupported or server-managed update field: ${unexpected[0]}`);
  if (Object.keys(body).length === 0) throw new HttpError(400, "At least one update field is required");
  if (body.status !== undefined) {
    if (typeof body.status !== "string" || !STATUSES.has(body.status.toUpperCase())) {
      throw new HttpError(400, "status must be OPEN, IN_PROGRESS, or RESOLVED");
    }
    body.status = body.status.toUpperCase();
  }
  if (body.assignedTo !== undefined) body.assignedTo = requireText(body.assignedTo, "assignedTo");
  if (body.by !== undefined) body.by = requireText(body.by, "by");

  const existing = await db.getIncidentById(id);
  if (!existing) throw new HttpError(404, "Incident not found");

  if (body.status && body.status !== existing.status) {
    const statusUpdate = await db.updateIncident(id, { status: body.status });
    if (!statusUpdate) throw new HttpError(404, "Incident not found");
    await timelineService.addTimelineEntry(id, "STATUS_CHANGE", existing.status, body.status, body.by || "System");
  }

  const latest = await db.getIncidentById(id);
  if (!latest) throw new HttpError(404, "Incident not found");
  if (body.assignedTo && body.assignedTo !== latest.assignedTo) {
    const assignmentUpdate = await db.updateIncident(id, { assignedTo: body.assignedTo });
    if (!assignmentUpdate) throw new HttpError(404, "Incident not found");
    await timelineService.addTimelineEntry(id, "REASSIGNED", latest.assignedTo, body.assignedTo, body.by || "System");
  }

  const updated = await db.getIncidentById(id);
  if (!updated) throw new HttpError(404, "Incident not found");
  return updated;
}

async function deleteIncident(id) {
  validateId(id);
  const deleted = await db.deleteIncident(id);
  if (!deleted) throw new HttpError(404, "Incident not found");
  return { message: "Incident deleted" };
}

module.exports = {
  GROUPING_WINDOW_MS,
  MAX_FINDING_REFS,
  MAX_EVENT_IDS,
  createIncident,
  createIncidentFromFindings,
  getAllIncidents,
  getIncidentById,
  updateIncident,
  deleteIncident
};
