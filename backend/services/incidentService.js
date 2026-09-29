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

async function createIncidentInQueue(body) {
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
    updatedAt: now
  };

  return db.createIncident(incident);
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

module.exports = { createIncident, getAllIncidents, getIncidentById, updateIncident, deleteIncident };
