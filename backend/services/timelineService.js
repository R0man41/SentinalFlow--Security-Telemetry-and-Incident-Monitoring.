const db = require("../db");

async function addTimelineEntry(incidentId, action, from, to, by) {
  const validActions = ["CREATED", "STATUS_CHANGE", "REASSIGNED", "ESCALATED"];
  if (!validActions.includes(action)) {
    throw new Error("Invalid timeline action");
  }

  const incident = await db.getIncidentById(incidentId);
  if (!incident) {
    throw new Error("Incident not found");
  }

  const timeline = Array.isArray(incident.timeline) ? incident.timeline : [];
  timeline.push({
    timestamp: new Date().toISOString(),
    action,
    from,
    to,
    by
  });

  return db.updateIncident(incidentId, { timeline });
}

module.exports = { addTimelineEntry };
