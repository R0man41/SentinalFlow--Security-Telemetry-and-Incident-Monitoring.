const db = require("../db");
const timelineService = require("./timelineService");

let escalationQueue = Promise.resolve();

function runEscalationCheck() {
  const result = escalationQueue.then(runEscalationCheckOnce);
  escalationQueue = result.catch(() => {});
  return result;
}

async function runEscalationCheckOnce() {
  const incidents = await db.getAllIncidents();
  const now = Date.now();

  const breached = incidents.filter((incident) => {
    const isActive = incident.status === "OPEN" || incident.status === "IN_PROGRESS";
    const notEscalated = incident.escalated === false;
    const isBreached = new Date(incident.slaDeadline).getTime() < now;
    return isActive && notEscalated && isBreached;
  });

  for (const incident of breached) {
    let nextSeverity = incident.severity;

    if (incident.severity === "LOW") {
      nextSeverity = "MEDIUM";
    } else if (incident.severity === "MEDIUM") {
      nextSeverity = "HIGH";
    } else if (incident.severity === "HIGH") {
      nextSeverity = "CRITICAL";
    }

    await db.updateIncident(incident.incidentId, {
      severity: nextSeverity,
      escalated: true
    });

    await timelineService.addTimelineEntry(
      incident.incidentId,
      "ESCALATED",
      incident.severity,
      nextSeverity,
      "System"
    );
  }

  return breached.length;
}

module.exports = { runEscalationCheck };
