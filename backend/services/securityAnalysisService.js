const detectionCoordinator = require("./detectionCoordinator");
const incidentService = require("./incidentService");

async function analyzeBatch(batch, { buildIncidentDescription, useRecentEventState = false } = {}) {
  const analysis = await detectionCoordinator.analyzeBatch(batch, { useRecentEventState });
  const { detection, findings } = analysis;

  try {
    let incident = null;
    if (detection.status === "threat_detected") {
      const matchedSummary = findings
        .map((finding) => finding.ruleId ? `${finding.ruleId} (${finding.type})` : finding.type)
        .join(", ") || "none";
      const description = typeof buildIncidentDescription === "function"
        ? buildIncidentDescription({ detection, findings, matchedSummary })
        : `Threat detected. Type: ${detection.type}. Severity: ${detection.severity}. Findings: ${matchedSummary}.`;

      incident = await incidentService.createIncidentFromFindings({
        title: `${detection.type || "Detected Threat"}${findings[0]?.ruleId ? ` (${findings[0].ruleId})` : ""}`,
        severity: detection.severity || "MEDIUM",
        assignedTo: "Auto-System",
        description,
        findings
      });
    }

    return { detection, findings, incident };
  } catch (error) {
    analysis.rollbackStateChanges?.();
    throw error;
  }
}

module.exports = { analyzeBatch };
