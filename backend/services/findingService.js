const { randomUUID } = require("crypto");

function createFindings(detection) {
  const matchedRules = Array.isArray(detection?.matchedRules) ? detection.matchedRules : [];
  return matchedRules.map((rule) => {
    const evidence = Array.isArray(rule.evidence) ? rule.evidence : [];
    const evidenceEventIds = evidence.map((item) => item?.eventId);
    const eventIds = [...new Set([
      ...(Array.isArray(rule.eventIds) ? rule.eventIds : []),
      ...evidenceEventIds
    ].filter((eventId) => typeof eventId === "string" && eventId.length > 0))];

    return {
      findingId: `FIND-${randomUUID()}`,
      ruleId: rule.id,
      eventIds,
      type: rule.type || "Unknown",
      severity: rule.severity || "MEDIUM",
      summary: rule.description || `${rule.type || "Threat"} detected`,
      count: rule.count,
      detectedAt: new Date().toISOString(),
      evidence
    };
  });
}

module.exports = { createFindings };
