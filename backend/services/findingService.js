const { randomUUID } = require("crypto");

function createFindingsFromCandidates(candidates) {
  if (!Array.isArray(candidates)) return [];

  return candidates.map((candidate) => {
    const evidence = Array.isArray(candidate.evidence) ? candidate.evidence : [];
    const evidenceEventIds = evidence.map((item) => item?.eventId);
    const eventIds = [...new Set([
      ...(Array.isArray(candidate.eventIds) ? candidate.eventIds : []),
      ...evidenceEventIds
    ].filter((eventId) => typeof eventId === "string" && eventId.length > 0))];

    const finding = {
      findingId: `FIND-${randomUUID()}`,
      eventIds,
      type: candidate.type || "Unknown",
      severity: candidate.severity || "MEDIUM",
      summary: candidate.summary || candidate.description || `${candidate.type || "Threat"} detected`,
      count: candidate.count,
      detectedAt: new Date().toISOString(),
      evidence
    };

    // Rule findings retain their existing identifier. Other detector types
    // can produce findings without pretending to have a rule ID.
    if (typeof candidate.ruleId === "string" && candidate.ruleId) finding.ruleId = candidate.ruleId;
    if (typeof candidate.detectorType === "string" && candidate.detectorType) {
      finding.detectorType = candidate.detectorType;
    }
    if (typeof candidate.detectorId === "string" && candidate.detectorId) {
      finding.detectorId = candidate.detectorId;
    }
    return finding;
  });
}

function createFindings(detection) {
  const matchedRules = Array.isArray(detection?.matchedRules) ? detection.matchedRules : [];
  return createFindingsFromCandidates(matchedRules.map((rule) => ({
    ruleId: rule.id,
    type: rule.type,
    severity: rule.severity,
    description: rule.description,
    count: rule.count,
    eventIds: rule.eventIds,
    evidence: rule.evidence
  })));
}

module.exports = { createFindings, createFindingsFromCandidates };
