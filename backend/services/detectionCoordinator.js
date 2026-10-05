const ruleDetector = require("./ruleDetector");
const { detectBruteForceCorrelation } = require("./correlationDetector");
const behavioralDetector = require("./behavioralDetector");
const findingService = require("./findingService");

// Rule and correlation detectors run before bounded-state behavioral detection.
const DETECTOR_STAGES = [
  { name: "raw-rules", detect: ruleDetector.detectRawRules },
  { name: "bf001-correlation", detect: detectBruteForceCorrelation },
  { name: "event-aware-rules", detect: ruleDetector.detectEventAwareRules },
  { name: "behavioral", detect: behavioralDetector.detect }
];

function ruleCandidates(detection) {
  const matchedRules = Array.isArray(detection?.matchedRules) ? detection.matchedRules : [];
  return matchedRules.map((rule) => ({
    ruleId: rule.id,
    type: rule.type,
    severity: rule.severity,
    description: rule.description,
    count: rule.count,
    eventIds: rule.eventIds,
    evidence: rule.evidence
  }));
}

function severityWeight(severity) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(severity || "").toUpperCase()] || 0;
}

function createDetectionCoordinator(detectors = DETECTOR_STAGES) {
  async function analyzeBatch(batch, { useRecentEventState = false } = {}) {
    const context = {
      rawInput: batch?.rawInput,
      events: batch?.events,
      detection: undefined,
      findingCandidates: [],
      stateRollbackActions: [],
      useRecentEventState: useRecentEventState === true
    };

    let rolledBack = false;
    function rollbackStateChanges() {
      if (rolledBack) return;
      rolledBack = true;
      for (const rollback of context.stateRollbackActions.splice(0).reverse()) {
        try {
          rollback();
        } catch {
          // Keep the original detector or persistence error intact.
        }
      }
    }

    try {
      for (const detector of detectors) {
        // A detector error must reach the caller; treating it as a clean result
        // could hide a detection failure.
        const result = await detector.detect(context);
        if (result?.detection !== undefined) context.detection = result.detection;
        if (Array.isArray(result?.findingCandidates)) {
          context.findingCandidates.push(...result.findingCandidates);
        }
      }

      const candidates = [...ruleCandidates(context.detection), ...context.findingCandidates];
      const findings = findingService.createFindingsFromCandidates(candidates);
      const highestSeverity = candidates
        .slice()
        .sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity))[0];
      const detection = context.findingCandidates.length && highestSeverity
        ? {
            ...context.detection,
            status: "threat_detected",
            type: highestSeverity.type || "Unknown",
            severity: highestSeverity.severity || "MEDIUM"
          }
        : context.detection;

      return {
        detection,
        findings,
        rollbackStateChanges
      };
    } catch (error) {
      rollbackStateChanges();
      throw error;
    }
  }

  return { analyzeBatch };
}

module.exports = {
  analyzeBatch: createDetectionCoordinator().analyzeBatch,
  createDetectionCoordinator,
  DETECTOR_STAGES
};
