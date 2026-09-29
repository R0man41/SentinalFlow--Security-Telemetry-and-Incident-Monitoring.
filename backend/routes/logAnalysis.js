const express = require("express");
const incidentService = require("../services/incidentService");
const findingService = require("../services/findingService");
const logAnalysisService = require("../services/logAnalysisService");
const logParserService = require("../services/logParserService");
const {
  evaluateBruteForceContext,
  applyBruteForceContext
} = require("../services/bruteForceCorrelationService");
const {
  matchEventAwareRules,
  mergeEventAwareMatches,
  stripInternalEvidence
} = require("../services/eventAwareMatcher");
const { HttpError, asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.post("/", asyncHandler(async (req, res) => {
  const logs = req.body && typeof req.body.logs === "string" ? req.body.logs.trim() : "";
  if (!logs) throw new HttpError(400, "logs field is required and cannot be empty");

  const batch = logParserService.parseLogBatch(logs);
  const rawDetection = await logAnalysisService.analyzeLogs(batch.rawInput);
  const bfContext = evaluateBruteForceContext(batch.rawInput, batch.events);
  const contextAwareDetection = applyBruteForceContext(rawDetection, bfContext);
  const eventMatches = matchEventAwareRules(batch.events);
  const detection = mergeEventAwareMatches(contextAwareDetection, eventMatches);
  const findings = findingService.createFindings(detection);
  let incident = null;
  if (detection.status === "threat_detected") {
    const matchedSummary = findings.map((finding) => `${finding.ruleId} (${finding.type})`).join(", ") || "none";
    const description = `Threat detected in logs. Type: ${detection.type}. Severity: ${detection.severity}. Matched rules: ${matchedSummary}. Snippet: ${logs
      .slice(0, 200)
      .replace(/\s+/g, " ")
      .trim()}${logs.length > 200 ? "..." : ""}`;

    incident = await incidentService.createIncident({
      title: `${detection.type || "Detected Threat"}${findings[0]?.ruleId ? ` (${findings[0].ruleId})` : ""}`,
      severity: detection.severity || "MEDIUM",
      assignedTo: "Auto-System",
      description
    });
  }
  res.json({ detection: stripInternalEvidence(detection), incident });
}));

module.exports = router;
