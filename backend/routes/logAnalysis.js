const express = require("express");
const securityAnalysisService = require("../services/securityAnalysisService");
const logParserService = require("../services/logParserService");
const { stripInternalEvidence } = require("../services/eventAwareMatcher");
const { HttpError, asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.post("/", asyncHandler(async (req, res) => {
  const logs = req.body && typeof req.body.logs === "string" ? req.body.logs.trim() : "";
  if (!logs) throw new HttpError(400, "logs field is required and cannot be empty");

  const batch = logParserService.parseLogBatch(logs);
  const { detection, incident } = await securityAnalysisService.analyzeBatch(batch, {
    buildIncidentDescription: ({ matchedSummary }) =>
      `Manual log analysis detected one or more security findings. Matched rules: ${matchedSummary}.`
  });
  res.json({ detection: stripInternalEvidence(detection), incident });
}));

module.exports = router;
