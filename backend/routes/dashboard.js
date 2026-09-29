const express = require("express");
const db = require("../db");
const { computeHealthScore } = require("../utils/healthScore");
const { asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.get("/", asyncHandler(async (req, res) => {
  const incidents = await db.getAllIncidents();
  const total = incidents.length;
  const open = incidents.filter((incident) => incident.status === "OPEN").length;
  const inProgress = incidents.filter((incident) => incident.status === "IN_PROGRESS").length;
  const resolved = incidents.filter((incident) => incident.status === "RESOLVED").length;
  const critical = incidents.filter((incident) => incident.severity === "CRITICAL" && incident.status !== "RESOLVED").length;

  res.json({
    total,
    open,
    inProgress,
    resolved,
    critical,
    healthScore: computeHealthScore(incidents),
    escalatedCount: 0
  });
}));

module.exports = router;
