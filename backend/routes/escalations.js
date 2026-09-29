const express = require("express");
const escalationService = require("../services/escalationService");
const { asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.post("/run", asyncHandler(async (req, res) => {
  const escalatedCount = await escalationService.runEscalationCheck();
  res.json({ escalatedCount });
}));

module.exports = router;
