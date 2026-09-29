const express = require("express");
const incidentService = require("../services/incidentService");
const { asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.post("/", asyncHandler(async (req, res) => {
  res.json(await incidentService.createIncident(req.body));
}));

router.get("/", asyncHandler(async (req, res) => {
  res.json(await incidentService.getAllIncidents(req.query));
}));

router.get("/:id", asyncHandler(async (req, res) => {
  res.json(await incidentService.getIncidentById(req.params.id));
}));

router.put("/:id", asyncHandler(async (req, res) => {
  res.json(await incidentService.updateIncident(req.params.id, req.body));
}));

router.delete("/:id", asyncHandler(async (req, res) => {
  res.json(await incidentService.deleteIncident(req.params.id));
}));

module.exports = router;
