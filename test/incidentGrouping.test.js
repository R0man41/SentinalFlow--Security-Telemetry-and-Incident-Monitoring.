const { after, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const directory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "incident-grouping-"));
const incidentsFile = path.join(directory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;

const db = require("../backend/db");
const incidentService = require("../backend/services/incidentService");
const escalationService = require("../backend/services/escalationService");

const baseTime = Date.parse("2026-10-04T10:00:00.000Z");
let sequence = 0;

function finding(overrides = {}) {
  sequence += 1;
  return {
    findingId: `FIND-${sequence}`,
    type: "SQL Injection",
    severity: "MEDIUM",
    summary: "Suspicious input detected",
    detectedAt: new Date(baseTime + sequence * 1000).toISOString(),
    eventIds: ["EVENT-1"],
    evidence: [{ message: "raw request body must not be persisted" }],
    ...overrides
  };
}

function incidentInput(findings) {
  return {
    title: "Security finding",
    description: "Threat detected.",
    severity: "MEDIUM",
    assignedTo: "Auto-System",
    findings
  };
}

describe("finding to incident grouping", { concurrency: false }, () => {
  beforeEach(async () => {
    sequence = 0;
    await fs.writeFile(incidentsFile, "[]\n");
  });

  after(async () => {
    await fs.rm(directory, { recursive: true, force: true });
  });

  it("creates one incident with compact references for multiple findings and unique event IDs", async () => {
    const first = finding({ ruleId: "SQLI_001", eventIds: ["E1", "E2"] });
    const second = finding({
      type: "High Request Volume",
      severity: "HIGH",
      detectorType: "behavioral",
      detectorId: "request-volume",
      eventIds: ["E2", "E3"]
    });

    const incident = await incidentService.createIncidentFromFindings(incidentInput([first, second]));

    assert.equal((await db.getAllIncidents()).length, 1);
    assert.equal(incident.findingRefs.length, 2);
    assert.deepEqual(incident.eventIds, ["E1", "E2", "E3"]);
    assert.equal(incident.severity, "HIGH");
    assert.equal(incident.findingRefs[0].ruleId, "SQLI_001");
    assert.equal(incident.findingRefs[1].detectorType, "behavioral");
    assert.equal(incident.findingRefs[1].detectorId, "request-volume");
    assert.equal("evidence" in incident.findingRefs[0], false);
    assert.equal(JSON.stringify(incident).includes("raw request body"), false);
  });

  it("groups overlapping event IDs inside the window and at the inclusive boundary", async () => {
    const initial = finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"] });
    const firstIncident = await incidentService.createIncidentFromFindings(incidentInput([initial]));
    const insideWindow = finding({
      detectedAt: new Date(baseTime + 5 * 60 * 1000).toISOString(),
      eventIds: ["E1"]
    });
    const groupedInside = await incidentService.createIncidentFromFindings(incidentInput([insideWindow]));
    const atBoundary = finding({
      detectedAt: new Date(baseTime + 5 * 60 * 1000 + incidentService.GROUPING_WINDOW_MS).toISOString(),
      eventIds: ["E1", "E2"]
    });

    const grouped = await incidentService.createIncidentFromFindings(incidentInput([atBoundary]));

    assert.equal(groupedInside.incidentId, firstIncident.incidentId);
    assert.equal(grouped.incidentId, firstIncident.incidentId);
    assert.equal((await db.getAllIncidents()).length, 1);
    assert.deepEqual(grouped.eventIds, ["E1", "E2"]);
    assert.equal(grouped.findingRefs.length, 3);
    assert.equal(grouped.timeline.at(-1).action, "FINDINGS_ASSOCIATED");
  });

  it("creates another incident outside the window or without event ID overlap", async () => {
    const first = finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"] });
    await incidentService.createIncidentFromFindings(incidentInput([first]));

    const unrelated = finding({ detectedAt: new Date(baseTime + 60_000).toISOString(), eventIds: ["E2"] });
    const secondIncident = await incidentService.createIncidentFromFindings(incidentInput([unrelated]));
    const outsideWindow = finding({
      detectedAt: new Date(baseTime + 60_000 + incidentService.GROUPING_WINDOW_MS + 1).toISOString(),
      eventIds: ["E2"]
    });
    const thirdIncident = await incidentService.createIncidentFromFindings(incidentInput([outsideWindow]));

    assert.notEqual(secondIncident.incidentId, thirdIncident.incidentId);
    assert.equal((await db.getAllIncidents()).length, 3);
  });

  it("does not use same-IP-like context or invent event IDs as grouping fallbacks", async () => {
    const first = finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"], clientIp: "203.0.113.8" });
    const original = await incidentService.createIncidentFromFindings(incidentInput([first]));
    const noIds = finding({ detectedAt: new Date(baseTime + 1000).toISOString(), eventIds: [], clientIp: "203.0.113.8" });
    const other = await incidentService.createIncidentFromFindings(incidentInput([noIds]));

    assert.notEqual(other.incidentId, original.incidentId);
    assert.deepEqual(other.eventIds, []);
    assert.equal(other.findingRefs.length, 1);
    assert.equal((await db.getAllIncidents()).length, 2);
  });

  it("attaches to IN_PROGRESS incidents without lowering severity or changing SLA or escalation", async () => {
    const original = await incidentService.createIncidentFromFindings(incidentInput([
      finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"], severity: "MEDIUM" })
    ]));
    const preservedDeadline = "2026-10-04T11:00:00.000Z";
    await db.updateIncident(original.incidentId, {
      status: "IN_PROGRESS",
      severity: "HIGH",
      escalated: true,
      slaDeadline: preservedDeadline
    });

    const attached = await incidentService.createIncidentFromFindings(incidentInput([
      finding({ detectedAt: new Date(baseTime + 1000).toISOString(), eventIds: ["E1"], severity: "LOW" })
    ]));

    assert.equal(attached.incidentId, original.incidentId);
    assert.equal(attached.status, "IN_PROGRESS");
    assert.equal(attached.severity, "HIGH");
    assert.equal(attached.escalated, true);
    assert.equal(attached.slaDeadline, preservedDeadline);
  });

  it("does not attach to resolved incidents", async () => {
    const original = await incidentService.createIncidentFromFindings(incidentInput([
      finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"] })
    ]));
    await db.updateIncident(original.incidentId, { status: "RESOLVED" });
    const later = await incidentService.createIncidentFromFindings(incidentInput([
      finding({ detectedAt: new Date(baseTime + 1000).toISOString(), eventIds: ["E1"] })
    ]));

    assert.notEqual(later.incidentId, original.incidentId);
    assert.equal((await db.getIncidentById(original.incidentId)).status, "RESOLVED");
    assert.equal((await db.getAllIncidents()).length, 2);
  });

  it("allows incidents with finding context to follow the existing escalation path", async () => {
    const created = await incidentService.createIncidentFromFindings(incidentInput([
      finding({ detectedAt: new Date(baseTime).toISOString(), eventIds: ["E1"], severity: "LOW" })
    ]));
    await db.updateIncident(created.incidentId, { slaDeadline: "2000-01-01T00:00:00.000Z" });

    assert.equal(await escalationService.runEscalationCheck(), 1);
    const escalated = await db.getIncidentById(created.incidentId);
    assert.equal(escalated.severity, "HIGH");
    assert.equal(escalated.escalated, true);
    assert.equal(escalated.findingRefs.length, 1);
    assert.equal(escalated.eventIds[0], "E1");
    assert.equal(escalated.timeline.at(-1).action, "ESCALATED");
  });

  it("bounds finding references and event IDs while preserving the earliest entries", async () => {
    const findings = Array.from({ length: 205 }, (_, index) => finding({
      findingId: `FIND-${String(index + 1).padStart(3, "0")}`,
      detectedAt: new Date(baseTime + index * 1000).toISOString(),
      eventIds: [`EVENT-${String(index + 1).padStart(3, "0")}`]
    }));
    const incident = await incidentService.createIncidentFromFindings(incidentInput(findings));

    assert.equal(incident.findingRefs.length, incidentService.MAX_FINDING_REFS);
    assert.equal(incident.eventIds.length, incidentService.MAX_EVENT_IDS);
    assert.equal(incident.findingRefs[0].findingId, "FIND-001");
    assert.equal(incident.findingRefs.at(-1).findingId, "FIND-050");
    assert.equal(incident.eventIds[0], "EVENT-001");
    assert.equal(incident.eventIds.at(-1), "EVENT-200");
  });
});
