const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { parseLogBatch } = require("../backend/services/logParserService");
const ruleDetector = require("../backend/services/ruleDetector");
const { detectBruteForceCorrelation } = require("../backend/services/correlationDetector");
const {
  analyzeBatch,
  createDetectionCoordinator,
  DETECTOR_STAGES
} = require("../backend/services/detectionCoordinator");

function structuredFailedLogins(count = 3) {
  return Array.from({ length: count }, (_, index) => JSON.stringify({
    timestamp: `2026-01-01T00:00:0${index}Z`,
    message: "login failed",
    clientIp: "192.0.2.15",
    authentication: { result: "failed" },
    user: "alice"
  })).join("\n");
}

describe("detection coordinator", () => {
  it("runs the raw rule detector independently", async () => {
    const { detection } = await ruleDetector.detectRawRules({ rawInput: "DROP TABLE accounts" });

    assert.equal(detection.status, "threat_detected");
    assert.ok(detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
  });

  it("runs event-aware rule detection independently", () => {
    const { detection } = ruleDetector.detectEventAwareRules({
      detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] },
      events: [{ eventId: "evt-1", http: { body: "DROP TABLE accounts" } }]
    });

    assert.equal(detection.status, "threat_detected");
    assert.ok(detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
  });

  it("runs structured BF_001 correlation independently", async () => {
    const batch = parseLogBatch(structuredFailedLogins());
    const { detection: rawDetection } = await ruleDetector.detectRawRules({ rawInput: batch.rawInput });
    const { detection } = detectBruteForceCorrelation({
      rawInput: batch.rawInput,
      events: batch.events,
      detection: rawDetection
    });

    const bruteForce = detection.matchedRules.find((rule) => rule.id === "BF_001");
    assert.equal(bruteForce.count, 3);
    assert.deepEqual(bruteForce.eventIds, batch.events.map((event) => event.eventId));
  });

  it("preserves raw detection and creates the existing Finding shape", async () => {
    const result = await analyzeBatch(parseLogBatch("DROP TABLE accounts"));

    assert.equal(result.detection.status, "threat_detected");
    assert.equal(result.detection.severity, "CRITICAL");
    assert.ok(result.detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
    assert.deepEqual(result.findings.map((finding) => finding.ruleId), ["SQLI_003"]);
    assert.equal(result.findings[0].severity, "CRITICAL");
    assert.ok(result.findings[0].findingId.startsWith("FIND-"));
  });

  it("preserves event-aware-only results", async () => {
    const batch = {
      rawInput: "ordinary request",
      events: [{ eventId: "evt-body", http: { body: "DROP TABLE accounts" } }]
    };
    const result = await analyzeBatch(batch);

    assert.ok(result.detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
    assert.equal(result.findings[0].eventIds[0], "evt-body");
  });

  it("preserves BF_001 correlation and Finding evidence", async () => {
    const batch = parseLogBatch(structuredFailedLogins());
    const result = await analyzeBatch(batch);
    const finding = result.findings.find((item) => item.ruleId === "BF_001");

    assert.equal(result.detection.status, "threat_detected");
    assert.equal(finding.count, 3);
    assert.equal(finding.eventIds.length, 3);
    assert.equal(finding.evidence.length, 3);
  });

  it("returns a clean result and no findings when nothing matches", async () => {
    const result = await analyzeBatch(parseLogBatch("ordinary application activity"));

    assert.deepEqual(result.detection, {
      status: "clean",
      type: "None",
      severity: "LOW",
      matchedRules: []
    });
    assert.deepEqual(result.findings, []);
  });

  it("preserves empty-input validation from the raw detector", async () => {
    await assert.rejects(
      analyzeBatch(parseLogBatch("")),
      { statusCode: 400, message: "Logs must be a non-empty string" }
    );
  });

  it("propagates detector errors instead of reporting a clean result", async () => {
    const detectorError = new Error("detector unavailable");
    const coordinator = createDetectionCoordinator([
      { name: "failing-test-detector", detect: async () => { throw detectorError; } }
    ]);

    await assert.rejects(coordinator.analyzeBatch(parseLogBatch("ordinary activity")), (error) => error === detectorError);
  });

  it("supports finding candidates without forcing them to have a rule ID", async () => {
    const coordinator = createDetectionCoordinator([
      {
        name: "test-behavior-detector",
        detect: async () => ({
          detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] },
          findingCandidates: [{
            type: "High Request Volume",
            severity: "HIGH",
            summary: "Client exceeded the request threshold",
            count: 12,
            eventIds: ["evt-12"]
          }]
        })
      }
    ]);

    const result = await coordinator.analyzeBatch(parseLogBatch("ordinary activity"));

    assert.equal(result.detection.status, "threat_detected");
    assert.equal(result.detection.severity, "HIGH");
    assert.equal(result.findings.length, 1);
    assert.equal(Object.hasOwn(result.findings[0], "ruleId"), false);
    assert.equal(result.findings[0].summary, "Client exceeded the request threshold");
  });

  it("keeps a behavioral finding alongside an independent rule finding", async () => {
    const coordinator = createDetectionCoordinator([
      {
        name: "test-rule-detector",
        detect: async () => ({
          detection: {
            status: "threat_detected",
            type: "SQL Injection",
            severity: "CRITICAL",
            matchedRules: [{ id: "SQLI_003", type: "SQL Injection", severity: "CRITICAL", count: 1 }]
          }
        })
      },
      {
        name: "test-behavior-detector",
        detect: async () => ({ findingCandidates: [{
          detectorType: "behavioral",
          detectorId: "request-volume",
          type: "High Request Volume",
          severity: "MEDIUM",
          summary: "Client exceeded the HTTP request threshold",
          count: 20,
          eventIds: ["evt-20"]
        }] })
      }
    ]);

    const result = await coordinator.analyzeBatch(parseLogBatch("routine request"));
    assert.ok(result.findings.some((finding) => finding.ruleId === "SQLI_003"));
    assert.ok(result.findings.some((finding) => finding.detectorId === "request-volume"));
    assert.equal(result.detection.status, "threat_detected");
  });

  it("runs detector stages in the registered deterministic order", async () => {
    const order = [];
    const coordinator = createDetectionCoordinator([
      { name: "first", detect: async () => { order.push("first"); return { detection: { matchedRules: [] } }; } },
      { name: "second", detect: async ({ detection }) => { order.push("second"); return { detection }; } }
    ]);

    await coordinator.analyzeBatch(parseLogBatch("ordinary activity"));
    assert.deepEqual(order, ["first", "second"]);
    assert.deepEqual(DETECTOR_STAGES.map((stage) => stage.name), [
      "raw-rules",
      "bf001-correlation",
      "event-aware-rules",
      "behavioral"
    ]);
  });
});
