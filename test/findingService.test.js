const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const findingService = require("../backend/services/findingService");
const logAnalysisService = require("../backend/services/logAnalysisService");
const { parseLogBatch } = require("../backend/services/logParserService");
const {
  matchEventAwareRule,
  matchEventAwareRules,
  mergeEventAwareMatches
} = require("../backend/services/eventAwareMatcher");

const eventAwareInput = [
  '{"timestamp":"2000-01-01T00:00:00Z","message":"request","path":"/\\u002e\\u002e/\\u002e\\u002e/private/file"}',
  '{"message":"second request"}'
].join("\n");

describe("internal Finding model", () => {
  it("constructs a Finding from generic rule metadata without rule-specific behavior", () => {
    const evidence = [
      { eventId: "event-a", excerpt: "bounded excerpt", start: 0, end: 7 },
      { eventId: "event-c", excerpt: "another excerpt", start: 4, end: 9 }
    ];
    const [finding] = findingService.createFindings({ matchedRules: [{
      id: "GENERIC_RULE_001",
      type: "Generic Detection",
      severity: "HIGH",
      count: 4,
      description: "Generic metadata summary",
      eventIds: ["event-a", "event-b"],
      evidence
    }] });

    assert.equal(finding.ruleId, "GENERIC_RULE_001");
    assert.equal(finding.type, "Generic Detection");
    assert.equal(finding.severity, "HIGH");
    assert.equal(finding.count, 4);
    assert.equal(finding.summary, "Generic metadata summary");
    assert.deepEqual(finding.eventIds, ["event-a", "event-b", "event-c"]);
    assert.deepEqual(finding.evidence, evidence);
  });

  it("converts one matched rule into a Finding with the required fields", async () => {
    const detection = await logAnalysisService.analyzeLogs("OR 1=1");
    const [finding] = findingService.createFindings(detection);

    assert.match(finding.findingId, /^FIND-[0-9a-f-]{36}$/i);
    assert.equal(finding.ruleId, "SQLI_001");
    assert.equal(finding.type, "SQL Injection");
    assert.equal(finding.severity, "HIGH");
    assert.equal(finding.count, detection.matchedRules[0].count);
    assert.ok(finding.summary.length > 0);
    assert.ok(Number.isFinite(Date.parse(finding.detectedAt)));
  });

  it("gives legacy-only detections empty event and evidence arrays", async () => {
    const detection = await logAnalysisService.analyzeLogs("OR 1=1");
    const [finding] = findingService.createFindings(detection);
    assert.deepEqual(finding.eventIds, []);
    assert.deepEqual(finding.evidence, []);
  });

  it("carries parser event IDs and evidence for event-aware detections", async () => {
    const batch = parseLogBatch(eventAwareInput);
    const rawDetection = await logAnalysisService.analyzeLogs(batch.rawInput);
    assert.equal(rawDetection.status, "clean");
    const detection = mergeEventAwareMatches(rawDetection, matchEventAwareRules(batch.events));
    const findings = findingService.createFindings(detection);
    const finding = findings.find((item) => item.ruleId === "TRAV_001");

    assert.equal(findings.length, 1);
    assert.deepEqual(finding.eventIds, [batch.events[0].eventId]);
    assert.equal(finding.evidence[0].eventId, batch.events[0].eventId);
    assert.equal(finding.evidence[0].excerpt, batch.events[0].http.path);
    assert.equal(finding.count, detection.matchedRules[0].count);
    assert.equal(finding.detectedAt === batch.events[0].eventTime, false);
  });

  it("packages event IDs and evidence from each event-aware matcher", () => {
    const cases = [
      ["TRAV_001", "/../../private/file"],
      ["TRAV_002", "/etc/passwd"],
      ["PROM_001", "/actuator/metrics"],
      ["CONF_001", "/settings/config.env"]
    ];

    for (const [ruleId, path] of cases) {
      const batch = parseLogBatch([
        JSON.stringify({ message: "request", path }),
        JSON.stringify({ message: "second request" })
      ].join("\n"));
      const ruleMatch = matchEventAwareRule(batch.events, ruleId);
      const [finding] = findingService.createFindings({ matchedRules: [ruleMatch] });

      assert.equal(finding.ruleId, ruleId);
      assert.equal(finding.count, 1);
      assert.deepEqual(finding.eventIds, [batch.events[0].eventId]);
      assert.equal(finding.evidence[0].eventId, batch.events[0].eventId);
      assert.equal(finding.evidence[0].excerpt.length <= 200, true);
    }
  });

  it("keeps one Finding and the raw count while retaining event evidence for an overlap", async () => {
    const input = "GET /../../private/file HTTP/1.1";
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(batch.rawInput);
    const rawCount = rawDetection.matchedRules.find((rule) => rule.id === "TRAV_001").count;
    const merged = mergeEventAwareMatches(rawDetection, matchEventAwareRules(batch.events));
    const findings = findingService.createFindings(merged);
    const traversalFindings = findings.filter((finding) => finding.ruleId === "TRAV_001");

    assert.equal(merged.matchedRules.filter((rule) => rule.id === "TRAV_001").length, 1);
    assert.equal(traversalFindings.length, 1);
    assert.equal(traversalFindings[0].count, rawCount);
    assert.deepEqual(traversalFindings[0].eventIds, [batch.events[0].eventId]);
    assert.equal(traversalFindings[0].evidence.length, 1);
  });

  it("creates one Finding per logical matched rule when multiple rules match", async () => {
    const detection = await logAnalysisService.analyzeLogs("OR 1=1 <script>alert(1)</script>");
    const findings = findingService.createFindings(detection);

    assert.deepEqual(findings.map((finding) => finding.ruleId), ["SQLI_001", "XSS_001"]);
    assert.equal(new Set(findings.map((finding) => finding.ruleId)).size, findings.length);
  });

  it("returns no Findings for a clean detection", () => {
    assert.deepEqual(findingService.createFindings({
      status: "clean", type: "None", severity: "LOW", matchedRules: []
    }), []);
  });

  it("generates distinct finding IDs and analysis-time timestamps", async () => {
    const detection = await logAnalysisService.analyzeLogs("OR 1=1 <script>alert(1)</script>");
    const before = Date.now();
    const findings = findingService.createFindings(detection);
    const after = Date.now();

    assert.equal(new Set(findings.map((finding) => finding.findingId)).size, findings.length);
    for (const finding of findings) {
      const detectedAt = Date.parse(finding.detectedAt);
      assert.ok(detectedAt >= before && detectedAt <= after);
    }

    const batch = parseLogBatch(eventAwareInput);
    const eventDetection = mergeEventAwareMatches(
      await logAnalysisService.analyzeLogs(batch.rawInput),
      matchEventAwareRules(batch.events)
    );
    const [eventFinding] = findingService.createFindings(eventDetection);
    assert.notEqual(eventFinding.detectedAt, batch.events[0].eventTime);
  });
});
