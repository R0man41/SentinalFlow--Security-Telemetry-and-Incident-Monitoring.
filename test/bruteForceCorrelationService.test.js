const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const logAnalysisService = require("../backend/services/logAnalysisService");
const findingService = require("../backend/services/findingService");
const { parseLogBatch } = require("../backend/services/logParserService");
const {
  BF001_CORRELATION_WINDOW_MS,
  evaluateBruteForceContext,
  applyBruteForceContext
} = require("../backend/services/bruteForceCorrelationService");

const BASE_TIME = Date.parse("2026-01-01T00:00:00.000Z");

function at(offsetMs) {
  return new Date(BASE_TIME + offsetMs).toISOString();
}

function structuredLog(entries) {
  return entries.map(({ clientIp, offsetMs = 0, message = "login failed", result = "failed" }) =>
    JSON.stringify({
      timestamp: at(offsetMs),
      message,
      clientIp,
      authentication: { result }
    })
  ).join("\n");
}

function plainStructuredLog(entries) {
  return entries.map(({ clientIp, offsetMs = 0 }) =>
    `${at(offsetMs)} client_ip=${clientIp} auth_result=failed login failed`
  ).join("\n");
}

async function detectionsFor(logs) {
  const batch = parseLogBatch(logs);
  const rawDetection = batch.rawInput
    ? await logAnalysisService.analyzeLogs(batch.rawInput)
    : { status: "clean", type: "None", severity: "LOW", matchedRules: [] };
  const contextResult = evaluateBruteForceContext(batch.rawInput, batch.events);
  return { batch, rawDetection, contextResult, detection: applyBruteForceContext(rawDetection, contextResult) };
}

describe("BF_001 context-aware correlation", () => {
  it("characterizes the inclusive provisional window for three failures", async () => {
    const cases = [
      { label: "0 seconds", spanMs: 0, formsGroup: true },
      { label: "30 seconds", spanMs: 30_000, formsGroup: true },
      { label: "1 minute", spanMs: 60_000, formsGroup: true },
      { label: "4 minutes", spanMs: 4 * 60_000, formsGroup: true },
      { label: "5 minutes", spanMs: BF001_CORRELATION_WINDOW_MS, formsGroup: true },
      { label: "just over 5 minutes", spanMs: BF001_CORRELATION_WINDOW_MS + 1, formsGroup: false }
    ];

    for (const { label, spanMs, formsGroup } of cases) {
      const logs = structuredLog([
        { clientIp: "10.0.0.1", offsetMs: 0 },
        { clientIp: "10.0.0.1", offsetMs: Math.floor(spanMs / 2) },
        { clientIp: "10.0.0.1", offsetMs: spanMs }
      ]);
      const { contextResult, detection } = await detectionsFor(logs);
      const match = detection.matchedRules.find((rule) => rule.id === "BF_001");

      assert.equal(contextResult.handled, true, `${label}: context should be eligible`);
      assert.equal(Boolean(match), formsGroup, `${label}: qualifying group result`);
      if (formsGroup) assert.equal(match.count, 3, `${label}: all events form one qualifying group`);
    }
  });

  it("characterizes threshold counts from zero through seven as event counts", async () => {
    for (const count of [0, 1, 2, 3, 4, 5, 7]) {
      const logs = plainStructuredLog(Array.from({ length: count }, (_, index) => ({
        clientIp: "10.0.0.1",
        offsetMs: index * 30_000
      })));
      const { contextResult, detection } = await detectionsFor(logs);
      const match = detection.matchedRules.find((rule) => rule.id === "BF_001");

      assert.equal(contextResult.handled, true, `count ${count}: structured context remains eligible`);
      assert.equal(match?.count ?? null, count >= 3 ? count : null, `count ${count}: threshold/count semantics`);
    }
  });

  it("uses the existing threshold for three failures from one source within the window", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1", offsetMs: 0 },
      { clientIp: "10.0.0.1", offsetMs: 60_000 },
      { clientIp: "10.0.0.1", offsetMs: 4 * 60_000 }
    ]);
    const { contextResult, detection } = await detectionsFor(logs);
    const match = detection.matchedRules.find((rule) => rule.id === "BF_001");

    assert.equal(contextResult.handled, true);
    assert.equal(match.count, 3);
    assert.equal(match.evidence.length, 3);
  });

  it("does not combine failures from different sources", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1" },
      { clientIp: "10.0.0.2", offsetMs: 1_000 },
      { clientIp: "10.0.0.3", offsetMs: 2_000 }
    ]);
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(rawDetection.matchedRules.some((rule) => rule.id === "BF_001"));
    assert.equal(contextResult.handled, true);
    assert.equal(contextResult.match, null);
    assert.equal(detection.matchedRules.some((rule) => rule.id === "BF_001"), false);
  });

  it("characterizes same, different, and mixed source identity", async () => {
    const cases = [
      {
        label: "same IP",
        entries: ["10.0.0.1", "10.0.0.1", "10.0.0.1"],
        qualifyingCount: 3
      },
      {
        label: "different IPs",
        entries: ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        qualifyingCount: null
      },
      {
        label: "mixed IPs",
        entries: ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.1"],
        qualifyingCount: 3
      }
    ];

    for (const { label, entries, qualifyingCount } of cases) {
      const logs = structuredLog(entries.map((clientIp, index) => ({ clientIp, offsetMs: index * 1_000 })));
      const { batch, contextResult } = await detectionsFor(logs);

      assert.equal(contextResult.handled, true, `${label}: complete context is eligible`);
      assert.equal(contextResult.match?.count ?? null, qualifyingCount, `${label}: qualifying event count`);
      if (label === "mixed IPs") {
        assert.deepEqual(contextResult.match.eventIds, [
          batch.events[0].eventId,
          batch.events[1].eventId,
          batch.events[4].eventId
        ]);
      }
    }
  });

  it("does not combine same-source failures outside the time window", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1", offsetMs: 0 },
      { clientIp: "10.0.0.1", offsetMs: 3 * 60_000 },
      { clientIp: "10.0.0.1", offsetMs: 6 * 60_000 }
    ]);
    const { contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, true);
    assert.equal(detection.matchedRules.some((rule) => rule.id === "BF_001"), false);
  });

  it("includes a failure exactly on the inclusive five-minute boundary", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1", offsetMs: 0 },
      { clientIp: "10.0.0.1", offsetMs: 2 * 60_000 },
      { clientIp: "10.0.0.1", offsetMs: BF001_CORRELATION_WINDOW_MS }
    ]);
    const { contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, true);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("reports all five qualifying events once and caps evidence at the shared limit", async () => {
    const logs = structuredLog(Array.from({ length: 5 }, (_, index) => ({
      clientIp: "10.0.0.1",
      offsetMs: index * 30_000
    })));
    const { batch, detection } = await detectionsFor(logs);
    const matches = detection.matchedRules.filter((rule) => rule.id === "BF_001");
    const findings = findingService.createFindings(detection).filter((finding) => finding.ruleId === "BF_001");

    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, 5);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].count, 5);
    assert.deepEqual(findings[0].eventIds, batch.events.map((event) => event.eventId));
    assert.equal(findings[0].evidence.length, 5);
    assert.ok(findings[0].evidence.every((item) => item.excerpt.length <= 200));
  });

  it("sums events from each qualifying source group into one logical BF_001 result", async () => {
    const logs = structuredLog([
      ...[0, 1_000, 2_000].map((offsetMs) => ({ clientIp: "10.0.0.1", offsetMs })),
      ...[0, 1_000, 2_000].map((offsetMs) => ({ clientIp: "10.0.0.2", offsetMs }))
    ]);
    const { batch, detection } = await detectionsFor(logs);
    const matches = detection.matchedRules.filter((rule) => rule.id === "BF_001");
    const finding = findingService.createFindings(detection).find((item) => item.ruleId === "BF_001");

    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, 6);
    assert.deepEqual(finding.eventIds, batch.events.map((event) => event.eventId));
    assert.equal(finding.evidence.length, 5);
  });

  it("falls back to the raw detector when client IP context is unavailable", async () => {
    const logs = [
      `${at(0)} login failed`,
      `${at(1_000)} login failed`,
      `${at(2_000)} login failed`
    ].join("\n");
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);

    const [finding] = findingService.createFindings(detection);
    assert.equal(finding.ruleId, "BF_001");
    assert.equal(finding.count, 3);
    assert.deepEqual(finding.eventIds, []);
    assert.deepEqual(finding.evidence, []);
  });

  it("falls back to the raw detector when event timestamps are missing", async () => {
    const logs = [
      "client_ip=10.0.0.1 login failed",
      "client_ip=10.0.0.1 login failed",
      "client_ip=10.0.0.1 login failed"
    ].join("\n");
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("does not fabricate or substitute eventTime when JSON timestamps are missing", async () => {
    const logs = Array.from({ length: 3 }, () => JSON.stringify({
      message: "login failed",
      clientIp: "10.0.0.1",
      authentication: { result: "failed" }
    })).join("\n");
    const batch = parseLogBatch(logs, { receivedAt: "2026-01-01T12:00:00.000Z" });
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(batch.receivedAt, "2026-01-01T12:00:00.000Z");
    assert.ok(batch.events.every((event) => event.eventTime === undefined));
    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("falls back deterministically for invalid JSON event timestamps", async () => {
    const logs = Array.from({ length: 3 }, (_, index) => JSON.stringify({
      timestamp: `not-a-timestamp-${index}`,
      message: "login failed",
      clientIp: "10.0.0.1",
      authentication: { result: "failed" }
    })).join("\n");
    const batch = parseLogBatch(logs, { receivedAt: "2026-01-01T12:00:00.000Z" });
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(batch.parseWarnings.some((warning) => warning.includes("timestamp field")));
    assert.ok(batch.events.every((event) => event.eventTime === undefined));
    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("falls back when JSON events have no authentication result", async () => {
    const logs = Array.from({ length: 3 }, (_, index) => JSON.stringify({
      timestamp: at(index * 1_000),
      message: "login failed",
      clientIp: "10.0.0.1"
    })).join("\n");
    const { batch, rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(batch.events.every((event) => event.authentication === undefined));
    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("uses whole-evaluation fallback when context is partial", async () => {
    const logs = [
      JSON.stringify({ timestamp: at(0), message: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } }),
      JSON.stringify({ timestamp: at(1_000), message: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } }),
      JSON.stringify({ message: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } })
    ].join("\n");
    const { batch, rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(batch.events.slice(0, 2).every((event) => event.eventTime));
    assert.equal(batch.events[2].eventTime, undefined);
    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("falls back when raw and normalized BF_001 match counts disagree", async () => {
    const logs = [
      JSON.stringify({ timestamp: at(0), message: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } }),
      JSON.stringify({ timestamp: at(1_000), message: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } }),
      JSON.stringify({ timestamp: at(2_000), message: "ordinary event", note: "login failed", clientIp: "10.0.0.1", authentication: { result: "failed" } })
    ].join("\n");
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("retains legacy cross-source aggregation when incomplete context forces fallback", async () => {
    const logs = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
      .map((clientIp) => `client_ip=${clientIp} auth_result=failed login failed`)
      .join("\n");
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("falls back when the parser cannot extract authentication information", async () => {
    const logs = [0, 1_000, 2_000].map((offsetMs) =>
      `${at(offsetMs)} client_ip=10.0.0.1 password failed`
    ).join("\n");
    const { batch, rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(batch.events.every((event) => !event.authentication));
    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("does not combine mixed-source failures when no source reaches threshold", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1" },
      { clientIp: "10.0.0.1", offsetMs: 1_000 },
      { clientIp: "10.0.0.2", offsetMs: 2_000 },
      { clientIp: "10.0.0.2", offsetMs: 3_000 }
    ]);
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.ok(rawDetection.matchedRules.some((rule) => rule.id === "BF_001"));
    assert.equal(contextResult.handled, true);
    assert.equal(detection.matchedRules.some((rule) => rule.id === "BF_001"), false);
  });

  it("keeps raw count authoritative while producing one Finding with context evidence", async () => {
    const logs = structuredLog([
      { clientIp: "10.0.0.1", offsetMs: 0 },
      { clientIp: "10.0.0.1", offsetMs: 1_000 },
      { clientIp: "10.0.0.1", offsetMs: 2_000 }
    ]);
    const { batch, rawDetection, detection } = await detectionsFor(logs);
    const rawCount = rawDetection.matchedRules.find((rule) => rule.id === "BF_001").count;
    const bfMatches = detection.matchedRules.filter((rule) => rule.id === "BF_001");
    const bfFindings = findingService.createFindings(detection).filter((finding) => finding.ruleId === "BF_001");

    assert.equal(bfMatches.length, 1);
    assert.equal(bfMatches[0].count, rawCount);
    assert.equal(bfFindings.length, 1);
    assert.equal(bfFindings[0].count, rawCount);
    assert.deepEqual(bfFindings[0].eventIds, batch.events.map((event) => event.eventId));
    assert.equal(bfFindings[0].evidence.length, 3);
  });

  it("falls back when one legacy failure cannot be represented as a structured event", async () => {
    const logs = [
      structuredLog([{ clientIp: "10.0.0.1", offsetMs: 0 }]).split("\n")[0],
      `${at(1_000)} login failed`,
      structuredLog([{ clientIp: "10.0.0.1", offsetMs: 2_000 }]).split("\n")[0]
    ].join("\n");
    const { rawDetection, contextResult, detection } = await detectionsFor(logs);

    assert.equal(contextResult.handled, false);
    assert.equal(detection, rawDetection);
    assert.equal(detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });
});
