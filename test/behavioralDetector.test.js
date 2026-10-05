const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createRecentEventStore } = require("../backend/services/recentEventStore");
const { crossRequestBruteForce } = require("../backend/services/correlationDetector");
const {
  createBehavioralDetector,
  DEFAULT_REQUEST_THRESHOLD,
  DEFAULT_REQUEST_WINDOW_MS,
  REQUEST_THRESHOLD,
  REQUEST_WINDOW_MS
} = require("../backend/services/behavioralDetector");
const findingService = require("../backend/services/findingService");

function requestEvent(index, { clientIp = "203.0.113.20", timestamp, http = { method: "GET", path: "/home" } } = {}) {
  return {
    eventId: `evt-${index}`,
    eventTime: timestamp || new Date(Date.parse("2026-10-04T10:00:00Z") + index * 1000).toISOString(),
    clientIp,
    message: "routine request",
    http
  };
}

function setup(options = {}) {
  const store = createRecentEventStore({ maxEvents: 100 });
  const detector = createBehavioralDetector({ store, threshold: 4, windowMs: 60_000, ...options });
  function process(event, { duplicateStoreInsert = false, stateRollbackActions } = {}) {
    store.add(event, { includeMessage: false });
    if (duplicateStoreInsert) store.add(event, { includeMessage: false });
    return detector.detect({ useRecentEventState: true, events: [event], stateRollbackActions });
  }
  return { store, detector, process };
}

describe("behavioral request-volume detector", () => {
  it("does not create a finding below its fixed threshold", () => {
    const { process } = setup();
    for (let index = 1; index <= 3; index += 1) {
      assert.deepEqual(process(requestEvent(index)).findingCandidates, []);
    }
  });

  it("creates a behavioral finding exactly at threshold with the right events and severity", () => {
    const { process } = setup();
    let result;
    for (let index = 1; index <= 4; index += 1) result = process(requestEvent(index));
    const [candidate] = result.findingCandidates;

    assert.equal(candidate.detectorType, "behavioral");
    assert.equal(candidate.detectorId, "request-volume");
    assert.equal(candidate.count, 4);
    assert.deepEqual(candidate.eventIds, ["evt-1", "evt-2", "evt-3", "evt-4"]);
    assert.equal(candidate.severity, "MEDIUM");
    assert.match(candidate.summary, /203\.0\.113\.20 generated 4 HTTP requests within 60 seconds/);
    assert.ok(candidate.summary.length < 200);
    assert.deepEqual(candidate.evidence, []);

    const [finding] = findingService.createFindingsFromCandidates([candidate]);
    assert.equal(finding.detectorType, "behavioral");
    assert.equal(finding.detectorId, "request-volume");
    assert.equal(finding.ruleId, undefined);
    assert.ok(Number.isFinite(Date.parse(finding.detectedAt)));
  });

  it("suppresses repeat findings while active, then alerts after the rolling count falls below threshold", () => {
    const { process } = setup();
    for (let index = 1; index <= 4; index += 1) process(requestEvent(index));
    assert.deepEqual(process(requestEvent(5)).findingCandidates, []);

    const afterOldWindow = process(requestEvent(6, { timestamp: "2026-10-04T10:01:05.000Z" }));
    assert.deepEqual(afterOldWindow.findingCandidates, []);
    let renewed;
    for (let index = 7; index <= 10; index += 1) {
      const result = process(requestEvent(index, {
        timestamp: new Date(Date.parse("2026-10-04T10:01:05Z") + (index - 6) * 1000).toISOString()
      }));
      if (result.findingCandidates.length) renewed = result;
    }
    assert.ok(renewed);
    assert.equal(renewed.findingCandidates[0].count, 4);
  });

  it("does not roll back suppression refreshed by a concurrent request", () => {
    const { process, detector } = setup();
    for (let index = 1; index <= 3; index += 1) process(requestEvent(index));

    const failedRequestActions = [];
    const thresholdResult = process(requestEvent(4), { stateRollbackActions: failedRequestActions });
    assert.equal(thresholdResult.findingCandidates.length, 1);
    assert.equal(detector.activeAlertCount(), 1);

    const successfulRequestActions = [];
    const suppressedResult = process(requestEvent(5), { stateRollbackActions: successfulRequestActions });
    assert.deepEqual(suppressedResult.findingCandidates, []);
    failedRequestActions[0]();

    assert.equal(detector.activeAlertCount(), 1);
    assert.deepEqual(process(requestEvent(6)).findingCandidates, []);
  });

  it("can restore suppression cleared by a request that later fails", () => {
    const { process, detector } = setup();
    for (let index = 1; index <= 4; index += 1) process(requestEvent(index));
    assert.equal(detector.activeAlertCount(), 1);

    const rollbackActions = [];
    const outsideWindow = process(requestEvent(5, {
      timestamp: "2026-10-04T10:02:00.000Z"
    }), { stateRollbackActions: rollbackActions });
    assert.deepEqual(outsideWindow.findingCandidates, []);
    assert.equal(detector.activeAlertCount(), 0);

    rollbackActions[0]();
    assert.equal(detector.activeAlertCount(), 1);
  });

  it("keeps client IP groups separate", () => {
    const { process } = setup();
    for (let index = 1; index <= 3; index += 1) process(requestEvent(index, { clientIp: "203.0.113.20" }));
    for (let index = 4; index <= 6; index += 1) process(requestEvent(index, { clientIp: "203.0.113.21" }));
    const firstGroup = process(requestEvent(7, { clientIp: "203.0.113.20" }));
    const secondGroup = process(requestEvent(8, { clientIp: "203.0.113.21" }));
    assert.deepEqual(firstGroup.findingCandidates[0].eventIds, ["evt-1", "evt-2", "evt-3", "evt-7"]);
    assert.deepEqual(secondGroup.findingCandidates[0].eventIds, ["evt-4", "evt-5", "evt-6", "evt-8"]);
  });

  it("uses an inclusive rolling-window boundary and excludes events just outside it", () => {
    const atBoundary = setup();
    for (const [index, second] of [[1, 0], [2, 20], [3, 40]]) {
      atBoundary.process(requestEvent(index, { timestamp: `2026-10-04T10:00:${String(second).padStart(2, "0")}Z` }));
    }
    const boundary = atBoundary.process(requestEvent(4, { timestamp: "2026-10-04T10:01:00Z" }));
    assert.equal(boundary.findingCandidates[0].count, 4);

    const outside = setup();
    for (const [index, timestamp] of [
      [1, "2026-10-04T10:00:00Z"],
      [2, "2026-10-04T10:00:20Z"],
      [3, "2026-10-04T10:00:40Z"]
    ]) outside.process(requestEvent(index, { timestamp }));
    const afterBoundary = outside.process(requestEvent(4, { timestamp: "2026-10-04T10:01:00.001Z" }));
    assert.deepEqual(afterBoundary.findingCandidates, []);
  });

  it("ignores missing IPs, invalid or missing times, and events without HTTP request context", () => {
    const { process, detector } = setup();
    for (let index = 1; index <= 4; index += 1) {
      const event = requestEvent(index);
      process({ ...event, clientIp: undefined });
      process({ ...event, eventTime: "invalid" });
      process({ ...event, eventTime: undefined });
      process({ ...event, http: undefined });
      process({ ...event, http: { body: "payload only" } });
    }
    assert.deepEqual(detector.detect({ useRecentEventState: false, events: [requestEvent(99)] }).findingCandidates, []);
    assert.equal(detector.activeAlertCount(), 0);
  });

  it("counts the current event exactly once even if it is already in the recent store twice", () => {
    const { process } = setup();
    for (let index = 1; index <= 3; index += 1) process(requestEvent(index));
    const current = requestEvent(4);
    const result = process(current, { duplicateStoreInsert: true });
    assert.equal(result.findingCandidates[0].count, 4);
    assert.equal(result.findingCandidates[0].eventIds.filter((id) => id === "evt-4").length, 1);
  });

  it("uses the state snapshot captured with the current request before later requests interleave", () => {
    const store = createRecentEventStore();
    const detector = createBehavioralDetector({ store, threshold: 4, windowMs: 60_000 });
    const current = requestEvent(1);
    store.add(requestEvent(0, { timestamp: current.eventTime }), { includeMessage: false });
    store.add(requestEvent(-1, { timestamp: current.eventTime }), { includeMessage: false });
    const currentContext = {
      useRecentEventState: true,
      rawInput: current.message,
      events: [current],
      detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] }
    };
    crossRequestBruteForce(currentContext, store);

    const later = requestEvent(2, { timestamp: current.eventTime });
    store.add(later, { includeMessage: false });
    assert.deepEqual(detector.detect(currentContext).findingCandidates, []);

    const laterContext = {
      ...currentContext,
      rawInput: later.message,
      events: [later]
    };
    crossRequestBruteForce(laterContext, store);
    const result = detector.detect(laterContext);
    assert.equal(result.findingCandidates[0].count, 4);
    assert.deepEqual(result.findingCandidates[0].eventIds, ["evt--1", "evt-0", "evt-1", "evt-2"]);
  });

  it("bounds active suppression keys", () => {
    const { process, detector } = setup({ maxActiveIps: 1 });
    for (let index = 1; index <= 4; index += 1) process(requestEvent(index, { clientIp: "203.0.113.20" }));
    for (let index = 5; index <= 8; index += 1) process(requestEvent(index, { clientIp: "203.0.113.21" }));
    assert.equal(detector.activeAlertCount(), 1);
  });

  it("uses bounded explicit defaults and valid configuration ranges", () => {
    assert.equal(DEFAULT_REQUEST_THRESHOLD, 20);
    assert.equal(DEFAULT_REQUEST_WINDOW_MS, 60_000);
    assert.ok(REQUEST_THRESHOLD >= 4 && REQUEST_THRESHOLD <= 1000);
    assert.ok(REQUEST_WINDOW_MS >= 1000 && REQUEST_WINDOW_MS <= 240_000);
  });
});
