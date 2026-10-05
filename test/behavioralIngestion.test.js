const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { configureTestCredentials, testAdminAuthorization, testEventIngestionAuthorization } = require("./helpers/adminAuth");

const directory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "behavioral-ingestion-"));
const incidentsFile = path.join(directory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;
// These tests exercise multi-event behavioral thresholds rather than API throttling.
process.env.EVENT_RATE_LIMIT_PER_MINUTE = "10000";
process.env.EVENT_RATE_LIMIT_BURST = "10000";
configureTestCredentials();
const app = require("../backend/server");
const { recentEventStore } = require("../backend/services/recentEventStore");
const behavioralDetector = require("../backend/services/behavioralDetector");

let server;
let baseUrl;

async function postHttpEvent(index, clientIp = "203.0.113.30", overrides = {}) {
  const response = await fetch(`${baseUrl}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: testEventIngestionAuthorization() },
    body: JSON.stringify({
      timestamp: new Date(Date.parse("2026-10-04T10:00:00Z") + index * 100).toISOString(),
      source: "demo-app",
      message: "Routine HTTP request",
      clientIp,
      http: { method: "GET", path: "/home" },
      ...overrides
    })
  });
  return { status: response.status, json: await response.json() };
}

function hasBehavioralDetection(result) {
  return result.json.detection.type === "High Request Volume";
}

describe("behavioral request-volume ingestion", { concurrency: false }, () => {
  before(async () => {
    server = await new Promise((resolve, reject) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
      listener.once("error", reject);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  beforeEach(async () => {
    recentEventStore.clear();
    behavioralDetector.clearActiveAlerts();
    await fs.writeFile(incidentsFile, "[]\n");
  });

  after(async () => {
    if (server) {
      server.closeAllConnections?.();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    await fs.rm(directory, { recursive: true, force: true });
  });

  it("creates one medium incident at the threshold and suppresses later requests in that alert window", async () => {
    let twentieth;
    for (let index = 1; index <= 20; index += 1) {
      const result = await postHttpEvent(index);
      assert.equal(result.status, 201);
      if (index < 20) {
        assert.equal(hasBehavioralDetection(result), false);
        assert.equal(result.json.incident, null);
      }
      twentieth = result;
    }

    assert.equal(hasBehavioralDetection(twentieth), true);
    assert.equal(twentieth.json.detection.severity, "MEDIUM");
    assert.ok(twentieth.json.incident);
    assert.equal(twentieth.json.incident.severity, "MEDIUM");
    assert.deepEqual(Object.keys(twentieth.json).sort(), ["accepted", "detection", "eventId", "incident"]);
    assert.equal(twentieth.json.incident.findingRefs[0].detectorId, "request-volume");

    const twentyFirst = await postHttpEvent(21);
    assert.equal(twentyFirst.status, 201);
    assert.equal(hasBehavioralDetection(twentyFirst), false);
    assert.equal(twentyFirst.json.incident, null);

      const incidentsResponse = await fetch(`${baseUrl}/incidents`, {
        headers: { Authorization: testAdminAuthorization() }
      });
    const incidents = await incidentsResponse.json();
    assert.equal(incidentsResponse.status, 200);
    assert.equal(incidents.length, 1);
  });

  it("does not count a retried HTTP request twice toward behavioral detection", async () => {
    for (let index = 1; index <= 19; index += 1) {
      const result = await postHttpEvent(index, "203.0.113.39", { externalEventId: `REQ-${index}` });
      assert.equal(result.json.duplicate, false);
      assert.equal(hasBehavioralDetection(result), false);
    }
    assert.equal(recentEventStore.size(), 19);

    const retry = await postHttpEvent(1, "203.0.113.39", { externalEventId: "REQ-1" });
    assert.equal(retry.status, 200);
    assert.equal(retry.json.duplicate, true);
    assert.equal(recentEventStore.size(), 19);

    const twentieth = await postHttpEvent(20, "203.0.113.39", { externalEventId: "REQ-20" });
    assert.equal(hasBehavioralDetection(twentieth), true);
    assert.equal(recentEventStore.size(), 20);
  });

  it("keeps behavioral request counts independent for different client IPs", async () => {
    for (let index = 1; index <= 10; index += 1) await postHttpEvent(index, "203.0.113.30");
    for (let index = 11; index <= 20; index += 1) await postHttpEvent(index, "203.0.113.31");
    for (let index = 21; index <= 29; index += 1) {
      const a = await postHttpEvent(index, "203.0.113.30");
      const b = await postHttpEvent(index + 100, "203.0.113.31");
      assert.equal(hasBehavioralDetection(a), false);
      assert.equal(hasBehavioralDetection(b), false);
    }
    const aThreshold = await postHttpEvent(30, "203.0.113.30");
    const bThreshold = await postHttpEvent(130, "203.0.113.31");
    assert.equal(hasBehavioralDetection(aThreshold), true);
    assert.equal(hasBehavioralDetection(bThreshold), true);
  });

  it("does not retain untimed HTTP events for timestamp-window behavior", async () => {
    const result = await postHttpEvent(1, "203.0.113.33", { timestamp: undefined });
    assert.equal(result.status, 201);
    assert.equal(hasBehavioralDetection(result), false);
    assert.equal(recentEventStore.size(), 0);
  });

  it("keeps request-volume behavior and BF_001 as separate findings that can share an incident", async () => {
    let third;
    let twentieth;
    for (let index = 1; index <= 20; index += 1) {
      const result = await postHttpEvent(index, "203.0.113.32", {
        message: "Login failed",
        result: "failed"
      });
      if (index === 3) third = result;
      if (index === 20) twentieth = result;
    }

    assert.ok(third.json.detection.matchedRules.some((rule) => rule.id === "BF_001"));
    assert.ok(third.json.incident);
    assert.equal(hasBehavioralDetection(twentieth), true);
    assert.ok(twentieth.json.incident);
    const incidents = await (await fetch(`${baseUrl}/incidents`, {
      headers: { Authorization: testAdminAuthorization() }
    })).json();
    assert.equal(incidents.length, 1);
    assert.ok(incidents[0].title.includes("BF_001"));
    assert.deepEqual(incidents[0].findingRefs.map((reference) => reference.type), ["Brute Force", "High Request Volume"]);
    assert.ok(incidents[0].findingRefs.some((reference) => reference.detectorId === "request-volume"));
  });

  it("keeps manual HTTP log batches outside the stateful behavioral stream", async () => {
    const logs = Array.from({ length: 20 }, (_, index) => JSON.stringify({
      timestamp: new Date(Date.parse("2026-10-04T10:00:00Z") + index * 100).toISOString(),
      message: "routine request",
      clientIp: "203.0.113.40",
      http: { method: "GET", path: "/home" }
    })).join("\n");
    const manualResponse = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: testAdminAuthorization() },
      body: JSON.stringify({ logs })
    });
    const manual = await manualResponse.json();

    assert.equal(manualResponse.status, 200);
    assert.equal(manual.detection.status, "clean");
    assert.equal(recentEventStore.size(), 0);

    for (let index = 1; index < 20; index += 1) {
      const result = await postHttpEvent(index, "203.0.113.40");
      assert.equal(hasBehavioralDetection(result), false);
    }
  });
});
