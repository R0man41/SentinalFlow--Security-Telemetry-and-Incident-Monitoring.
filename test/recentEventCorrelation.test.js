const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { configureTestCredentials, testAdminAuthorization, testEventIngestionAuthorization } = require("./helpers/adminAuth");

const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "recent-event-correlation-"));
process.env.INCIDENTS_FILE = path.join(temporaryDirectory, "incidents.json");
configureTestCredentials();
const app = require("../backend/server");
const { recentEventStore, MAX_EVENTS } = require("../backend/services/recentEventStore");

let server;
let baseUrl;

function postEvent(overrides = {}) {
  return fetch(`${baseUrl}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: testEventIngestionAuthorization() },
    body: JSON.stringify({
      timestamp: "2026-10-04T10:00:00Z",
      source: "demo-app",
      message: "Login failed",
      clientIp: "203.0.113.10",
      user: "alice",
      result: "failed",
      ...overrides
    })
  }).then(async (response) => ({ status: response.status, json: await response.json() }));
}

function hasBF(result) {
  return result.json.detection.matchedRules.some((rule) => rule.id === "BF_001");
}

async function send(times, shared = {}) {
  const results = [];
  for (const timestamp of times) results.push(await postEvent({ timestamp, ...shared }));
  return results;
}

describe("cross-request BF_001 correlation", { concurrency: false }, () => {
  before(async () => {
    server = await new Promise((resolve, reject) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
      listener.once("error", reject);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  beforeEach(() => recentEventStore.clear());

  after(async () => {
    if (server) {
      server.closeAllConnections?.();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  });

  it("triggers only on the third separate qualifying event and includes that event", async () => {
    const results = await send([
      "2026-10-04T10:00:00Z",
      "2026-10-04T10:01:00Z",
      "2026-10-04T10:03:00Z"
    ]);

    assert.equal(results[0].status, 201);
    assert.equal(results[1].status, 201);
    assert.equal(hasBF(results[0]), false);
    assert.equal(hasBF(results[1]), false);
    assert.equal(hasBF(results[2]), true);
    assert.equal(results[2].json.detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
    assert.ok(results[2].json.incident);
    assert.equal(recentEventStore.size(), 3);
  });

  it("does not mix client IP groups", async () => {
    const first = await postEvent({ timestamp: "2026-10-04T10:00:00Z", clientIp: "203.0.113.10" });
    const second = await postEvent({ timestamp: "2026-10-04T10:01:00Z", clientIp: "203.0.113.11" });
    const third = await postEvent({ timestamp: "2026-10-04T10:02:00Z", clientIp: "203.0.113.10" });
    assert.deepEqual([hasBF(first), hasBF(second), hasBF(third)], [false, false, false]);
  });

  it("honors the inclusive five-minute boundary", async () => {
    const results = await send([
      "2026-10-04T10:00:00Z",
      "2026-10-04T10:02:30Z",
      "2026-10-04T10:05:00Z"
    ]);
    assert.equal(hasBF(results[2]), true);
  });

  it("does not include an event more than five minutes outside the group window", async () => {
    const results = await send([
      "2026-10-04T10:00:00Z",
      "2026-10-04T10:05:00.001Z",
      "2026-10-04T10:05:00.002Z"
    ]);
    assert.equal(hasBF(results[2]), false);
  });

  it("orders out-of-order event timestamps deterministically", async () => {
    const results = await send([
      "2026-10-04T10:02:00Z",
      "2026-10-04T10:00:00Z",
      "2026-10-04T10:01:00Z"
    ]);
    assert.equal(hasBF(results[2]), true);
    assert.equal(results[2].json.detection.matchedRules.find((rule) => rule.id === "BF_001").count, 3);
  });

  it("does not store unrelated, missing-context, or untimed events", async () => {
    await postEvent({ message: "routine health check" });
    await postEvent({ timestamp: "2026-10-04T10:00:00Z", clientIp: undefined });
    await postEvent({ timestamp: undefined });
    assert.equal(recentEventStore.size(), 0);
  });

  it("keeps missing timestamps from qualifying but allows three later valid timed events", async () => {
    await postEvent({ timestamp: undefined });
    const first = await postEvent({ timestamp: "2026-10-04T10:00:00Z" });
    const second = await postEvent({ timestamp: "2026-10-04T10:01:00Z" });
    const third = await postEvent({ timestamp: "2026-10-04T10:02:00Z" });
    assert.equal(hasBF(first), false);
    assert.equal(hasBF(second), false);
    assert.equal(hasBF(third), true);
    assert.equal(recentEventStore.size(), 3);
  });

  it("rejects invalid event timestamps and does not store the rejected event", async () => {
    const invalid = await postEvent({ timestamp: "not-a-time" });
    assert.equal(invalid.status, 400);
    assert.equal(recentEventStore.size(), 0);
  });

  it("suppresses another finding for an already qualifying ongoing group", async () => {
    await send(["2026-10-04T10:00:00Z", "2026-10-04T10:01:00Z", "2026-10-04T10:02:00Z"]);
    const fourth = await postEvent({ timestamp: "2026-10-04T10:03:00Z" });
    assert.equal(hasBF(fourth), false);
    assert.equal(fourth.json.incident, null);
    assert.equal(recentEventStore.size(), 4);
  });

  it("keeps manual analysis isolated from ingestion state in both directions", async () => {
    const manualResponse = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: testAdminAuthorization() },
      body: JSON.stringify({ logs: [0, 1, 2].map((index) => JSON.stringify({
        timestamp: `2026-10-04T10:0${index}:00Z`,
        message: "Login failed",
        clientIp: "203.0.113.10",
        authentication: { result: "failed" }
      })).join("\n") })
    });
    const manual = await manualResponse.json();
    assert.equal(manualResponse.status, 200);
    assert.ok(manual.detection.matchedRules.some((rule) => rule.id === "BF_001"));
    assert.equal(recentEventStore.size(), 0);

    const first = await postEvent({ timestamp: "2026-10-04T10:00:00Z" });
    const second = await postEvent({ timestamp: "2026-10-04T10:01:00Z" });
    assert.equal(hasBF(first), false);
    assert.equal(hasBF(second), false);
    assert.equal(recentEventStore.size(), 2);

    const independentManual = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: testAdminAuthorization() },
      body: JSON.stringify({ logs: "ordinary application event" })
    });
    assert.equal(independentManual.status, 200);
    assert.equal(recentEventStore.size(), 2);
  });

  it("enforces the configured finite maximum in the store", async () => {
    assert.ok(recentEventStore.size() <= MAX_EVENTS);
  });
});
