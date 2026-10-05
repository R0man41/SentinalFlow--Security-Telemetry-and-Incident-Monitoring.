const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const {
  configureTestCredentials,
  testAdminAuthorization,
  testEventIngestionAuthorization
} = require("./helpers/adminAuth");

const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "event-auth-tests-"));
const incidentsFile = path.join(temporaryDirectory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;
configureTestCredentials();

const app = require("../backend/server");
const normalizer = require("../backend/services/externalEventNormalizer");
const securityAnalysisService = require("../backend/services/securityAnalysisService");
const behavioralDetector = require("../backend/services/behavioralDetector");
const { recentEventStore } = require("../backend/services/recentEventStore");
const createEventIngestionAuth = require("../backend/middleware/eventIngestionAuth").createEventIngestionAuth;

let server;
let baseUrl;

function startServer() {
  return new Promise((resolve, reject) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    listener.once("error", reject);
  });
}

async function stopServer() {
  if (!server) return;
  const current = server;
  server = null;
  if (typeof current.closeAllConnections === "function") current.closeAllConnections();
  await new Promise((resolve, reject) => current.close((error) => error ? reject(error) : resolve()));
}

async function request(body, authorization, { raw = false, query = "" } = {}) {
  const response = await fetch(baseUrl + "/events" + query, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authorization === undefined ? {} : { Authorization: authorization })
    },
    body: raw ? body : JSON.stringify(body)
  });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : null };
}

async function assertNoEventProcessing() {
  assert.equal(recentEventStore.size(), 0);
  assert.equal(recentEventStore.dedupSize(), 0);
  assert.equal(behavioralDetector.activeAlertCount(), 0);
  assert.deepEqual(JSON.parse(await fs.readFile(incidentsFile, "utf8")), []);
}

describe("POST /events Bearer authentication", { concurrency: false }, () => {
  before(async () => {
    server = await startServer();
    baseUrl = "http://127.0.0.1:" + server.address().port;
  });

  beforeEach(async () => {
    recentEventStore.clear();
    behavioralDetector.clearActiveAlerts();
    await fs.writeFile(incidentsFile, "[]\n", "utf8");
  });

  after(async () => {
    await stopServer();
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  });

  it("rejects absent, malformed, wrong, admin, query, and body credentials before event processing", async () => {
    const originalNormalizer = normalizer.createEventBatch;
    const originalAnalysis = securityAnalysisService.analyzeBatch;
    let normalizationCalls = 0;
    let analysisCalls = 0;
    normalizer.createEventBatch = (...args) => {
      normalizationCalls += 1;
      return originalNormalizer(...args);
    };
    securityAnalysisService.analyzeBatch = (...args) => {
      analysisCalls += 1;
      return originalAnalysis(...args);
    };

    const payload = {
      timestamp: "2026-10-04T10:00:00Z",
      source: "caller-controlled-demo",
      externalEventId: "must-not-be-reserved",
      message: "login failed",
      clientIp: "203.0.113.70",
      result: "failed",
      http: { method: "GET", path: "/account" }
    };
    try {
      const results = [
        await request(payload),
        await request(payload, "Basic " + Buffer.from("test-admin:test-only-password").toString("base64")),
        await request(payload, "Bearer"),
        await request(payload, "Bearer wrong-token"),
        await request({ ...payload, token: "test-only-ingestion-token" }),
        await request(payload, undefined, { query: "?token=test-only-ingestion-token" }),
        await request("{", undefined, { raw: true })
      ];

      for (const result of results) {
        assert.equal(result.response.status, 401);
        assert.equal(result.response.headers.get("www-authenticate"), 'Bearer realm="Event Ingestion"');
        assert.deepEqual(result.body, { error: "Authentication required" });
        await assertNoEventProcessing();
      }
      assert.equal(normalizationCalls, 0);
      assert.equal(analysisCalls, 0);
    } finally {
      normalizer.createEventBatch = originalNormalizer;
      securityAnalysisService.analyzeBatch = originalAnalysis;
    }
  });

  it("accepts the ingestion token and preserves completed duplicate and conflict behavior", async () => {
    const event = {
      timestamp: "2026-10-04T10:00:00Z",
      source: "caller-controlled-demo",
      externalEventId: "auth-success-id",
      message: "routine request"
    };
    const first = await request(event, testEventIngestionAuthorization());
    assert.equal(first.response.status, 201);
    assert.equal(first.body.accepted, true);
    assert.equal(first.body.duplicate, false);
    assert.equal(recentEventStore.dedupSize(), 1);

    const duplicate = await request(event, testEventIngestionAuthorization());
    assert.equal(duplicate.response.status, 200);
    assert.equal(duplicate.body.duplicate, true);
    assert.equal(duplicate.body.eventId, first.body.eventId);

    const conflict = await request({ ...event, message: "changed payload" }, testEventIngestionAuthorization());
    assert.equal(conflict.response.status, 409);
    assert.deepEqual(conflict.body, { error: "event_identity_conflict" });
  });

  it("does not let the ingestion token authorize admin routes and keeps health public", async () => {
    const admin = await fetch(baseUrl + "/dashboard", {
      headers: { Authorization: testEventIngestionAuthorization() }
    });
    assert.equal(admin.status, 401);

    const health = await fetch(baseUrl + "/health");
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { message: "API is running" });
  });

  it("fails closed when the ingestion token is not configured", () => {
    for (const middleware of [createEventIngestionAuth(undefined), createEventIngestionAuth("")]) {
      let status;
      let body;
      let continued = false;
      const response = {
        status(code) { status = code; return this; },
        json(value) { body = value; return this; }
      };

      middleware({ get: () => "Bearer test-only-ingestion-token" }, response, () => { continued = true; });
      assert.equal(status, 503);
      assert.deepEqual(body, { error: "Event ingestion authentication is not configured" });
      assert.equal(continued, false);
    }
  });

  it("rejects admin Basic credentials on /events without side effects", async () => {
    const result = await request({
      source: "demo-app",
      externalEventId: "admin-must-not-authorize",
      message: "routine request"
    }, testAdminAuthorization());
    assert.equal(result.response.status, 401);
    assert.deepEqual(result.body, { error: "Authentication required" });
    await assertNoEventProcessing();
  });
});
