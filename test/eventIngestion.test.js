const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { configureTestCredentials, testAdminAuthorization, testEventIngestionAuthorization } = require("./helpers/adminAuth");
const { MAX_HTTP_BODY_BYTES_PER_EVENT } = require("../backend/services/logParserService");

const tempDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "event-ingestion-tests-"));
const dataFile = path.join(tempDirectory, "incidents.json");
const originalIncidentsFile = process.env.INCIDENTS_FILE;
process.env.INCIDENTS_FILE = dataFile;
// Keep this broad pipeline suite focused on ingestion behavior; rate-limit boundaries
// have their own isolated tests with deliberately small values.
process.env.EVENT_RATE_LIMIT_PER_MINUTE = "10000";
process.env.EVENT_RATE_LIMIT_BURST = "10000";
configureTestCredentials();

const app = require("../backend/server");
const normalizer = require("../backend/services/externalEventNormalizer");
const securityAnalysisService = require("../backend/services/securityAnalysisService");
const detectionCoordinator = require("../backend/services/detectionCoordinator");
const incidentService = require("../backend/services/incidentService");
const behavioralDetector = require("../backend/services/behavioralDetector");
const { REQUEST_THRESHOLD } = behavioralDetector;
const { recentEventStore } = require("../backend/services/recentEventStore");

let server;
let baseUrl;

function startServer() {
  return new Promise((resolve, reject) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    listener.once("error", reject);
  });
}

async function request(body, { raw = false } = {}) {
  const response = await fetch(`${baseUrl}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: testEventIngestionAuthorization() },
    body: raw ? body : JSON.stringify(body)
  });
  const text = await response.text();
  return { response, text, json: text ? JSON.parse(text) : null };
}

function minimumEvent(overrides = {}) {
  return { source: "demo-app", message: "HTTP request", ...overrides };
}

async function readStoredIncidents() {
  try {
    return JSON.parse(await fs.readFile(dataFile, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

describe("external event normalization", () => {
  it("creates a one-event batch with server-generated IDs and ingestion time", () => {
    const batch = normalizer.createEventBatch(minimumEvent());

    assert.match(batch.batchId, /^LOG-BATCH-/);
    assert.ok(Number.isFinite(Date.parse(batch.receivedAt)));
    assert.equal(batch.rawInput, "HTTP request");
    assert.equal(batch.events.length, 1);
    assert.equal(batch.events[0].eventId, `${batch.batchId}-EVENT-1`);
    assert.equal(Object.hasOwn(batch.events[0], "eventTime"), false);
  });

  it("preserves an optional validated externalEventId separately from the internal eventId", () => {
    const batch = normalizer.createEventBatch(minimumEvent({ externalEventId: " APP-123 " }));
    const [event] = batch.events;

    assert.equal(event.externalEventId, "APP-123");
    assert.match(event.eventId, /^LOG-BATCH-.*-EVENT-1$/);
    assert.notEqual(event.externalEventId, event.eventId);
    assert.equal(normalizer.createEventBatch(minimumEvent({ externalEventId: "x".repeat(128) })).events[0].externalEventId.length, 128);
  });

  it("fingerprints normalized sender fields canonically and excludes internal IDs", () => {
    const first = {
      eventId: "internal-a",
      externalEventId: "sender-1",
      source: { service: "demo-app" },
      message: "request",
      http: { method: "GET", path: "/home" }
    };
    const reordered = {
      http: { path: "/home", method: "GET" },
      message: "request",
      source: { service: "demo-app" },
      externalEventId: "sender-1",
      eventId: "internal-b"
    };

    assert.equal(normalizer.fingerprintExternalEvent(first), normalizer.fingerprintExternalEvent(reordered));
    assert.notEqual(normalizer.fingerprintExternalEvent(first), normalizer.fingerprintExternalEvent({ ...first, message: "changed" }));
  });

  it("maps all core external fields into the existing normalized event model", () => {
    const batch = normalizer.createEventBatch({
      timestamp: "2026-10-04T10:15:00Z",
      source: "demo-app",
      message: "Login failed",
      clientIp: "203.0.113.10",
      user: "alice",
      result: "FAILED"
    });
    const [event] = batch.events;

    assert.equal(event.eventTime, "2026-10-04T10:15:00.000Z");
    assert.deepEqual(event.source, { service: "demo-app" });
    assert.equal(event.message, "Login failed");
    assert.equal(event.rawMessage, "Login failed");
    assert.equal(event.clientIp, "203.0.113.10");
    assert.deepEqual(event.actor, { user: "alice" });
    assert.deepEqual(event.authentication, { result: "failed" });
  });

  it("accepts explicit timezone offsets and normalizes them to UTC", () => {
    const event = normalizer.createEventBatch(minimumEvent({ timestamp: "2026-10-04T10:15:00+05:30" })).events[0];
    assert.equal(event.eventTime, "2026-10-04T04:45:00.000Z");
  });

  it("does not substitute receivedAt when timestamp is absent", () => {
    const batch = normalizer.createEventBatch(minimumEvent());
    assert.ok(batch.receivedAt);
    assert.equal(Object.hasOwn(batch.events[0], "eventTime"), false);
  });

  it("rejects malformed, timezone-less, and trailing-text timestamps", () => {
    for (const timestamp of [
      "2026-99-45T10:15:00Z",
      "2026-10-04T10:15:00",
      "2026-10-04T10:15:00Z trailing text"
    ]) {
      assert.throws(
        () => normalizer.createEventBatch(minimumEvent({ timestamp })),
        { statusCode: 400, message: /valid ISO-8601 timestamp/ }
      );
    }
  });

  it("validates client and destination IP addresses while accepting IPv6", () => {
    assert.equal(normalizer.createEventBatch(minimumEvent({ clientIp: "2001:db8::1" })).events[0].clientIp, "2001:db8::1");
    assert.throws(() => normalizer.createEventBatch(minimumEvent({ clientIp: "not-an-ip" })), { statusCode: 400 });
    assert.throws(() => normalizer.createEventBatch(minimumEvent({ destination: { ip: "999.1.1.1" } })), { statusCode: 400 });
  });

  it("requires source and message", () => {
    for (const input of [{ message: "hello" }, { source: "demo-app" }, { source: " ", message: "hello" }, { source: "demo-app", message: "" }]) {
      assert.throws(() => normalizer.createEventBatch(input), { statusCode: 400 });
    }
  });

  it("rejects empty and control-character external IDs", () => {
    for (const externalEventId of ["", "   ", "APP-\n123", "APP-\u0000"]) {
      assert.throws(() => normalizer.createEventBatch(minimumEvent({ externalEventId })), { statusCode: 400 });
    }
  });

  it("rejects unknown top-level and nested fields, including internal identifiers", () => {
    for (const input of [
      minimumEvent({ randomStuff: true }),
      minimumEvent({ eventId: "client-id" }),
      minimumEvent({ batchId: "client-batch" }),
      minimumEvent({ receivedAt: "2026-01-01T00:00:00Z" }),
      minimumEvent({ rawInput: "untrusted" }),
      minimumEvent({ http: { headers: { authorization: "secret" } } }),
      minimumEvent({ process: { environment: "secret" } }),
      minimumEvent({ destination: { metadata: {} } })
    ]) {
      assert.throws(() => normalizer.createEventBatch(input), { statusCode: 400, message: /Unsupported/ });
    }
  });

  it("rejects oversized values for each external scalar field", () => {
    const cases = [
      ["source", (value) => minimumEvent({ source: value })],
      ["externalEventId", (value) => minimumEvent({ externalEventId: value })],
      ["message", (value) => minimumEvent({ message: value })],
      ["timestamp", (value) => minimumEvent({ timestamp: value })],
      ["clientIp", (value) => minimumEvent({ clientIp: value })],
      ["user", (value) => minimumEvent({ user: value })],
      ["result", (value) => minimumEvent({ result: value })],
      ["http.path", (value) => minimumEvent({ http: { path: value } })],
      ["http.query", (value) => minimumEvent({ http: { query: value } })],
      ["http.url", (value) => minimumEvent({ http: { url: value } })],
      ["http.userAgent", (value) => minimumEvent({ http: { userAgent: value } })],
      ["http.method", (value) => minimumEvent({ http: { method: value } })],
      ["process.name", (value) => minimumEvent({ process: { name: value } })],
      ["process.command", (value) => minimumEvent({ process: { command: value } })],
      ["destination.host", (value) => minimumEvent({ destination: { host: value } })],
      ["destination.ip", (value) => minimumEvent({ destination: { ip: value } })]
    ];

    for (const [field, makeInput] of cases) {
      const limit = normalizer.STRING_LIMITS[field];
      assert.throws(
        () => normalizer.createEventBatch(makeInput("x".repeat(limit + 1))),
        { statusCode: 400, message: new RegExp(field.replace(".", "\\.") + " must not exceed") }
      );
    }
  });

  it("maps supported HTTP fields without decoding or adding arbitrary headers", () => {
    const batch = normalizer.createEventBatch(minimumEvent({
      http: {
        method: "get",
        url: "https://example.test/search?q=%3Cscript%3E",
        path: "/search",
        query: "q=%3Cscript%3E",
        userAgent: "sqlmap",
        body: "payload=%3Cscript%3E"
      }
    }));

    assert.deepEqual(batch.events[0].http, {
      method: "GET",
      url: "https://example.test/search?q=%3Cscript%3E",
      path: "/search",
      query: "q=%3Cscript%3E",
      userAgent: "sqlmap",
      body: "payload=%3Cscript%3E"
    });
  });

  it("reuses the normalized event HTTP body byte limit", () => {
    const accepted = normalizer.createEventBatch(minimumEvent({ http: { body: "x".repeat(MAX_HTTP_BODY_BYTES_PER_EVENT) } }));
    assert.equal(Buffer.byteLength(accepted.events[0].http.body), MAX_HTTP_BODY_BYTES_PER_EVENT);
    assert.throws(
      () => normalizer.createEventBatch(minimumEvent({ http: { body: "x".repeat(MAX_HTTP_BODY_BYTES_PER_EVENT + 1) } })),
      { statusCode: 400, message: /http\.body must not exceed/ }
    );
  });

  it("maps process and destination fields and rejects unsupported HTTP methods", () => {
    const event = normalizer.createEventBatch(minimumEvent({
      process: { name: "node", command: "node worker.js" },
      destination: { ip: "192.0.2.30", host: "api.example.test" }
    })).events[0];
    assert.deepEqual(event.process, { name: "node", command: "node worker.js" });
    assert.deepEqual(event.destination, { ip: "192.0.2.30", host: "api.example.test" });
    assert.throws(() => normalizer.createEventBatch(minimumEvent({ http: { method: "CONNECT" } })), { statusCode: 400 });
  });
});

describe("POST /events", { concurrency: false }, () => {
  beforeEach(() => recentEventStore.clear());
  before(async () => {
    server = await startServer();
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) {
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    if (originalIncidentsFile === undefined) delete process.env.INCIDENTS_FILE;
    else process.env.INCIDENTS_FILE = originalIncidentsFile;
    await fs.rm(tempDirectory, { recursive: true, force: true });
  });

  it("accepts one minimal event and returns only accepted, ID, detection, and incident", async () => {
    const { response, json } = await request(minimumEvent());
    assert.equal(response.status, 201);
    assert.equal(json.accepted, true);
    assert.match(json.eventId, /^LOG-BATCH-.*-EVENT-1$/);
    assert.equal(json.detection.status, "clean");
    assert.equal(json.incident, null);
    assert.deepEqual(Object.keys(json).sort(), ["accepted", "detection", "eventId", "incident"]);
    assert.equal(Object.hasOwn(json, "findings"), false);
    assert.equal(Object.hasOwn(json, "rawInput"), false);
    assert.equal(recentEventStore.dedupSize(), 0);
  });

  it("ignores an exact retry before analysis and returns the original internal ID", async () => {
    const senderEvent = minimumEvent({
      externalEventId: "SQLI-RETRY-1",
      message: "HTTP request",
      clientIp: "203.0.113.82",
      timestamp: "2026-10-04T10:15:00Z",
      http: { method: "POST", path: "/search", body: "DROP TABLE accounts" }
    });
    const beforeIncidents = (await readStoredIncidents()).length;
    let afterFirstIncidents;
    const originalAnalyzeBatch = securityAnalysisService.analyzeBatch;
    let analysisCalls = 0;
    securityAnalysisService.analyzeBatch = (...args) => {
      analysisCalls += 1;
      return originalAnalyzeBatch(...args);
    };
    let first;
    let retry;
    try {
      first = await request(senderEvent);
      assert.equal(first.response.status, 201);
      assert.equal(first.json.duplicate, false);
      assert.equal(recentEventStore.getExternalEventIdentity("demo-app", "SQLI-RETRY-1").state, "COMPLETED");
      assert.ok(first.json.incident);
      assert.notEqual(first.json.eventId, senderEvent.externalEventId);
      const recentCount = recentEventStore.size();
      afterFirstIncidents = await readStoredIncidents();
      assert.equal(afterFirstIncidents.length, beforeIncidents + 1);

      retry = await request(senderEvent);
      assert.equal(recentEventStore.size(), recentCount);
    } finally {
      securityAnalysisService.analyzeBatch = originalAnalyzeBatch;
    }
    assert.equal(retry.response.status, 200);
    assert.deepEqual(retry.json, { accepted: true, duplicate: true, eventId: first.json.eventId });
    const afterRetryIncidents = await readStoredIncidents();
    assert.equal(afterRetryIncidents.length, afterFirstIncidents.length);
    assert.equal(analysisCalls, 1);
    const firstIncidentAfterRetry = afterRetryIncidents.find((incident) => incident.incidentId === first.json.incident.incidentId);
    const firstIncidentAfterDelivery = afterFirstIncidents.find((incident) => incident.incidentId === first.json.incident.incidentId);
    assert.equal(firstIncidentAfterRetry.findingRefs.length, firstIncidentAfterDelivery.findingRefs.length);
  });

  it("returns processing for an identical delivery while the first request is in flight", async () => {
    const senderEvent = minimumEvent({ externalEventId: "CONCURRENT-1", message: "HTTP request" });
    const originalAnalyzeBatch = securityAnalysisService.analyzeBatch;
    let started;
    let release;
    const processingStarted = new Promise((resolve) => { started = resolve; });
    const analysisGate = new Promise((resolve) => { release = resolve; });
    securityAnalysisService.analyzeBatch = async () => {
      started();
      await analysisGate;
      return {
        detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] },
        incident: null
      };
    };

    let firstPromise;
    let second;
    try {
      firstPromise = request(senderEvent);
      await processingStarted;
      const originalIdentity = recentEventStore.getExternalEventIdentity("demo-app", "CONCURRENT-1");
      second = await request(senderEvent);
      assert.equal(second.response.status, 202);
      assert.deepEqual(second.json, { accepted: true, processing: true, eventId: originalIdentity.eventId });

      const conflict = await request({ ...senderEvent, message: "changed content" });
      assert.equal(conflict.response.status, 409);
      assert.deepEqual(conflict.json, { error: "event_identity_conflict" });
    } finally {
      release();
      securityAnalysisService.analyzeBatch = originalAnalyzeBatch;
    }

    const first = await firstPromise;
    assert.equal(first.response.status, 201);
    assert.equal(first.json.duplicate, false);
    assert.equal(recentEventStore.dedupSize(), 1);
    assert.equal(recentEventStore.getExternalEventIdentity("demo-app", "CONCURRENT-1").state, "COMPLETED");
  });

  it("scopes sender IDs by source and treats different IDs as distinct", async () => {
    const first = await request(minimumEvent({ source: "demo-app", externalEventId: "123" }));
    const differentId = await request(minimumEvent({ source: "demo-app", externalEventId: "124" }));
    const differentSource = await request(minimumEvent({ source: "another-app", externalEventId: "123" }));

    assert.equal(first.response.status, 201);
    assert.equal(differentId.response.status, 201);
    assert.equal(differentSource.response.status, 201);
    assert.equal(first.json.duplicate, false);
    assert.equal(differentId.json.duplicate, false);
    assert.equal(differentSource.json.duplicate, false);
    assert.equal(new Set([first.json.eventId, differentId.json.eventId, differentSource.json.eventId]).size, 3);
  });

  it("rejects reused sender IDs when normalized message or event time changes", async () => {
    const first = await request(minimumEvent({ externalEventId: "CONFLICT-1", message: "Login failed" }));
    assert.equal(first.response.status, 201);
    const changedMessage = await request(minimumEvent({ externalEventId: "CONFLICT-1", message: "Login succeeded" }));
    assert.equal(changedMessage.response.status, 409);
    assert.deepEqual(changedMessage.json, { error: "event_identity_conflict" });

    const changedTimestamp = await request(minimumEvent({
      externalEventId: "CONFLICT-1",
      message: "Login failed",
      timestamp: "2026-10-04T10:15:00Z"
    }));
    assert.equal(changedTimestamp.response.status, 409);
    assert.equal(JSON.stringify(changedTimestamp.json).includes("fingerprint"), false);
    const originalRetry = await request(minimumEvent({ externalEventId: "CONFLICT-1", message: "Login failed" }));
    assert.equal(originalRetry.response.status, 200);
    assert.equal(originalRetry.json.duplicate, true);
  });

  it("deduplicates an old out-of-order event time using receipt identity", async () => {
    const oldEvent = minimumEvent({
      externalEventId: "OUT-OF-ORDER-1",
      timestamp: "2026-10-04T10:05:00Z",
      message: "Login failed"
    });
    const first = await request(oldEvent);
    const retry = await request(oldEvent);

    assert.equal(first.response.status, 201);
    assert.equal(retry.response.status, 200);
    assert.equal(retry.json.eventId, first.json.eventId);
  });

  it("routes normalized single events through the shared analysis service", async () => {
    const originalAnalyzeBatch = securityAnalysisService.analyzeBatch;
    let seenBatch;
    securityAnalysisService.analyzeBatch = async (batch) => {
      seenBatch = batch;
      return {
        detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] },
        findings: [],
        incident: null
      };
    };

    try {
      const { response, json } = await request(minimumEvent({ user: "alice", clientIp: "203.0.113.10" }));
      assert.equal(response.status, 201);
      assert.equal(json.eventId, seenBatch.events[0].eventId);
      assert.equal(seenBatch.events.length, 1);
      assert.equal(seenBatch.events[0].clientIp, "203.0.113.10");
      assert.deepEqual(seenBatch.events[0].actor, { user: "alice" });
      assert.ok(seenBatch.batchId);
      assert.ok(seenBatch.receivedAt);
    } finally {
      securityAnalysisService.analyzeBatch = originalAnalyzeBatch;
    }
  });

  it("records an external identity before invoking downstream analysis", async () => {
    const originalAnalyzeBatch = securityAnalysisService.analyzeBatch;
    securityAnalysisService.analyzeBatch = async () => {
      assert.equal(recentEventStore.dedupSize(), 1);
      return {
        detection: { status: "clean", type: "None", severity: "LOW", matchedRules: [] },
        findings: [],
        incident: null
      };
    };

    try {
      const { response, json } = await request(minimumEvent({ externalEventId: "CLAIM-BEFORE-ANALYSIS" }));
      assert.equal(response.status, 201);
      assert.equal(json.duplicate, false);
    } finally {
      securityAnalysisService.analyzeBatch = originalAnalyzeBatch;
    }
  });

  it("marks a detection failure as retryable and completes the retry with the original event ID", async () => {
    const coordinatorAnalyzeBatch = detectionCoordinator.analyzeBatch;
    let calls = 0;
    detectionCoordinator.analyzeBatch = (...args) => {
      calls += 1;
      if (calls === 1) throw new Error("simulated detection failure");
      return coordinatorAnalyzeBatch(...args);
    };

    const event = minimumEvent({ externalEventId: "DETECTION-RETRY", message: "ordinary activity" });
    try {
      const failed = await request(event);
      assert.equal(failed.response.status, 500);
      const failedIdentity = recentEventStore.getExternalEventIdentity("demo-app", "DETECTION-RETRY");
      assert.equal(failedIdentity.state, "FAILED");
      const conflict = await request({ ...event, message: "different after failure" });
      assert.equal(conflict.response.status, 409);
      assert.deepEqual(conflict.json, { error: "event_identity_conflict" });

      const retry = await request(event);
      assert.equal(retry.response.status, 201);
      assert.equal(retry.json.duplicate, false);
      assert.equal(retry.json.eventId, failedIdentity.eventId);
      assert.equal(recentEventStore.getExternalEventIdentity("demo-app", "DETECTION-RETRY").state, "COMPLETED");
    } finally {
      detectionCoordinator.analyzeBatch = coordinatorAnalyzeBatch;
    }
  });

  it("cleans recent-event state after incident persistence failure and permits a same-ID retry", async () => {
    const createIncidentFromFindings = incidentService.createIncidentFromFindings;
    incidentService.createIncidentFromFindings = async () => {
      throw new Error("simulated incident persistence failure");
    };
    const event = minimumEvent({
      externalEventId: "PERSISTENCE-RETRY",
      message: "HTTP request",
      timestamp: "2026-10-04T10:15:00Z",
      clientIp: "203.0.113.91",
      http: { method: "POST", path: "/search", body: "DROP TABLE accounts" }
    });
    const incidentCountBefore = (await readStoredIncidents()).length;

    try {
      const failed = await request(event);
      assert.equal(failed.response.status, 500);
      const failedIdentity = recentEventStore.getExternalEventIdentity("demo-app", "PERSISTENCE-RETRY");
      assert.equal(failedIdentity.state, "FAILED");
      assert.equal(recentEventStore.size(), 0);
      assert.equal((await readStoredIncidents()).length, incidentCountBefore);

      incidentService.createIncidentFromFindings = createIncidentFromFindings;
      const retry = await request(event);
      assert.equal(retry.response.status, 201);
      assert.equal(retry.json.eventId, failedIdentity.eventId);
      assert.ok(retry.json.incident);
      assert.equal(recentEventStore.size(), 1);
      assert.equal(recentEventStore.getRecentEvents()[0].eventId, failedIdentity.eventId);
      assert.equal(recentEventStore.getExternalEventIdentity("demo-app", "PERSISTENCE-RETRY").state, "COMPLETED");
    } finally {
      incidentService.createIncidentFromFindings = createIncidentFromFindings;
    }
  });

  it("rolls back behavioral suppression when persistence fails so the identified retry can alert", async () => {
    const createIncidentFromFindings = incidentService.createIncidentFromFindings;
    const clientIp = "203.0.113.229";
    const startTime = Date.parse("2026-10-04T10:15:00Z");
    const incidentCountBefore = (await readStoredIncidents()).length;
    let persistenceCalls = 0;
    behavioralDetector.clearActiveAlerts();
    incidentService.createIncidentFromFindings = async (input) => {
      persistenceCalls += 1;
      assert.ok(input.findings.some((finding) => finding.detectorId === "request-volume"));
      if (persistenceCalls === 1) throw new Error("simulated behavioral incident persistence failure");
      return createIncidentFromFindings(input);
    };

    function behavioralEvent(index, externalEventId) {
      return minimumEvent({
        source: "behavior-app",
        externalEventId,
        message: "routine request",
        timestamp: new Date(startTime + index).toISOString(),
        clientIp,
        http: { method: "GET", path: "/home" }
      });
    }

    const failedEvent = behavioralEvent(REQUEST_THRESHOLD - 1, "BEHAVIOR-FAILED-THRESHOLD");
    try {
      for (let index = 0; index < REQUEST_THRESHOLD - 1; index += 1) {
        const prior = await request(behavioralEvent(index, `BEHAVIOR-PRIOR-${index}`));
        assert.equal(prior.response.status, 201);
        assert.equal(prior.json.detection.status, "clean");
      }

      const failed = await request(failedEvent);
      assert.equal(failed.response.status, 500);
      assert.equal(recentEventStore.getExternalEventIdentity("behavior-app", "BEHAVIOR-FAILED-THRESHOLD").state, "FAILED");
      assert.equal(recentEventStore.size(), REQUEST_THRESHOLD - 1);
      assert.equal(behavioralDetector.activeAlertCount(), 0);
      assert.equal((await readStoredIncidents()).length, incidentCountBefore);

      const retry = await request(failedEvent);
      assert.equal(retry.response.status, 201);
      assert.equal(retry.json.duplicate, false);
      assert.equal(retry.json.eventId, recentEventStore.getExternalEventIdentity("behavior-app", "BEHAVIOR-FAILED-THRESHOLD").eventId);
      assert.equal(retry.json.detection.type, "High Request Volume");
      assert.ok(retry.json.incident);
      assert.equal(recentEventStore.size(), REQUEST_THRESHOLD);
      assert.equal(behavioralDetector.activeAlertCount(), 1);

      const completedRetry = await request(failedEvent);
      assert.equal(completedRetry.response.status, 200);
      assert.equal(completedRetry.json.duplicate, true);
      assert.equal(recentEventStore.size(), REQUEST_THRESHOLD);
      assert.equal((await readStoredIncidents()).length, incidentCountBefore + 1);

      const subsequent = await request(behavioralEvent(REQUEST_THRESHOLD, "BEHAVIOR-SUPPRESSED-AFTER-SUCCESS"));
      assert.equal(subsequent.response.status, 201);
      assert.equal(subsequent.json.detection.status, "clean");
      assert.equal(subsequent.json.incident, null);
    } finally {
      incidentService.createIncidentFromFindings = createIncidentFromFindings;
      behavioralDetector.clearActiveAlerts();
    }
  });

  it("marks completion before attempting to send the successful response", async () => {
    const express = require("express");
    const originalJson = express.response.json;
    let stateAtResponse;
    express.response.json = function (body) {
      if (body?.duplicate === false) {
        stateAtResponse = recentEventStore.getExternalEventIdentity("demo-app", "COMPLETE-BEFORE-RESPONSE")?.state;
      }
      return originalJson.call(this, body);
    };

    try {
      const result = await request(minimumEvent({ externalEventId: "COMPLETE-BEFORE-RESPONSE" }));
      assert.equal(result.response.status, 201);
      assert.equal(stateAtResponse, "COMPLETED");
    } finally {
      express.response.json = originalJson;
    }
  });

  it("uses event-aware SQLI_003 detection without returning evidence or request contents", async () => {
    const { response, json } = await request(minimumEvent({
      message: "HTTP request",
      http: { method: "POST", path: "/search", body: "DROP TABLE accounts" }
    }));

    assert.equal(response.status, 201);
    assert.ok(json.detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
    assert.ok(json.incident);
    assert.equal(JSON.stringify(json).includes("DROP TABLE accounts"), false);
    assert.equal(JSON.stringify(json).includes("evidence"), false);
  });

  it("uses event-aware SCAN_001 detection from http.userAgent", async () => {
    const { response, json } = await request(minimumEvent({ http: { method: "GET", path: "/login", userAgent: "sqlmap" } }));
    assert.equal(response.status, 201);
    assert.ok(json.detection.matchedRules.some((rule) => rule.id === "SCAN_001"));
  });

  it("does not store sensitive event payloads in the incident description", async () => {
    const secret = "private-marker-should-not-persist";
    const { response, json } = await request(minimumEvent({
      message: `password="${secret}" HTTP request`,
      http: { body: "DROP TABLE accounts" }
    }));

    assert.equal(response.status, 201);
    assert.ok(json.incident);
    assert.equal(json.incident.description.includes(secret), false);
    assert.equal(json.incident.description.includes("DROP TABLE accounts"), false);
    const storedIncidents = JSON.parse(await fs.readFile(dataFile, "utf8"));
    assert.equal(JSON.stringify(storedIncidents).includes(secret), false);
    assert.ok(Array.isArray(storedIncidents[0].eventIds));
  });

  it("correlates failed logins across separate event requests", async () => {
    let last;
    for (let index = 0; index < 3; index += 1) {
      const { response, json } = await request(minimumEvent({
        timestamp: `2026-10-04T10:15:0${index}Z`,
        message: "Login failed",
        clientIp: "203.0.113.10",
        user: "alice",
        result: "failed"
      }));
      assert.equal(response.status, 201);
      if (index < 2) {
        assert.equal(json.detection.status, "clean");
        assert.equal(json.incident, null);
      }
      last = json;
    }
    assert.ok(last.detection.matchedRules.some((rule) => rule.id === "BF_001"));
    assert.ok(last.incident);
  });

  it("does not let a retried failed login increase BF_001 correlation count", async () => {
    const sendLogin = (seconds, externalEventId) => request(minimumEvent({
      externalEventId,
      timestamp: `2026-10-04T10:20:0${seconds}Z`,
      message: "Login failed",
      clientIp: "203.0.113.84",
      user: "alice",
      result: "failed"
    }));

    const first = await sendLogin(0, "LOGIN-1");
    assert.equal(first.json.detection.status, "clean");
    assert.equal(recentEventStore.size(), 1);
    const retry = await sendLogin(0, "LOGIN-1");
    assert.equal(retry.response.status, 200);
    assert.equal(recentEventStore.size(), 1);

    const second = await sendLogin(1, "LOGIN-2");
    assert.equal(second.json.detection.status, "clean");
    assert.equal(recentEventStore.size(), 2);
    const third = await sendLogin(2, "LOGIN-3");
    const bruteForce = third.json.detection.matchedRules.find((rule) => rule.id === "BF_001");
    assert.equal(bruteForce.count, 3);
    assert.equal(recentEventStore.size(), 3);
  });

  it("returns the existing 400 error envelope for validation and malformed JSON", async () => {
    const invalidEvent = await request({ source: "demo-app", message: "hello", extra: "no" });
    assert.equal(invalidEvent.response.status, 400);
    assert.deepEqual(invalidEvent.json, { error: "Unsupported event field: extra" });

    const malformed = await request('{"source":', { raw: true });
    assert.equal(malformed.response.status, 400);
    assert.deepEqual(malformed.json, { error: "Invalid JSON request body" });
  });

  it("uses the existing 413 response for an oversized HTTP request", async () => {
    const tooLarge = JSON.stringify(minimumEvent({ message: "x".repeat(101 * 1024) }));
    const { response, json } = await request(tooLarge, { raw: true });
    assert.equal(response.status, 413);
    assert.deepEqual(json, { error: "Request body is too large" });
  });

  it("keeps the manual log-analysis route available through the shared analysis service", async () => {
    const response = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: testAdminAuthorization() },
      body: JSON.stringify({ logs: "DROP TABLE accounts" })
    });
    const json = await response.json();
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.ok(json.detection.matchedRules.some((rule) => rule.id === "SQLI_003"));
    assert.ok(json.incident);
  });
});
