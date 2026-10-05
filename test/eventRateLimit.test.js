const { after, before, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { configureTestCredentials, testEventIngestionAuthorization } = require("./helpers/adminAuth");

const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "event-rate-limit-"));
const incidentsFile = path.join(temporaryDirectory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;
process.env.EVENT_RATE_LIMIT_PER_MINUTE = "1";
process.env.EVENT_RATE_LIMIT_BURST = "2";
configureTestCredentials();

const app = require("../backend/server");
const eventRateLimit = require("../backend/middleware/eventRateLimit");
const normalizer = require("../backend/services/externalEventNormalizer");
const detectionCoordinator = require("../backend/services/detectionCoordinator");
const incidentService = require("../backend/services/incidentService");
const { recentEventStore } = require("../backend/services/recentEventStore");

let server;
let baseUrl;

before(async () => {
  server = await new Promise((resolve, reject) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    listener.once("error", reject);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await fs.rm(temporaryDirectory, { recursive: true, force: true });
});

function middlewareResult(middleware) {
  const headers = {};
  const result = { continued: false, status: null, body: null, headers };
  const response = {
    set(name, value) { headers[name.toLowerCase()] = value; return this; },
    status(value) { result.status = value; return this; },
    json(value) { result.body = value; return this; }
  };
  middleware({}, response, () => { result.continued = true; });
  return result;
}

describe("POST /events rate limiting", { concurrency: false }, () => {
  it("uses an injectable clock for burst, rejection, and token replenishment", () => {
    let now = 0;
    const limiter = eventRateLimit.createEventRateLimiter({
      ratePerMinute: 2,
      burstCapacity: 2,
      now: () => now
    });

    assert.equal(middlewareResult(limiter).continued, true);
    assert.equal(middlewareResult(limiter).continued, true);
    const rejected = middlewareResult(limiter);
    assert.equal(rejected.status, 429);
    assert.deepEqual(rejected.body, { error: "rate_limit_exceeded" });
    assert.equal(rejected.headers["retry-after"], "30");

    now = 30_000;
    assert.equal(middlewareResult(limiter).continued, true);
  });

  it("uses defaults for invalid config and bounds configured values", () => {
    assert.deepEqual(eventRateLimit.readRateLimitConfig({
      EVENT_RATE_LIMIT_PER_MINUTE: "invalid",
      EVENT_RATE_LIMIT_BURST: "bad"
    }), { ratePerMinute: 120, burstCapacity: 30 });
    assert.deepEqual(eventRateLimit.readRateLimitConfig({
      EVENT_RATE_LIMIT_PER_MINUTE: "20000",
      EVENT_RATE_LIMIT_BURST: "0"
    }), { ratePerMinute: 10000, burstCapacity: 1 });
  });

  it("authenticates before limiting and rejects over-limit requests before parsing or event processing", async () => {
    recentEventStore.clear();
    let normalizationCalls = 0;
    let detectionCalls = 0;
    let incidentCalls = 0;
    const originalNormalize = normalizer.createEventBatch;
    const originalAnalyze = detectionCoordinator.analyzeBatch;
    const originalCreateIncident = incidentService.createIncidentFromFindings;
    normalizer.createEventBatch = (...args) => {
      normalizationCalls += 1;
      return originalNormalize(...args);
    };
    detectionCoordinator.analyzeBatch = (...args) => {
      detectionCalls += 1;
      return originalAnalyze(...args);
    };
    incidentService.createIncidentFromFindings = (...args) => {
      incidentCalls += 1;
      return originalCreateIncident(...args);
    };

    try {
      const invalidAuth = await fetch(`${baseUrl}/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-token" },
        body: "{"
      });
      assert.equal(invalidAuth.status, 401);
      assert.deepEqual(await invalidAuth.json(), { error: "Authentication required" });

      const missingAuth = await fetch(`${baseUrl}/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{"
      });
      assert.equal(missingAuth.status, 401);

      for (let index = 0; index < 2; index += 1) {
        const body = {
          timestamp: new Date().toISOString(),
          source: `different-service-${index}`,
          externalEventId: `rate-limited-event-${index}`,
          message: "ordinary request activity",
          clientIp: `203.0.113.${index + 1}`,
          http: { method: "GET", path: `/resource/${index}` }
        };
        const accepted = await fetch(`${baseUrl}/events`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: testEventIngestionAuthorization() },
          body: JSON.stringify(body)
        });
        assert.equal(accepted.status, 201);
      }

      assert.equal(normalizationCalls, 2);
      assert.equal(detectionCalls, 2);
      const beforeRejected = {
        recentEvents: recentEventStore.size(),
        dedupEntries: recentEventStore.dedupSize(),
        incidentFile: await fs.readFile(incidentsFile, "utf8").catch((error) => error.code === "ENOENT" ? "<missing>" : Promise.reject(error))
      };
      const output = [];
      const originalLog = console.log;
      console.log = (...args) => output.push(args.join(" "));
      let rejected;
      try {
        rejected = await fetch(`${baseUrl}/events`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: testEventIngestionAuthorization() },
          body: '{"message":"rejected-body-secret-marker"'
        });
      } finally {
        console.log = originalLog;
      }

      assert.equal(rejected.status, 429);
      assert.deepEqual(await rejected.json(), { error: "rate_limit_exceeded" });
      const retryAfter = Number(rejected.headers.get("retry-after"));
      assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60);
      assert.equal(normalizationCalls, 2);
      assert.equal(detectionCalls, 2);
      assert.equal(incidentCalls, 0);
      assert.equal(recentEventStore.size(), beforeRejected.recentEvents);
      assert.equal(recentEventStore.dedupSize(), beforeRejected.dedupEntries);
      const incidentFileAfter = await fs.readFile(incidentsFile, "utf8").catch((error) => error.code === "ENOENT" ? "<missing>" : Promise.reject(error));
      assert.equal(incidentFileAfter, beforeRejected.incidentFile);
      const loggedOutput = output.join("\n");
      assert.equal(loggedOutput.includes("test-only-ingestion-token"), false);
      assert.equal(loggedOutput.includes("rejected-body-secret-marker"), false);
    } finally {
      normalizer.createEventBatch = originalNormalize;
      detectionCoordinator.analyzeBatch = originalAnalyze;
      incidentService.createIncidentFromFindings = originalCreateIncident;
    }
  });
});
