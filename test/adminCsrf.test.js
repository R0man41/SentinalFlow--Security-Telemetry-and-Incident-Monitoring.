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

const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "admin-csrf-tests-"));
const incidentsFile = path.join(temporaryDirectory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;
process.env.PUBLIC_ORIGIN = "https://public.example.test";
configureTestCredentials();

const app = require("../backend/server");
const db = require("../backend/db");
const createAdminOriginGuard = require("../backend/middleware/adminOriginGuard").createAdminOriginGuard;

let server;
let baseUrl;

const fixture = {
  incidentId: "INC-2020-0001",
  title: "CSRF fixture",
  description: "Origin guard test",
  severity: "HIGH",
  status: "OPEN",
  assignedTo: "Test-OnCall",
  slaDeadline: "2000-01-01T00:00:00.000Z",
  escalated: false,
  timeline: [{ timestamp: "2000-01-01T00:00:00.000Z", action: "CREATED", from: null, to: "OPEN", by: "Test-OnCall" }],
  createdAt: "2000-01-01T00:00:00.000Z",
  updatedAt: "2000-01-01T00:00:00.000Z"
};

function startServer() {
  return new Promise((resolve, reject) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    listener.once("error", reject);
  });
}

async function request(method, route, {
  body,
  raw = false,
  contentType = "application/json",
  authorization = testAdminAuthorization(),
  origin,
  secFetchSite
} = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = contentType;
  if (authorization !== undefined) headers.Authorization = authorization;
  if (origin !== undefined) headers.Origin = origin;
  if (secFetchSite !== undefined) headers["Sec-Fetch-Site"] = secFetchSite;
  const response = await fetch(baseUrl + route, {
    method,
    headers,
    ...(body === undefined ? {} : { body: raw ? body : JSON.stringify(body) })
  });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : null };
}

function assertRejected(result) {
  assert.equal(result.response.status, 403);
  assert.deepEqual(result.body, { error: "cross_origin_request" });
}

describe("admin same-origin request protection", { concurrency: false }, () => {
  before(async () => {
    server = await startServer();
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  beforeEach(async () => {
    await fs.writeFile(incidentsFile, "[]\n", "utf8");
  });

  after(async () => {
    if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  });

  it("allows an authenticated same-origin POST /incidents", async () => {
    const result = await request("POST", "/incidents", {
      origin: "https://public.example.test",
      body: { title: "Created", severity: "LOW", assignedTo: "Test" }
    });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.title, "Created");
  });

  it("allows an authenticated same-origin PUT /incidents/:id", async () => {
    await db.createIncident(fixture);
    const result = await request("PUT", `/incidents/${fixture.incidentId}`, {
      origin: "https://public.example.test",
      body: { status: "RESOLVED" }
    });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.status, "RESOLVED");
  });

  it("allows an authenticated same-origin DELETE /incidents/:id", async () => {
    await db.createIncident(fixture);
    const result = await request("DELETE", `/incidents/${fixture.incidentId}`, {
      origin: "https://public.example.test"
    });
    assert.equal(result.response.status, 200);
    assert.equal(await db.getIncidentById(fixture.incidentId), null);
  });

  it("rejects cross-origin incident POST, PUT, and DELETE without changing incident data", async () => {
    await db.createIncident(fixture);

    const create = await request("POST", "/incidents", {
      origin: "https://attacker.example.test",
      body: { title: "Must not create", severity: "LOW", assignedTo: "Attacker" }
    });
    assertRejected(create);

    const update = await request("PUT", `/incidents/${fixture.incidentId}`, {
      origin: "https://attacker.example.test",
      body: { status: "RESOLVED" }
    });
    assertRejected(update);

    const remove = await request("DELETE", `/incidents/${fixture.incidentId}`, {
      origin: "https://attacker.example.test"
    });
    assertRejected(remove);

    assert.deepEqual(await db.getAllIncidents(), [fixture]);
  });

  it("rejects cross-origin malformed JSON before parsing or creating incidents", async () => {
    const result = await request("POST", "/incidents", {
      origin: "https://attacker.example.test",
      body: "{",
      raw: true
    });
    assertRejected(result);
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("rejects cross-origin form-style escalation requests before changing incidents", async () => {
    const overdueIncident = { ...fixture, escalated: false };
    await db.createIncident(overdueIncident);

    const result = await request("POST", "/escalations/run", {
      origin: "https://attacker.example.test",
      secFetchSite: "cross-site",
      contentType: "application/x-www-form-urlencoded",
      body: "run=1",
      raw: true
    });
    assertRejected(result);
    assert.equal((await db.getIncidentById(fixture.incidentId)).escalated, false);
  });

  it("protects POST /analyze-logs before parsing or detection", async () => {
    const result = await request("POST", "/analyze-logs", {
      origin: "https://attacker.example.test",
      body: { logs: "OR 1=1" }
    });
    assertRejected(result);
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("rejects mismatched schemes, ports, null, malformed, and same-site cross-origin values", async () => {
    const origins = [
      "http://public.example.test",
      "https://public.example.test:444",
      "null",
      "not an origin",
      "https://public.example.test/path",
      "https://admin.public.example.test"
    ];

    for (const origin of origins) {
      const result = await request("POST", "/incidents", {
        origin,
        secFetchSite: origin === "https://admin.public.example.test" ? "same-site" : undefined,
        body: { title: "Rejected", severity: "LOW", assignedTo: "Test" }
      });
      assertRejected(result);
    }
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("rejects Sec-Fetch-Site values other than same-origin", async () => {
    for (const secFetchSite of ["same-site", "cross-site", "none", "unknown"]) {
      const result = await request("POST", "/incidents", {
        origin: "https://public.example.test",
        secFetchSite,
        body: { title: "Rejected", severity: "LOW", assignedTo: "Test" }
      });
      assertRejected(result);
    }
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("accepts matching Origin with Sec-Fetch-Site same-origin", async () => {
    const result = await request("POST", "/incidents", {
      origin: "https://public.example.test",
      secFetchSite: "same-origin",
      body: { title: "Same origin", severity: "LOW", assignedTo: "Test" }
    });
    assert.equal(result.response.status, 200);
  });

  it("allows authenticated CLI clients with neither Origin nor Sec-Fetch-Site", async () => {
    const result = await request("POST", "/incidents", {
      body: { title: "CLI", severity: "LOW", assignedTo: "Test" }
    });
    assert.equal(result.response.status, 200);
  });

  it("allows missing Origin with same-origin metadata and rejects same-site or cross-site metadata", async () => {
    const sameOrigin = await request("POST", "/incidents", {
      secFetchSite: "same-origin",
      body: { title: "Same-origin metadata", severity: "LOW", assignedTo: "Test" }
    });
    assert.equal(sameOrigin.response.status, 200);

    await fs.writeFile(incidentsFile, "[]\n", "utf8");
    for (const secFetchSite of ["same-site", "cross-site"]) {
      const rejected = await request("POST", "/incidents", {
        secFetchSite,
        body: { title: "Rejected", severity: "LOW", assignedTo: "Test" }
      });
      assertRejected(rejected);
    }
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("keeps GET admin routes usable and leaves health and event Bearer auth unaffected", async () => {
    await db.createIncident(fixture);
    for (const route of ["/dashboard", "/incidents", `/incidents/${fixture.incidentId}`]) {
      const result = await request("GET", route);
      assert.equal(result.response.status, 200, route);
    }

    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { message: "API is running" });

    const eventResponse = await fetch(`${baseUrl}/events`, {
      method: "POST",
      headers: {
        Authorization: testEventIngestionAuthorization(),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ source: "csrf-test", message: "routine activity" })
    });
    assert.equal(eventResponse.status, 201);
  });

  it("preserves Basic Auth precedence for invalid credentials", async () => {
    const result = await request("POST", "/incidents", {
      authorization: "Basic " + Buffer.from("wrong:credentials").toString("base64"),
      origin: "https://attacker.example.test",
      body: { title: "Rejected", severity: "LOW", assignedTo: "Test" }
    });
    assert.equal(result.response.status, 401);
    assert.deepEqual(result.body, { error: "Authentication required" });
  });

  it("uses incoming protocol and host as the local-development fallback", () => {
    const guard = createAdminOriginGuard({ publicOrigin: "" });
    const response = {
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; }
    };
    let continued = false;
    guard({
      method: "POST",
      protocol: "http",
      get(name) {
        return { host: "localhost:3001", origin: "http://localhost:3001" }[name.toLowerCase()];
      }
    }, response, () => { continued = true; });
    assert.equal(continued, true);

    let forwardedHeaderContinued = false;
    const forwardedResponse = {
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; }
    };
    guard({
      method: "POST",
      protocol: "http",
      get(name) {
        return {
          host: "localhost:3001",
          origin: "https://localhost:3001",
          "x-forwarded-proto": "https"
        }[name.toLowerCase()];
      }
    }, forwardedResponse, () => { forwardedHeaderContinued = true; });
    assert.equal(forwardedHeaderContinued, false);
    assert.equal(forwardedResponse.statusCode, 403);
    assert.deepEqual(forwardedResponse.body, { error: "cross_origin_request" });
  });
});
