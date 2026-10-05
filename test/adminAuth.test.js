const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { configureTestCredentials, testAdminAuthorization, testEventIngestionAuthorization } = require("./helpers/adminAuth");

const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "admin-auth-tests-"));
const incidentsFile = path.join(temporaryDirectory, "incidents.json");
process.env.INCIDENTS_FILE = incidentsFile;
configureTestCredentials();

const app = require("../backend/server");
const db = require("../backend/db");
const createAdminAuth = require("../backend/middleware/adminAuth").createAdminAuth;

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

async function request(method, route, body, authorization) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authorization !== undefined) headers.Authorization = authorization;
  const response = await fetch(baseUrl + route, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : null };
}

const fixture = {
  incidentId: "INC-2020-0001",
  title: "Overdue fixture",
  description: "Admin auth mutation test",
  severity: "HIGH",
  status: "OPEN",
  assignedTo: "Test-OnCall",
  slaDeadline: "2000-01-01T00:00:00.000Z",
  escalated: false,
  timeline: [{ timestamp: "2000-01-01T00:00:00.000Z", action: "CREATED", from: null, to: "OPEN", by: "Test-OnCall" }],
  createdAt: "2000-01-01T00:00:00.000Z",
  updatedAt: "2000-01-01T00:00:00.000Z"
};

describe("admin API Basic Authentication", { concurrency: false }, () => {
  before(async () => {
    server = await startServer();
    baseUrl = "http://127.0.0.1:" + server.address().port;
  });

  beforeEach(async () => {
    await fs.writeFile(incidentsFile, "[]\n", "utf8");
  });

  after(async () => {
    await stopServer();
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  });

  it("keeps health public and allows separately authenticated event ingestion", async () => {
    const health = await request("GET", "/health");
    assert.equal(health.response.status, 200);
    assert.deepEqual(health.body, { message: "API is running" });

    const event = await request("POST", "/events", {
      source: "demo-app",
      message: "Routine request"
    }, testEventIngestionAuthorization());
    assert.equal(event.response.status, 201);
    assert.equal(event.body.accepted, true);
  });

  it("rejects missing, invalid, and malformed credentials with the same 401 challenge", async () => {
    const absent = await request("GET", "/dashboard");
    const wrongUsername = await request("GET", "/dashboard", undefined,
      "Basic " + Buffer.from("wrong-user:test-only-password").toString("base64"));
    const wrongPassword = await request("GET", "/dashboard", undefined,
      "Basic " + Buffer.from("test-admin:wrong-password").toString("base64"));
    const malformed = await request("GET", "/dashboard", undefined, "Basic bm9jb2xvbg==");

    for (const result of [absent, wrongUsername, wrongPassword, malformed]) {
      assert.equal(result.response.status, 401);
      assert.equal(result.response.headers.get("www-authenticate"),
        'Basic realm="Security Monitoring Admin", charset="UTF-8"');
      assert.deepEqual(result.body, { error: "Authentication required" });
    }
  });

  it("rejects every admin route before reads or mutations when credentials are missing", async () => {
    await db.createIncident(fixture);
    const routes = [
      ["GET", "/dashboard"],
      ["GET", "/incidents"],
      ["GET", "/incidents/" + fixture.incidentId],
      ["POST", "/incidents", { title: "Unauthorized", severity: "LOW", assignedTo: "Attacker" }],
      ["PUT", "/incidents/" + fixture.incidentId, { status: "RESOLVED" }],
      ["DELETE", "/incidents/" + fixture.incidentId],
      ["POST", "/analyze-logs", { logs: "OR 1=1" }],
      ["POST", "/escalations/run", {}]
    ];

    for (const [method, route, body] of routes) {
      const result = await request(method, route, body);
      assert.equal(result.response.status, 401, method + " " + route);
    }

    assert.deepEqual(await db.getIncidentById(fixture.incidentId), fixture);
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("allows valid admin credentials to access and mutate admin routes", async () => {
    await db.createIncident(fixture);
    for (const [method, route] of [
      ["GET", "/dashboard"],
      ["GET", "/incidents"],
      ["GET", "/incidents/" + fixture.incidentId]
    ]) {
      assert.equal((await request(method, route, undefined, testAdminAuthorization())).response.status, 200);
    }

    const updated = await request("PUT", "/incidents/" + fixture.incidentId,
      { status: "RESOLVED" }, testAdminAuthorization());
    assert.equal(updated.response.status, 200);
    assert.equal(updated.body.status, "RESOLVED");

    const created = await request("POST", "/incidents",
      { title: "Authorized", severity: "LOW", assignedTo: "Test" }, testAdminAuthorization());
    assert.equal(created.response.status, 200);

    const deleted = await request("DELETE", "/incidents/" + created.body.incidentId,
      undefined, testAdminAuthorization());
    assert.equal(deleted.response.status, 200);

    const analyzed = await request("POST", "/analyze-logs",
      { logs: "ordinary request completed" }, testAdminAuthorization());
    assert.equal(analyzed.response.status, 200);

    const escalation = await request("POST", "/escalations/run", {},
      testAdminAuthorization());
    assert.equal(escalation.response.status, 200);
  });

  it("fails closed with a clear service configuration error when credentials are not configured", () => {
    const middleware = createAdminAuth({});
    let status;
    let body;
    let continued = false;
    const response = {
      status(code) { status = code; return this; },
      json(value) { body = value; return this; }
    };

    middleware({ get: () => undefined }, response, () => { continued = true; });
    assert.equal(status, 503);
    assert.deepEqual(body, { error: "Admin authentication is not configured" });
    assert.equal(continued, false);
  });
});
