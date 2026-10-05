const { after, before, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const express = require("express");
const cors = require("cors");
const { configureTestCredentials, testAdminAuthorization, testEventIngestionAuthorization } = require("./helpers/adminAuth");
const {
  ALLOWED_METHODS,
  ALLOWED_HEADERS,
  parseAllowedOrigins,
  createCorsOptions
} = require("../backend/middleware/corsConfig");

const originalEnvironment = {
  cors: process.env.CORS_ALLOWED_ORIGINS,
  incidentsFile: process.env.INCIDENTS_FILE
};
const temporaryDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "cors-config-tests-"));
process.env.INCIDENTS_FILE = path.join(temporaryDirectory, "incidents.json");
configureTestCredentials();
process.env.CORS_ALLOWED_ORIGINS = " https://allowed.example.test, , https://second.example.test ";

const app = require("../backend/server");
let server;
let baseUrl;

function startServer(targetApp) {
  return new Promise((resolve, reject) => {
    const listener = targetApp.listen(0, "127.0.0.1", () => resolve(listener));
    listener.once("error", reject);
  });
}

async function stopServer(target) {
  if (typeof target.closeAllConnections === "function") target.closeAllConnections();
  await new Promise((resolve, reject) => target.close((error) => error ? reject(error) : resolve()));
}

describe("environment-driven CORS configuration", { concurrency: false }, () => {
  before(async () => {
    server = await startServer(app);
    baseUrl = "http://127.0.0.1:" + server.address().port;
  });

  after(async () => {
    await stopServer(server);
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
    if (originalEnvironment.cors === undefined) delete process.env.CORS_ALLOWED_ORIGINS;
    else process.env.CORS_ALLOWED_ORIGINS = originalEnvironment.cors;
    if (originalEnvironment.incidentsFile === undefined) delete process.env.INCIDENTS_FILE;
    else process.env.INCIDENTS_FILE = originalEnvironment.incidentsFile;
  });

  it("parses comma-separated origins by trimming, ignoring empty entries, and de-duplicating", () => {
    assert.deepEqual(parseAllowedOrigins(" https://a.example.test, ,https://b.example.test, https://a.example.test "),
      ["https://a.example.test", "https://b.example.test"]);
    assert.deepEqual(parseAllowedOrigins(undefined), []);
    assert.deepEqual(parseAllowedOrigins(" , , "), []);
    assert.deepEqual(parseAllowedOrigins("*"), []);
  });

  it("allows only configured exact origins, including each configured origin", async () => {
    for (const origin of ["https://allowed.example.test", "https://second.example.test"]) {
      const response = await fetch(baseUrl + "/health", { headers: { Origin: origin } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("access-control-allow-origin"), origin);
      assert.equal(response.headers.get("access-control-allow-credentials"), null);
      assert.equal(response.headers.get("access-control-expose-headers"), null);
    }

    for (const origin of [
      "https://attacker.example.test",
      "https://allowed.example.test.attacker.test",
      "https://allowed.example.test:443"
    ]) {
      const response = await fetch(baseUrl + "/health", { headers: { Origin: origin } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("access-control-allow-origin"), null);
      assert.notEqual(response.headers.get("access-control-allow-origin"), "*");
    }
  });

  it("allows the route and HEAD behavior without an Origin header or default wildcard", async () => {
    const response = await fetch(baseUrl + "/health");
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { message: "API is running" });
    assert.equal(response.headers.get("access-control-allow-origin"), null);

    const head = await fetch(baseUrl + "/health", { method: "HEAD", headers: { Origin: "https://allowed.example.test" } });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get("access-control-allow-origin"), "https://allowed.example.test");

    const noOriginApp = express();
    noOriginApp.use(cors(createCorsOptions(undefined)));
    noOriginApp.get("/probe", (req, res) => res.json({ ok: true }));
    const noOriginServer = await startServer(noOriginApp);
    try {
      const local = await fetch("http://127.0.0.1:" + noOriginServer.address().port + "/probe");
      assert.equal(local.status, 200);
      assert.equal(local.headers.get("access-control-allow-origin"), null);

      const crossOrigin = await fetch("http://127.0.0.1:" + noOriginServer.address().port + "/probe", {
        headers: { Origin: "https://any.example.test" }
      });
      assert.equal(crossOrigin.status, 200);
      assert.equal(crossOrigin.headers.get("access-control-allow-origin"), null);
      assert.notEqual(crossOrigin.headers.get("access-control-allow-origin"), "*");
    } finally {
      await stopServer(noOriginServer);
    }
  });

  it("answers allowed preflight with only the required methods and headers", async () => {
    const response = await fetch(baseUrl + "/events", {
      method: "OPTIONS",
      headers: {
        Origin: "https://allowed.example.test",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), "https://allowed.example.test");

    const methods = response.headers.get("access-control-allow-methods").split(",").map((method) => method.trim());
    assert.deepEqual(methods, ALLOWED_METHODS);
    assert.ok(methods.includes("POST"));
    assert.ok(methods.includes("HEAD"));
    assert.equal(methods.includes("PATCH"), false);

    const headers = response.headers.get("access-control-allow-headers").toLowerCase().split(",").map((header) => header.trim());
    assert.deepEqual(headers.sort(), ALLOWED_HEADERS.map((header) => header.toLowerCase()).sort());
    assert.equal(response.headers.get("access-control-allow-credentials"), null);
  });

  it("does not grant a disallowed origin during preflight", async () => {
    const response = await fetch(baseUrl + "/events", {
      method: "OPTIONS",
      headers: {
        Origin: "https://not-configured.example.test",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"
      }
    });
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.notEqual(response.headers.get("access-control-allow-origin"), "*");
  });

  it("does not bypass Basic or Bearer authentication for an allowed origin", async () => {
    const basic = await fetch(baseUrl + "/dashboard", {
      headers: {
        Origin: "https://allowed.example.test",
        Authorization: testAdminAuthorization()
      }
    });
    assert.equal(basic.status, 200);
    assert.equal(basic.headers.get("access-control-allow-origin"), "https://allowed.example.test");

    const denied = await fetch(baseUrl + "/events", {
      method: "POST",
      headers: {
        Origin: "https://allowed.example.test",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ source: "cors-test", message: "routine" })
    });
    assert.equal(denied.status, 401);
    assert.equal(denied.headers.get("access-control-allow-origin"), "https://allowed.example.test");

    const bearer = await fetch(baseUrl + "/events", {
      method: "POST",
      headers: {
        Origin: "https://allowed.example.test",
        "Content-Type": "application/json",
        Authorization: testEventIngestionAuthorization()
      },
      body: JSON.stringify({ source: "cors-test", message: "routine" })
    });
    assert.equal(bearer.status, 201);
  });
});
