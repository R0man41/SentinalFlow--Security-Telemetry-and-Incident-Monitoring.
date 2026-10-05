const { EventEmitter, once } = require("node:events");
const { spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { after, describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { configureTestCredentials } = require("./helpers/adminAuth");
configureTestCredentials();

const app = require("../backend/server");
const repositoryRoot = path.resolve(__dirname, "..");
const children = new Set();

after(async () => {
  await Promise.all([...children].map(async (child) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGTERM");
    await once(child, "exit");
  }));
});

function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "::", () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function launchServer(port, { signalHarness = false } = {}) {
  const env = {
    ...process.env,
    ADMIN_AUTH_USERNAME: "lifecycle-test-admin",
    ADMIN_AUTH_PASSWORD: "lifecycle-test-password",
    EVENT_INGESTION_TOKEN: "lifecycle-test-ingestion-token"
  };
  if (port === undefined) delete env.PORT;
  else env.PORT = String(port);

  const serverPath = path.join(repositoryRoot, "backend", "server.js");
  const source = signalHarness
    ? `const app = require(${JSON.stringify(serverPath)}); app.startLocalServer(); process.stdin.on("data", () => { process.stdin.pause(); process.emit("SIGTERM"); process.stdin.destroy(); });`
    : null;
  const args = source ? ["-e", source] : [serverPath];
  const child = spawn(process.execPath, args, {
    cwd: repositoryRoot,
    env,
    stdio: [signalHarness ? "pipe" : "ignore", "pipe", "pipe"]
  });
  child.output = "";
  child.stdout.on("data", (chunk) => { child.output += chunk.toString(); });
  child.stderr.on("data", (chunk) => { child.output += chunk.toString(); });
  children.add(child);
  child.once("exit", () => children.delete(child));
  return child;
}

function waitForOutput(child, pattern, timeoutMs = 5000) {
  if (pattern.test(child.output)) return Promise.resolve(child.output.match(pattern));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`Timed out waiting for ${pattern}`)), timeoutMs);
    function onData() {
      if (pattern.test(child.output)) finish(null, child.output.match(pattern));
    }
    function onExit(code, signal) {
      finish(new Error(`Server exited before ready (code ${code}, signal ${signal})`));
    }
    function finish(error, match) {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.stderr.off("data", onData);
      child.off("exit", onExit);
      if (error) reject(error);
      else resolve(match);
    }
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
}

function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`Timed out waiting for server process to exit. Output: ${child.output}`)), timeoutMs);
    function onExit(code, signal) {
      finish(null, { code, signal });
    }
    function finish(error, result) {
      clearTimeout(timer);
      child.off("exit", onExit);
      if (error) reject(error);
      else resolve(result);
    }
    child.once("exit", onExit);
  });
}

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, { agent: false }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
    }).once("error", reject);
  });
}

describe("server deployment lifecycle", { concurrency: false }, () => {
  it("selects port 3001 by default and uses an explicitly provided port", () => {
    assert.equal(app.resolvePort(undefined), 3001);
    assert.equal(app.resolvePort("4321"), 4321);
    assert.equal(app.resolvePort("0"), 0);
  });

  it("logs completed request metadata without credentials or request content", () => {
    const entries = [];
    const response = new EventEmitter();
    response.statusCode = 201;
    let continued = false;
    const request = {
      method: "POST",
      path: "/events",
      originalUrl: "/events?token=query-secret-marker",
      headers: { authorization: "Bearer header-secret-marker" },
      body: { message: "raw-body-secret-marker" }
    };

    app.createRequestLogger({ log: (entry) => entries.push(entry) })(request, response, () => { continued = true; });
    assert.equal(continued, true);
    assert.deepEqual(entries, []);
    response.emit("finish");

    assert.equal(entries.length, 1);
    assert.match(entries[0], /POST \/events 201 [\d.]+ms$/);
    for (const secret of ["query-secret-marker", "header-secret-marker", "raw-body-secret-marker"]) {
      assert.equal(entries[0].includes(secret), false);
    }
  });

  it("registers SIGTERM and SIGINT handlers that close the server", () => {
    for (const signal of ["SIGTERM", "SIGINT"]) {
      const processLike = new EventEmitter();
      let closeCalls = 0;
      const server = {
        close(callback) {
          closeCalls += 1;
          callback();
        },
        closeAllConnections() {}
      };
      const logger = { log() {}, error() {} };

      app.registerShutdownHandlers(server, { processLike, logger });
      processLike.emit(signal);

      assert.equal(closeCalls, 1, `${signal} should close the HTTP server`);
      assert.equal(processLike.listenerCount("SIGTERM"), signal === "SIGTERM" ? 0 : 1);
      assert.equal(processLike.listenerCount("SIGINT"), signal === "SIGINT" ? 0 : 1);
    }
  });

  it("forces remaining connections closed after the bounded shutdown timeout", async () => {
    const processLike = new EventEmitter();
    let forcedCloseCalls = 0;
    let exitCode;
    const server = {
      close() {},
      closeAllConnections() { forcedCloseCalls += 1; }
    };
    const logger = { log() {}, error() {} };
    processLike.exit = (code) => { exitCode = code; };

    app.registerShutdownHandlers(server, { processLike, logger, timeoutMs: 10 });
    processLike.emit("SIGTERM");
    await new Promise((resolve) => setTimeout(resolve, 30));

    assert.equal(forcedCloseCalls, 1);
    assert.equal(exitCode, 1);
  });

  it("starts on the requested port, serves health, and exits cleanly on SIGTERM", async () => {
    const port = await getAvailablePort();
    const child = launchServer(port, { signalHarness: true });
    await waitForOutput(child, new RegExp(`Server running on port ${port}`));

    const health = await get(`http://127.0.0.1:${port}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(JSON.parse(health.body), { message: "API is running" });

    child.stdin.write("shutdown\n");
    const result = await waitForExit(child);
    assert.equal(result.code, 0);
    assert.match(child.output, /HTTP server closed cleanly/);
  });

  it("fails on an occupied selected port instead of silently trying another one", async () => {
    const occupied = net.createServer();
    await new Promise((resolve, reject) => {
      occupied.once("error", reject);
      occupied.listen(0, "::", resolve);
    });
    const port = occupied.address().port;

    try {
      const child = launchServer(port);
      const result = await waitForExit(child);
      assert.equal(result.code, 1);
      assert.match(child.output, /Failed to start server/);
      assert.equal(child.output.includes("Trying"), false);
    } finally {
      await new Promise((resolve, reject) => occupied.close((error) => error ? reject(error) : resolve()));
    }
  });
});
