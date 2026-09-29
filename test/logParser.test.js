const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { parseLogBatch, parseIsoTimestamp } = require("../backend/services/logParserService");

describe("log parser and normalized events", () => {
  it("creates a batch and one plain-text event while preserving the trimmed input", () => {
    const batch = parseLogBatch("  2026-09-29T10:00:00Z user=alice failed login  \n");
    assert.match(batch.batchId, /^LOG-BATCH-/);
    assert.ok(Number.isFinite(Date.parse(batch.receivedAt)));
    assert.equal(batch.rawInput, "2026-09-29T10:00:00Z user=alice failed login");
    assert.equal(batch.events.length, 1);
    assert.equal(batch.events[0].rawMessage, "2026-09-29T10:00:00Z user=alice failed login");
    assert.equal(batch.events[0].message, batch.events[0].rawMessage);
    assert.equal(batch.events[0].eventTime, "2026-09-29T10:00:00.000Z");
    assert.equal(Object.hasOwn(batch, "parseWarnings"), false);
  });

  it("creates separate events for non-empty plain-text lines and preserves each exact line", () => {
    const batch = parseLogBatch(" first event \n\n  second event  \r\n   \nthird event ");
    assert.deepEqual(batch.events.map((event) => event.rawMessage), ["first event ", "  second event  ", "third event"]);
    assert.deepEqual(batch.events.map((event) => event.message), batch.events.map((event) => event.rawMessage));
    assert.equal(new Set(batch.events.map((event) => event.eventId)).size, 3);
  });

  it("returns no events for empty or whitespace-only input", () => {
    assert.deepEqual(parseLogBatch("").events, []);
    assert.deepEqual(parseLogBatch(" \n  \r\n ").events, []);
    assert.equal(parseLogBatch(" \n ").rawInput, "");
    assert.throws(() => parseLogBatch(null), /must be a string/);
  });

  it("normalizes ISO UTC timestamps and explicit timezone offsets", () => {
    assert.equal(parseIsoTimestamp("2026-09-29T10:00:00Z"), "2026-09-29T10:00:00.000Z");
    assert.equal(parseIsoTimestamp("2026-09-29T12:30:00+02:00"), "2026-09-29T10:30:00.000Z");
    assert.equal(parseIsoTimestamp("2026-09-29T05:00:00-05:00"), "2026-09-29T10:00:00.000Z");
  });

  it("extracts a client IP from the explicit source phrase in an authentication event", () => {
    const event = parseLogBatch("2026-09-29T10:00:00Z user=alice failed login from 10.0.0.5").events[0];
    assert.equal(event.clientIp, "10.0.0.5");
    assert.deepEqual(event.actor, { user: "alice" });
    assert.equal(event.eventTime, "2026-09-29T10:00:00.000Z");
  });

  it("leaves missing, ambiguous, and malformed plain-text timestamps absent", () => {
    for (const rawMessage of ["login failed", "09/29/2026 10:00:00 login failed"]) {
      const event = parseLogBatch(rawMessage).events[0];
      assert.equal(Object.hasOwn(event, "eventTime"), false);
    }
    const malformed = parseLogBatch("2026-99-45T30:70:70Z login failed");
    assert.equal(Object.hasOwn(malformed.events[0], "eventTime"), false);
    assert.match(malformed.parseWarnings[0], /timestamp-like prefix/);
    assert.equal(parseIsoTimestamp("2026-02-30T10:00:00Z"), null);
    assert.equal(parseIsoTimestamp("2026-09-29T10:00:00"), null);
  });

  const extractionCases = [
    ["source IP", "source_ip=10.0.0.5", (event) => assert.deepEqual(event.source, { ip: "10.0.0.5" })],
    ["actor user", "username=alice", (event) => assert.deepEqual(event.actor, { user: "alice" })],
    ["client IP", "client_ip=192.168.1.4", (event) => assert.equal(event.clientIp, "192.168.1.4")],
    ["HTTP method and path", "GET /login?q=x HTTP/1.1", (event) => {
      assert.equal(event.http.method, "GET");
      assert.equal(event.http.path, "/login");
      assert.equal(event.http.query, "q=x");
    }],
    ["HTTP URL and destination", "url=http://localhost:8080/login?q=x", (event) => {
      assert.equal(event.http.url, "http://localhost:8080/login?q=x");
      assert.equal(event.http.path, "/login");
      assert.equal(event.http.query, "q=x");
      assert.equal(event.destination.host, "localhost");
    }],
    ["user agent", "User-Agent: ExampleClient/1.0", (event) => assert.equal(event.http.userAgent, "ExampleClient/1.0")],
    ["process name", "process_name=node", (event) => assert.deepEqual(event.process, { name: "node" })],
    ["process command", "command=\"node worker.js\"", (event) => assert.deepEqual(event.process, { command: "node worker.js" })],
    ["authentication result", "auth_result=failed", (event) => assert.deepEqual(event.authentication, { result: "failed" })]
  ];

  for (const [fieldName, line, assertion] of extractionCases) {
    it(`extracts a simple ${fieldName}`, () => assertion(parseLogBatch(line).events[0]));
  }

  it("does not invent user, IP, process, or HTTP fields from unlabelled prose", () => {
    const event = parseLogBatch("alice mentioned 10.0.0.5 while discussing node and GET requests").events[0];
    for (const key of ["source", "actor", "clientIp", "http", "process", "destination", "authentication"]) {
      assert.equal(Object.hasOwn(event, key), false, `unexpected ${key}`);
    }
  });

  it("parses multiple valid JSON objects as JSON Lines and maps only recognized fields", () => {
    const lines = [
      '{"timestamp":"2026-09-29T10:00:00Z","message":"login failed","username":"alice","source_ip":"10.0.0.5","auth_result":"failed","extra":{"ignored":"value"}}',
      '  {"message":"GET /health","method":"GET","path":"/health","user_agent":"LocalTest"}  '
    ];
    const batch = parseLogBatch(lines.join("\n"));
    assert.equal(batch.events.length, 2);
    assert.equal(batch.events[0].rawMessage, lines[0]);
    assert.equal(batch.events[0].message, "login failed");
    assert.equal(batch.events[0].eventTime, "2026-09-29T10:00:00.000Z");
    assert.deepEqual(batch.events[0].source, { ip: "10.0.0.5" });
    assert.deepEqual(batch.events[0].actor, { user: "alice" });
    assert.deepEqual(batch.events[0].authentication, { result: "failed" });
    assert.equal(Object.hasOwn(batch.events[0], "extra"), false);
    assert.equal(batch.events[1].rawMessage, '  {"message":"GET /health","method":"GET","path":"/health","user_agent":"LocalTest"}');
    assert.deepEqual(batch.events[1].http, { method: "GET", path: "/health", userAgent: "LocalTest" });
  });

  it("recognizes JSON Lines across blank lines without creating blank events", () => {
    const batch = parseLogBatch('\n{"message":"first"}\n  \n{"message":"second"}\n');
    assert.deepEqual(batch.events.map((event) => event.message), ["first", "second"]);
    assert.equal(batch.events.length, 2);
  });

  it("falls back to plain text and warns for malformed JSON Lines", () => {
    const input = '{"message":"first"}\n{"message": }';
    const batch = parseLogBatch(input);
    assert.deepEqual(batch.events.map((event) => event.rawMessage), input.split("\n"));
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("malformed JSON Lines")));
  });

  it("falls back to plain text for mixed input and does not warn for ordinary logs", () => {
    const batch = parseLogBatch('{"message":"structured-looking"}\nrequest completed normally');
    assert.equal(batch.events.length, 2);
    assert.equal(batch.events[0].message, '{"message":"structured-looking"}');
    assert.equal(Object.hasOwn(batch, "parseWarnings"), false);
  });

  it("keeps a single JSON object line as plain text until it is part of JSON Lines", () => {
    const rawMessage = '{"message":"one object"}';
    const event = parseLogBatch(rawMessage).events[0];
    assert.equal(event.message, rawMessage);
    assert.equal(Object.hasOwn(event, "eventTime"), false);
  });

  it("captures raw bodies and selected headers from structured JSON event fields", () => {
    const rawBody = ' { "q": "OR 1=1", "encoded": "%3Cscript%3E" } ';
    const batch = parseLogBatch([
      JSON.stringify({
        message: "nested request",
        http: {
          userAgent: "ExistingAgent/1.0",
          headers: {
            "Content-Type": ["application/json; charset=utf-8", "application/json"],
            Host: "api.example.test",
            "X-Forwarded-For": ["192.0.2.1", "198.51.100.2"],
            Authorization: "Bearer secret-token",
            Cookie: "session=secret",
            "X-Unselected": "ignored"
          },
          body: rawBody
        }
      }),
      JSON.stringify({
        message: "top-level request",
        headers: { "content-TYPE": "application/x-www-form-urlencoded", Host: "form.example.test" },
        body: "q=hello+world&query=%3Cscript%3E"
      })
    ].join("\n"));

    assert.equal(batch.events[0].http.userAgent, "ExistingAgent/1.0");
    assert.deepEqual(batch.events[0].http.headers, {
      "content-type": ["application/json; charset=utf-8", "application/json"],
      host: ["api.example.test"],
      "x-forwarded-for": ["192.0.2.1", "198.51.100.2"]
    });
    assert.equal(batch.events[0].http.body, rawBody);
    assert.deepEqual(batch.events[1].http.headers, {
      "content-type": ["application/x-www-form-urlencoded"],
      host: ["form.example.test"]
    });
    assert.equal(batch.events[1].http.body, "q=hello+world&query=%3Cscript%3E");
    assert.equal(Object.hasOwn(batch.events[0].http.headers, "authorization"), false);
    assert.equal(Object.hasOwn(batch.events[0].http.headers, "cookie"), false);
  });

  it("preserves duplicate and empty selected header values without joining or decoding them", () => {
    const batch = parseLogBatch([
      JSON.stringify({
        http: { headers: {
          "Content-Type": "application/json",
          "content-type": ["application/json; charset=UTF-8", "text/plain"],
          Host: "",
          "X-Forwarded-For": ["192.0.2.1", "192.0.2.1"]
        } }
      }),
      JSON.stringify({ message: "second event" })
    ].join("\n"));

    assert.deepEqual(batch.events[0].http.headers, {
      "content-type": ["application/json", "application/json; charset=UTF-8", "text/plain"],
      host: [""],
      "x-forwarded-for": ["192.0.2.1", "192.0.2.1"]
    });
    assert.equal(Object.hasOwn(batch.events[1], "http"), false);
  });

  it("preserves explicitly empty and malformed JSON bodies as raw text", () => {
    const malformedJsonBody = '{"unfinished":';
    const batch = parseLogBatch([
      JSON.stringify({ http: { body: "", headers: { "Content-Type": "application/json" } } }),
      JSON.stringify({ body: malformedJsonBody, headers: { "Content-Type": "application/json" } })
    ].join("\n"));

    assert.equal(batch.events[0].http.body, "");
    assert.equal(batch.events[0].http.headers["content-type"][0], "application/json");
    assert.equal(batch.events[1].http.body, malformedJsonBody);
    assert.equal(Object.hasOwn(batch, "parseWarnings"), false);
  });

  it("omits missing and non-string body/header values", () => {
    const batch = parseLogBatch([
      JSON.stringify({ message: "missing" }),
      JSON.stringify({ http: { body: 7, headers: {
        Host: null,
        "Content-Type": 42,
        "X-Forwarded-For": ["192.0.2.1", false]
      } } })
    ].join("\n"));

    assert.equal(Object.hasOwn(batch.events[0], "http"), false);
    assert.deepEqual(batch.events[1].http.headers, { "x-forwarded-for": ["192.0.2.1"] });
    assert.equal(Object.hasOwn(batch.events[1].http, "body"), false);
  });

  it("omits an oversized body and warns while retaining the full raw input", () => {
    const oversized = "x".repeat(32 * 1024 + 1);
    const input = [
      JSON.stringify({ http: { body: oversized } }),
      JSON.stringify({ message: "second event" })
    ].join("\n");
    const batch = parseLogBatch(input);

    assert.equal(batch.rawInput, input);
    assert.equal(Object.hasOwn(batch.events[0].http || {}, "body"), false);
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("HTTP body exceeded capture limits")));
  });

  it("enforces the batch body budget without attaching one event's body to another", () => {
    const body = "b".repeat(32 * 1024);
    const batch = parseLogBatch([
      JSON.stringify({ http: { body } }),
      JSON.stringify({ http: { body } }),
      JSON.stringify({ http: { body: "last" } })
    ].join("\n"));

    assert.equal(batch.events[0].http.body.length, body.length);
    assert.equal(batch.events[1].http.body.length, body.length);
    assert.equal(Object.hasOwn(batch.events[2].http || {}, "body"), false);
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("HTTP body exceeded capture limits")));
  });

  it("bounds selected header bytes and the number of duplicate values", () => {
    const tooLarge = "h".repeat(16 * 1024 + 1);
    const manyValues = Array.from({ length: 33 }, (_, index) => `proxy-${index}`);
    const batch = parseLogBatch([
      JSON.stringify({ http: { headers: { Host: tooLarge } } }),
      JSON.stringify({ http: { headers: { "X-Forwarded-For": manyValues } } })
    ].join("\n"));

    assert.equal(Object.hasOwn(batch.events[0].http || {}, "headers"), false);
    assert.equal(batch.events[1].http.headers["x-forwarded-for"].length, 32);
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("selected HTTP headers exceeded capture limits")));
  });

  it("enforces the aggregate selected-header budget across structured events", () => {
    const value = "f".repeat(12 * 1024);
    const batch = parseLogBatch([
      JSON.stringify({ http: { headers: { Host: value } } }),
      JSON.stringify({ http: { headers: { Host: value } } }),
      JSON.stringify({ http: { headers: { Host: value } } })
    ].join("\n"));

    assert.equal(batch.events[0].http.headers.host[0].length, value.length);
    assert.equal(batch.events[1].http.headers.host[0].length, value.length);
    assert.equal(Object.hasOwn(batch.events[2].http || {}, "headers"), false);
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("selected HTTP headers exceeded capture limits")));
  });

  it("does not infer headers or bodies from following plain-text lines", () => {
    const batch = parseLogBatch([
      "POST /submit HTTP/1.1",
      "Content-Type: application/json",
      '{"query":"OR 1=1"}'
    ].join("\n"));

    assert.equal(batch.events.length, 3);
    assert.ok(batch.events.every((event) => !event.http?.headers && event.http?.body === undefined));
  });

  it("warns and omits eventTime when a JSON timestamp is not supported", () => {
    const batch = parseLogBatch('{"message":"first","timestamp":"09/29/2026 10:00:00"}\n{"message":"second"}');
    assert.equal(Object.hasOwn(batch.events[0], "eventTime"), false);
    assert.ok(batch.parseWarnings.some((warning) => warning.includes("timestamp field")));
  });
});
