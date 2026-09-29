const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const { parseLogBatch } = require("../backend/services/logParserService");
const { analyzeLogs, countPatternMatches, findFirstPatternMatch } = require("../backend/services/logAnalysisService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const {
  createEvidence,
  matchEventAwareRule,
  mergeEventAwareMatches
} = require("../backend/services/eventAwareMatcher");
const { createFindings } = require("../backend/services/findingService");

const rule = detectionRules.find((item) => item.id === "SQLI_003");

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function bodyBatch(body) {
  return parseLogBatch(jsonLines([
    { message: "request under test", http: { body } },
    { message: "second valid JSON event" }
  ]));
}

describe("SQLI_003 event-aware migration characterization", () => {
  it("records the exact rule definition and its effective raw detection defaults", () => {
    assert.deepEqual({
      id: rule.id,
      pattern: rule.pattern,
      type: rule.type,
      severity: rule.severity,
      regex: rule.regex,
      description: rule.description,
      repeatThreshold: rule.repeatThreshold
    }, {
      id: "SQLI_003",
      pattern: "(?i)\\b(DROP|TRUNCATE|DELETE)\\s+TABLE",
      type: "SQL Injection",
      severity: "CRITICAL",
      regex: true,
      description: "Detects destructive SQL commands.",
      repeatThreshold: undefined
    });
    assert.equal(Number(rule.repeatThreshold) || 1, 1);
    assert.deepEqual(EVENT_AWARE_RULES.find((entry) => entry.ruleId === "SQLI_003"), {
      ruleId: "SQLI_003",
      fields: [["http", "body"], ["http", "query"]]
    });
  });

  it("characterizes case, variants, surrounding text, spacing, newlines, and near misses", async () => {
    const positives = [
      "DROP TABLE users",
      "drop table users",
      "TRUNCATE TABLE accounts",
      "DELETE TABLE records",
      "Documentation: DROP TABLE syntax is shown here.",
      "DROP   TABLE users",
      "DROP\nTABLE users",
      "DROP TABLES users"
    ];
    for (const input of positives) {
      assert.ok(countPatternMatches(input, rule) > 0, `expected match for ${JSON.stringify(input)}`);
    }

    for (const input of [
      "DROP DATABASE users",
      "DELETE FROM users",
      "TRUNCATE users",
      "TABLE users",
      "XDROP TABLE users",
      "DROPPED TABLE users"
    ]) {
      assert.equal(countPatternMatches(input, rule), 0, `unexpected match for ${JSON.stringify(input)}`);
    }

    const raw = await analyzeLogs("prefix DROP TABLE users suffix");
    assert.equal(raw.matchedRules.find((match) => match.id === "SQLI_003")?.count, 1);
  });

  it("matches the unchanged pattern against raw normalized bodies of varied formats", () => {
    const bodies = [
      "DROP TABLE users", // plain text
      '"DROP TABLE users"', // JSON string value
      '{"statement":"DROP TABLE users"}', // JSON object text
      "name=users&action=DROP TABLE users", // form-like content
      "<query>DROP TABLE users</query>", // XML-like text
      "<code>DROP TABLE users</code>" // HTML/text content
    ];

    for (const body of bodies) {
      const batch = bodyBatch(body);
      assert.equal(batch.events[0].http.body, body);
      assert.ok(countPatternMatches(batch.events[0].http.body, rule) > 0,
        `expected normalized body match for ${JSON.stringify(body)}`);
    }

    const documentation = bodyBatch("DROP TABLE syntax is discussed in this documentation.");
    assert.equal(countPatternMatches(documentation.events[0].http.body, rule), 1);
  });

  it("matches literal query text but does not decode percent-encoded SQL", () => {
    const literal = parseLogBatch(jsonLines([
      { message: "query", http: { query: "id=1&name=DROP TABLE users" } },
      { message: "second valid JSON event" }
    ]));
    const encoded = parseLogBatch(jsonLines([
      { message: "encoded query", http: { query: "id=1&name=DROP%20TABLE%20users" } },
      { message: "second valid JSON event" }
    ]));

    assert.equal(literal.events[0].http.query, "id=1&name=DROP TABLE users");
    assert.equal(countPatternMatches(literal.events[0].http.query, rule), 1);
    assert.equal(encoded.events[0].http.query, "id=1&name=DROP%20TABLE%20users");
    assert.equal(countPatternMatches(encoded.events[0].http.query, rule), 0);
    assert.equal(countPatternMatches("id=1&name=DROP+TABLE+users", rule), 0);

    const requestLine = parseLogBatch("GET /search?q=DROP%20TABLE%20users HTTP/1.1").events[0];
    assert.equal(requestLine.http.query, "q=DROP%20TABLE%20users");
    assert.equal(countPatternMatches(requestLine.http.query, rule), 0);
  });

  it("can identify matching events and represent bounded evidence with the existing model", () => {
    const longMatch = `${"x".repeat(260)} DROP TABLE users${"y".repeat(80)}`;
    const logs = jsonLines([
      { message: "unrelated", http: { query: "page=2" } },
      { message: "body match", http: { body: longMatch } },
      { message: "query match", http: { query: "name=TRUNCATE TABLE accounts" } },
      { message: "second body match", http: { body: "DELETE TABLE records" } }
    ]);
    const events = parseLogBatch(logs).events;
    const matchingEvents = events.filter((event) =>
      countPatternMatches(event.http?.body || "", rule) > 0 ||
      countPatternMatches(event.http?.query || "", rule) > 0
    );

    assert.deepEqual(matchingEvents.map((event) => event.eventId), [
      events[1].eventId,
      events[2].eventId,
      events[3].eventId
    ]);
    assert.equal(new Set(events.map((event) => event.eventId)).size, events.length);
    assert.deepEqual(events.map((event) => Number(event.eventId.match(/EVENT-(\d+)$/)[1])), [1, 2, 3, 4]);

    const source = events[1].http.body;
    const range = findFirstPatternMatch(source, rule);
    const evidence = createEvidence(events[1].eventId, source, range);
    assert.equal(evidence.eventId, events[1].eventId);
    assert.ok(evidence.excerpt.length <= 200);
    assert.equal(evidence.start, range.start);
    assert.equal(evidence.end, range.end);

    const findings = createFindings({ matchedRules: [{
      id: rule.id,
      type: rule.type,
      severity: rule.severity,
      description: rule.description,
      count: 3,
      evidence: matchingEvents.map((event) => ({ eventId: event.eventId, excerpt: "bounded", start: 0, end: 1 }))
    }] });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].count, 3);
    assert.deepEqual(findings[0].eventIds, matchingEvents.map((event) => event.eventId));
  });

  it("adds body/query event attribution in deterministic event order", () => {
    const logs = jsonLines([
      { message: "unrelated", http: { body: "ordinary content" } },
      { message: "query match", http: { query: "name=DROP TABLE users" } },
      { message: "body matches", http: { body: "DROP TABLE first; DELETE TABLE second" } }
    ]);
    const events = parseLogBatch(logs).events;
    const match = matchEventAwareRule(events, "SQLI_003");

    assert.equal(match.count, 3);
    assert.deepEqual(match.evidence.map((item) => item.eventId), [events[1].eventId, events[2].eventId]);
    assert.ok(match.evidence.every((item) => item.excerpt.length <= 200));
  });

  it("keeps the raw count authoritative on overlap and adds normalized-only body matches", async () => {
    const overlappingLogs = jsonLines([
      { message: "matching request", http: { body: "DROP TABLE users" } },
      { message: "unrelated request" }
    ]);
    const overlapEvents = parseLogBatch(overlappingLogs).events;
    const raw = await analyzeLogs(overlappingLogs);
    const rawCount = raw.matchedRules.find((item) => item.id === "SQLI_003").count;
    const eventMatch = matchEventAwareRule(overlapEvents, "SQLI_003");
    const merged = mergeEventAwareMatches(raw, [eventMatch]);
    const mergedRules = merged.matchedRules.filter((item) => item.id === "SQLI_003");

    assert.equal(mergedRules.length, 1);
    assert.equal(mergedRules[0].count, rawCount);
    assert.deepEqual(mergedRules[0].evidence.map((item) => item.eventId), [overlapEvents[0].eventId]);

    const normalizedOnlyLogs = jsonLines([
      { message: "escaped newline body", http: { body: "DROP\nTABLE users" } },
      { message: "unrelated request" }
    ]);
    const normalizedOnlyEvents = parseLogBatch(normalizedOnlyLogs).events;
    const rawOnly = await analyzeLogs(normalizedOnlyLogs);
    assert.equal(rawOnly.matchedRules.some((item) => item.id === "SQLI_003"), false);
    const normalizedMatch = matchEventAwareRule(normalizedOnlyEvents, "SQLI_003");
    const normalizedMerged = mergeEventAwareMatches(rawOnly, [normalizedMatch]);
    const normalizedRules = normalizedMerged.matchedRules.filter((item) => item.id === "SQLI_003");

    assert.equal(normalizedMatch.count, 1);
    assert.equal(normalizedRules.length, 1);
    assert.equal(normalizedRules[0].count, 1);
    assert.deepEqual(normalizedRules[0].evidence.map((item) => item.eventId), [normalizedOnlyEvents[0].eventId]);
  });
});
