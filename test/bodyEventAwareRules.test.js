const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const { parseLogBatch } = require("../backend/services/logParserService");
const logAnalysisService = require("../backend/services/logAnalysisService");
const findingService = require("../backend/services/findingService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const {
  matchEventAwareRule,
  matchEventAwareRules,
  mergeEventAwareMatches
} = require("../backend/services/eventAwareMatcher");

const bodyRuleCases = [
  {
    id: "SQLI_001",
    body: "id=1' OR 1=1",
    escapedBody: String.raw`id=1' \u004fR 1=1`,
    safeBody: "id=1 AND active=true"
  },
  {
    id: "SQLI_002",
    body: "1 UNION SELECT username FROM users",
    escapedBody: String.raw`1 \u0055NION SELECT username FROM users`,
    safeBody: "SELECT username FROM users"
  },
  {
    id: "SQLI_004",
    body: "SLEEP(5)",
    escapedBody: String.raw`\u0053LEEP(5)`,
    safeBody: "sleep_duration=5"
  },
  {
    id: "XSS_001",
    body: "<script>alert(1)</script>",
    escapedBody: String.raw`\u003cscript\u003ealert(1)\u003c/script\u003e`,
    safeBody: "<p>Welcome</p>"
  },
  {
    id: "XSS_003",
    body: "javascript:alert(1)",
    escapedBody: String.raw`jav\u0061script:alert(1)`,
    safeBody: "https://example.test/page"
  },
  {
    id: "XXE_001",
    body: "<!ENTITY x SYSTEM 'file:///etc/passwd'>",
    escapedBody: String.raw`<!ENT\u0049TY x SYSTEM 'file:///etc/passwd'>`,
    safeBody: "<data><name>sample</name></data>"
  },
  {
    id: "GRAPHQL_001",
    body: '{"query":"{ __schema { types { name } } }"}',
    escapedBody: String.raw`{\"query\":\"{ __sch\u0065ma { types { name } } }\"}`,
    safeBody: '{"query":"{ user { name } }"}'
  }
];

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function encodedBodyLines(bodySource) {
  return [
    `{"message":"ordinary event","http":{"body":"safe request"}}`,
    `{"message":"matching event","http":{"body":"${bodySource}"}}`,
    `{"message":"another ordinary event","http":{"body":"safe request"}}`
  ].join("\n");
}

function ruleMatch(detection, ruleId) {
  return detection.matchedRules.find((rule) => rule.id === ruleId) || null;
}

describe("event-aware HTTP body rule migration", () => {
  it("registers only the seven approved body rules on http.body", () => {
    const bodyRules = EVENT_AWARE_RULES.filter(({ fields }) =>
      JSON.stringify(fields) === JSON.stringify([["http", "body"]])
    );
    assert.deepEqual(bodyRules.map(({ ruleId }) => ruleId), bodyRuleCases.map(({ id }) => id));

    for (const { id } of bodyRuleCases) {
      assert.equal(detectionRules.some((rule) => rule.id === id), true);
      assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === id), {
        ruleId: id,
        fields: [["http", "body"]]
      });
    }

    for (const id of [
      "SQLI_005", "XSS_002", "XSS_004", "NOSQL_001", "LDAP_001",
      "DESER_001", "SSTI_001", "HDR_001", "LOG4_001", "JWT_001"
    ]) {
      assert.equal(EVENT_AWARE_RULES.some((rule) => rule.ruleId === id), false, `${id} must remain unregistered`);
    }
  });

  for (const ruleCase of bodyRuleCases) {
    it(`${ruleCase.id} matches only the structured body event, with bounded evidence and a Finding`, () => {
      const prefix = "ordinary content ".repeat(20);
      const suffix = " trailing content".repeat(20);
      const body = `${prefix}${ruleCase.body}${suffix}`;
      const batch = parseLogBatch(jsonLines([
        { message: "event A", http: { body: "safe request" } },
        { message: "event B", http: { body } },
        { message: "event C", http: { body: ruleCase.safeBody } }
      ]));
      const matches = matchEventAwareRules(batch.events);
      const match = matches.find((item) => item.id === ruleCase.id);

      assert.ok(match, `expected ${ruleCase.id} to match event B body`);
      assert.equal(match.count, 1);
      assert.deepEqual(match.evidence.map((item) => item.eventId), [batch.events[1].eventId]);
      assert.ok(match.evidence[0].excerpt.length <= 200);
      assert.match(match.evidence[0].excerpt, /ordinary content/);
      const finding = findingService.createFindings({ matchedRules: [match] })[0];
      assert.deepEqual(finding.eventIds, [batch.events[1].eventId]);
      assert.deepEqual(finding.evidence, match.evidence);
      assert.equal(finding.evidence[0].eventId, batch.events[1].eventId);
      assert.equal(finding.evidence[0].excerpt.includes(body), false,
        "the full request body must not be copied into evidence");
    });

    it(`${ruleCase.id} keeps the raw count authoritative when raw and body matching overlap`, async () => {
      const logs = jsonLines([
        { message: "event A", http: { body: "safe request" } },
        { message: "event B", http: { body: ruleCase.body } },
        { message: "event C", http: { body: ruleCase.safeBody } }
      ]);
      const batch = parseLogBatch(logs);
      const rawDetection = await logAnalysisService.analyzeLogs(logs);
      const rawMatch = ruleMatch(rawDetection, ruleCase.id);
      const bodyMatch = matchEventAwareRule(batch.events, ruleCase.id);
      const merged = mergeEventAwareMatches(rawDetection, [bodyMatch, bodyMatch]);
      const mergedMatches = merged.matchedRules.filter((item) => item.id === ruleCase.id);

      assert.ok(rawMatch, `expected legacy raw detection for ${ruleCase.id}`);
      assert.equal(bodyMatch.count, 1);
      assert.equal(mergedMatches.length, 1);
      assert.equal(mergedMatches[0].count, rawMatch.count);
      assert.deepEqual(mergedMatches[0].evidence.map((item) => item.eventId), [batch.events[1].eventId]);
      const findings = findingService.createFindings(merged).filter((item) => item.ruleId === ruleCase.id);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].count, rawMatch.count);
      assert.deepEqual(findings[0].eventIds, [batch.events[1].eventId]);
    });

    it(`${ruleCase.id} adds a body-only match when JSON unescaping reveals the signature`, async () => {
      const logs = encodedBodyLines(ruleCase.escapedBody);
      const batch = parseLogBatch(logs);
      const rawDetection = await logAnalysisService.analyzeLogs(logs);
      const bodyMatch = matchEventAwareRule(batch.events, ruleCase.id);
      const merged = mergeEventAwareMatches(rawDetection, [bodyMatch]);

      assert.equal(ruleMatch(rawDetection, ruleCase.id), null);
      assert.equal(batch.events[1].http.body.includes("\\u"), false);
      assert.ok(bodyMatch);
      assert.equal(bodyMatch.count, 1);
      assert.deepEqual(bodyMatch.evidence.map((item) => item.eventId), [batch.events[1].eventId]);
      assert.equal(ruleMatch(merged, ruleCase.id).count, 1);
      const finding = findingService.createFindings(merged).find((item) => item.ruleId === ruleCase.id);
      assert.deepEqual(finding.eventIds, [batch.events[1].eventId]);
    });

    it(`${ruleCase.id} emits deterministic evidence for multiple matching events and ignores safe bodies`, () => {
      const batch = parseLogBatch(jsonLines([
        { message: "event A", http: { body: ruleCase.safeBody } },
        { message: "event B", http: { body: ruleCase.body } },
        { message: "event C", http: { body: ruleCase.safeBody } },
        { message: "event D", http: { body: ruleCase.body } }
      ]));
      const match = matchEventAwareRule(batch.events, ruleCase.id);

      assert.equal(match.count, 2);
      assert.deepEqual(match.evidence.map((item) => item.eventId), [
        batch.events[1].eventId,
        batch.events[3].eventId
      ]);
      assert.ok(match.evidence.every((item) => item.excerpt.length <= 200));

      const safeBatch = parseLogBatch(jsonLines([
        { message: "safe A", http: { body: ruleCase.safeBody } },
        { message: "safe B", http: { body: "ordinary request body" } }
      ]));
      assert.equal(matchEventAwareRule(safeBatch.events, ruleCase.id), null);
    });
  }
});
