const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const { parseLogBatch } = require("../backend/services/logParserService");
const logAnalysisService = require("../backend/services/logAnalysisService");
const findingService = require("../backend/services/findingService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const {
  MAX_EVIDENCE_EXCERPT_LENGTH,
  MAX_EVIDENCE_PER_RULE,
  matchEventAwareRule,
  mergeEventAwareMatches
} = require("../backend/services/eventAwareMatcher");

const rule = detectionRules.find((item) => item.id === "SSRF_001");
const targetUrl = "http://169.254.169.254/latest/meta-data";

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function rawRuleMatch(detection) {
  return detection.matchedRules.find((item) => item.id === "SSRF_001") || null;
}

describe("SSRF_001 event-aware request-input detection", () => {
  it("registers only body, URL, and query string fields using the existing rule", () => {
    const registration = EVENT_AWARE_RULES.find((item) => item.ruleId === "SSRF_001");
    assert.deepEqual(registration, {
      ruleId: "SSRF_001",
      fields: [["http", "body"], ["http", "url"], ["http", "query"]]
    });
    assert.equal(rule.pattern,
      "(?i)https?://(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|169\\.254\\.169\\.254|metadata\\.google\\.internal|instance-data)");
    assert.equal(registration.pattern, undefined, "the matcher uses the authoritative rule definition");
    assert.equal(EVENT_AWARE_RULES.some((item) => item.ruleId === "SSRF_001" &&
      item.fields.some((field) => JSON.stringify(field) === JSON.stringify(["http", "path"]))), false);
  });

  for (const [field, value] of [
    ["body", JSON.stringify({ url: targetUrl })],
    ["query", `target=${targetUrl}`],
    ["url", targetUrl]
  ]) {
    it(`detects a suspicious URL in http.${field} and ignores a safe value`, () => {
      const suspicious = parseLogBatch(jsonLines([
        { message: "event A", http: { [field]: field === "body" ? "https://public.example/" : "https://public.example/" } },
        { message: "event B", http: { [field]: value } },
        { message: "event C", http: { [field]: field === "body" ? "ordinary content" : "https://outside.example/path" } }
      ]));
      const match = matchEventAwareRule(suspicious.events, "SSRF_001");

      assert.ok(match);
      assert.equal(match.count, 1);
      assert.deepEqual(match.evidence.map((item) => item.eventId), [suspicious.events[1].eventId]);
      assert.match(match.evidence[0].excerpt, /169\.254\.169\.254/);

      const safe = parseLogBatch(jsonLines([
        { message: "safe A", http: { [field]: field === "body" ? "ordinary request" : "https://public.example/path" } },
        { message: "safe B", http: { [field]: field === "body" ? "another ordinary body" : "http://service.internal/health" } }
      ]));
      assert.equal(matchEventAwareRule(safe.events, "SSRF_001"), null);
    });
  }

  it("does not URL-decode percent-encoded destinations", () => {
    const encoded = "http%3A%2F%2F169.254.169.254/latest/meta-data";
    const batch = parseLogBatch(jsonLines([
      { message: "body", http: { body: encoded } },
      { message: "query", http: { query: `target=${encoded}` } },
      { message: "URL path", http: { url: `https://public.example/${encoded}` } },
      { message: "second event" }
    ]));

    assert.equal(batch.events[0].http.body, encoded);
    assert.equal(batch.events[1].http.query, `target=${encoded}`);
    assert.equal(matchEventAwareRule(batch.events, "SSRF_001"), null);
  });

  it("keeps raw count authoritative on overlap and attaches a Finding to the matching event", async () => {
    const logs = jsonLines([
      { message: "event A normal URL", http: { url: "https://public.example/" } },
      { message: "event B suspicious input", http: { body: targetUrl } },
      { message: "event C safe body", http: { body: "ordinary content" } }
    ]);
    const batch = parseLogBatch(logs);
    const rawDetection = await logAnalysisService.analyzeLogs(logs);
    const rawMatch = rawRuleMatch(rawDetection);
    const eventMatch = matchEventAwareRule(batch.events, "SSRF_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch, eventMatch]);
    const finalMatches = merged.matchedRules.filter((item) => item.id === "SSRF_001");
    const finding = findingService.createFindings(merged).find((item) => item.ruleId === "SSRF_001");

    assert.ok(rawMatch);
    assert.equal(rawMatch.count, 1);
    assert.equal(eventMatch.count, 1);
    assert.equal(finalMatches.length, 1);
    assert.equal(finalMatches[0].count, rawMatch.count);
    assert.equal(finding.count, rawMatch.count);
    assert.deepEqual(finding.eventIds, [batch.events[1].eventId]);
    assert.equal(finding.evidence.length, 1);
    assert.equal(finding.evidence[0].eventId, batch.events[1].eventId);
  });

  it("adds a body-input detection when JSON unescaping reveals the URL", async () => {
    const logs = [
      String.raw`{"message":"event A","http":{"body":"ordinary request"}}`,
      String.raw`{"message":"event B","http":{"body":"http\u003a\u002f\u002f169.254.169.254/latest/meta-data"}}`,
      String.raw`{"message":"event C","http":{"body":"safe content"}}`
    ].join("\n");
    const batch = parseLogBatch(logs);
    const rawDetection = await logAnalysisService.analyzeLogs(logs);
    const eventMatch = matchEventAwareRule(batch.events, "SSRF_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch]);
    const finding = findingService.createFindings(merged).find((item) => item.ruleId === "SSRF_001");

    assert.equal(rawRuleMatch(rawDetection), null);
    assert.equal(batch.events[1].http.body, targetUrl);
    assert.ok(eventMatch);
    assert.equal(eventMatch.count, 1);
    assert.deepEqual(finding.eventIds, [batch.events[1].eventId]);
    assert.equal(finding.evidence[0].eventId, batch.events[1].eventId);
  });

  it("keeps multiple matching event IDs in input order and caps evidence", () => {
    const records = Array.from({ length: MAX_EVIDENCE_PER_RULE + 2 }, (_, index) => ({
      message: `event ${index + 1}`,
      http: { body: `prefix-${index}-${targetUrl}-${"x".repeat(250)}` }
    }));
    const events = parseLogBatch(jsonLines(records)).events;
    const match = matchEventAwareRule(events, "SSRF_001");

    assert.equal(match.count, events.length);
    assert.equal(match.evidence.length, MAX_EVIDENCE_PER_RULE);
    assert.deepEqual(match.evidence.map((item) => item.eventId),
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
    assert.ok(match.evidence.every((item) => item.excerpt.length <= MAX_EVIDENCE_EXCERPT_LENGTH));
    assert.ok(match.evidence.every((item) => item.excerpt.includes("169.254.169.254")));
    const findings = findingService.createFindings({ matchedRules: [match] });
    assert.deepEqual(findings[0].eventIds,
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
  });

  it("does not convert a raw-only free-text match into event evidence", async () => {
    const logs = `request payload mentions ${targetUrl}`;
    const rawDetection = await logAnalysisService.analyzeLogs(logs);
    const events = parseLogBatch(logs).events;

    assert.ok(rawRuleMatch(rawDetection));
    assert.equal(events[0].http?.body, undefined);
    assert.equal(matchEventAwareRule(events, "SSRF_001"), null);
  });
});
