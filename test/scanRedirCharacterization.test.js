const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const logAnalysisService = require("../backend/services/logAnalysisService");
const findingService = require("../backend/services/findingService");
const { parseLogBatch } = require("../backend/services/logParserService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const {
  matchEventAwareRule,
  mergeEventAwareMatches
} = require("../backend/services/eventAwareMatcher");

const ruleById = new Map(detectionRules.map((rule) => [rule.id, rule]));

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function candidateFieldMatch(ruleId, events, fieldName) {
  const rule = ruleById.get(ruleId);
  let count = 0;
  const evidence = [];

  for (const event of events) {
    const value = event.http?.[fieldName];
    if (typeof value !== "string") continue;
    const eventCount = logAnalysisService.countPatternMatches(value, rule);
    count += eventCount;
    if (eventCount > 0 && evidence.length < MAX_EVIDENCE_PER_RULE && event.eventId) {
      const range = logAnalysisService.findFirstPatternMatch(value, rule);
      if (range) evidence.push(createEvidence(event.eventId, value, range));
    }
  }

  if (count === 0) return null;
  return {
    id: rule.id,
    pattern: rule.pattern,
    type: rule.type,
    severity: rule.severity.toUpperCase(),
    description: rule.description,
    count,
    evidence
  };
}

async function rawMatch(logs, ruleId) {
  const detection = await logAnalysisService.analyzeLogs(logs);
  return detection.matchedRules.find((rule) => rule.id === ruleId) || null;
}

async function rawDetection(logs) {
  return logAnalysisService.analyzeLogs(logs);
}

describe("SCAN_001 and REDIR_001 parser/matcher characterization", () => {
  it("registers SCAN_001 on http.userAgent and REDIR_001 on http.query", () => {
    const registered = EVENT_AWARE_RULES.map(({ ruleId }) => ruleId);
    assert.equal(registered.includes("SCAN_001"), true);
    assert.equal(registered.includes("REDIR_001"), true);
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "SCAN_001"), {
      ruleId: "SCAN_001",
      fields: [["http", "userAgent"]],
      pattern: "(?i)(sqlmap|nikto|nmap|burp|dirbuster|gobuster|zgrab|masscan)"
    });
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "REDIR_001"), {
      ruleId: "REDIR_001", fields: [["http", "query"]]
    });
  });

  it("preserves a complete User-Agent value from a plain-text header line", () => {
    const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 sqlmap/1.7";
    const batch = parseLogBatch(`User-Agent: ${userAgent}`);

    assert.equal(batch.events[0].http.userAgent, userAgent);
  });

  it("reads explicitly labeled text User-Agent values, including quoted values with spaces", () => {
    const value = "ExampleBrowser/4.2 scanner sqlmap/1.7";
    const batch = parseLogBatch(`request userAgent="${value}" status=200`);

    assert.equal(batch.events[0].http.userAgent, value);
    assert.equal(candidateFieldMatch("SCAN_001", batch.events, "userAgent"), null,
      "the existing rule pattern includes a User-Agent: prefix absent from the field value");
    assert.equal(matchEventAwareRule(batch.events, "SCAN_001").count, 1,
      "the field-specific event-aware pattern matches the extracted value");
  });

  it("reads the recognized top-level and nested JSON User-Agent fields", () => {
    const batch = parseLogBatch(jsonLines([
      { message: "one", userAgent: "sqlmap/1.7" },
      { message: "two", http: { user_agent: "nikto/2.1" } },
      { message: "three", http: { userAgent: "Mozilla/5.0 Chrome/120.0" } }
    ]));

    assert.deepEqual(batch.events.map((event) => event.http?.userAgent), [
      "sqlmap/1.7", "nikto/2.1", "Mozilla/5.0 Chrome/120.0"
    ]);
  });

  it("distinguishes a scanner User-Agent from an ordinary browser", async () => {
    const scannerLogs = "User-Agent: Mozilla/5.0 sqlmap/1.7";
    const browserLogs = "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36";
    const scannerBatch = parseLogBatch(scannerLogs);
    const browserBatch = parseLogBatch(browserLogs);

    assert.ok(await rawMatch(scannerLogs, "SCAN_001"));
    assert.equal(candidateFieldMatch("SCAN_001", scannerBatch.events, "userAgent"), null);
    assert.equal(matchEventAwareRule(scannerBatch.events, "SCAN_001").count, 1);
    assert.equal(await rawMatch(browserLogs, "SCAN_001"), null);
    assert.equal(candidateFieldMatch("SCAN_001", browserBatch.events, "userAgent"), null);
    assert.equal(matchEventAwareRule(browserBatch.events, "SCAN_001"), null);
  });

  it("counts multiple scanner events but retains evidence only for events that match", () => {
    const batch = parseLogBatch(jsonLines([
      { message: "first", userAgent: "Mozilla/5.0 Chrome/120.0" },
      { message: "second", userAgent: "sqlmap/1.7" },
      { message: "third", http: { userAgent: "nikto/2.1" } }
    ]));
    const match = matchEventAwareRule(batch.events, "SCAN_001");

    assert.equal(match.count, 2);
    assert.deepEqual(match.evidence.map((item) => item.eventId), [
      batch.events[1].eventId,
      batch.events[2].eventId
    ]);
  });

  it("leaves missing, empty, and malformed User-Agent values absent", () => {
    const batch = parseLogBatch(jsonLines([
      { message: "missing" },
      { message: "empty", userAgent: "  " },
      { message: "wrong type", userAgent: 123 },
      { message: "unrecognized key", "User-Agent": "sqlmap/1.7" }
    ]));

    assert.ok(batch.events.every((event) => event.http?.userAgent === undefined));
    assert.equal(candidateFieldMatch("SCAN_001", batch.events, "userAgent"), null);

    const malformedText = parseLogBatch("User Agent: sqlmap/1.7");
    assert.equal(malformedText.events[0].http?.userAgent, undefined);

    const partialText = parseLogBatch("User-Agent: sql");
    assert.equal(partialText.events[0].http.userAgent, "sql");
    assert.equal(matchEventAwareRule(partialText.events, "SCAN_001"), null);
  });

  it("shows raw SCAN_001 hits that a normalized-field-only candidate would miss", async () => {
    const logs = jsonLines([
      { message: "User-Agent: sqlmap/1.7" },
      { message: "ordinary request" }
    ]);
    const batch = parseLogBatch(logs);

    assert.ok(await rawMatch(logs, "SCAN_001"));
    assert.equal(batch.events[0].http?.userAgent, undefined);
    assert.equal(matchEventAwareRule(batch.events, "SCAN_001"), null);
  });

  it("shows JSON User-Agent field hits invisible to the current raw SCAN_001 pattern", async () => {
    const logs = jsonLines([
      { message: "request", userAgent: "sqlmap/1.7" },
      { message: "ordinary request" }
    ]);
    const batch = parseLogBatch(logs);

    assert.equal(await rawMatch(logs, "SCAN_001"), null);
    assert.equal(candidateFieldMatch("SCAN_001", batch.events, "userAgent"), null);
    assert.equal(matchEventAwareRule(batch.events, "SCAN_001").count, 1);
  });

  it("preserves the raw SCAN_001 count and evidence metadata for an overlap", async () => {
    const logs = "User-Agent: sqlmap/1.7";
    const batch = parseLogBatch(logs);
    const detection = await rawDetection(logs);
    const raw = detection.matchedRules.find((rule) => rule.id === "SCAN_001");
    const eventMatch = matchEventAwareRule(batch.events, "SCAN_001");
    const merged = mergeEventAwareMatches(detection, [eventMatch]);
    const mergedMatches = merged.matchedRules.filter((rule) => rule.id === "SCAN_001");
    const findings = findingService.createFindings(merged)
      .filter((item) => item.ruleId === "SCAN_001");
    assert.equal(mergedMatches.length, 1);
    assert.equal(mergedMatches[0].count, raw.count,
      "the production merger keeps the raw count authoritative");
    assert.equal(raw.count, 1);
    assert.equal(eventMatch.count, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].count, raw.count);
    assert.deepEqual(findings[0].eventIds, [batch.events[0].eventId]);
    assert.equal(findings[0].evidence[0].excerpt, batch.events[0].http.userAgent);
  });

  it("parses a plain request-line URL into path and one unsplit query string", () => {
    const query = "next=https://evil.example/a&source=mail";
    const batch = parseLogBatch(`GET /go?${query} HTTP/1.1`);

    assert.equal(batch.events[0].http.path, "/go");
    assert.equal(batch.events[0].http.query, query);
    assert.equal(Array.isArray(batch.events[0].http.query), false);
    assert.equal(batch.events[0].http.queryParameters, undefined);
  });

  it("derives matching query strings from plain request lines and recognized JSON URL fields", () => {
    const url = "https://app.example/go?next=https://evil.example/path";
    const textBatch = parseLogBatch(`GET ${url} HTTP/1.1`);
    const jsonBatch = parseLogBatch(jsonLines([
      { message: "request", url },
      { message: "second request", http: { url: "https://app.example/go?next=https://evil.example/path" } }
    ]));

    assert.equal(textBatch.events[0].http.query, "next=https://evil.example/path");
    assert.deepEqual(jsonBatch.events.map((event) => event.http.query), [
      "next=https://evil.example/path",
      "next=https://evil.example/path"
    ]);
    assert.equal(matchEventAwareRule(textBatch.events, "REDIR_001").count, 1);
    assert.equal(matchEventAwareRule(jsonBatch.events, "REDIR_001").count, 2);
  });

  it("reads explicitly labeled text and JSON query fields without splitting parameters", () => {
    const labeled = parseLogBatch([
      'request http.query="next=https://evil.example/a&next=https://other.example/b"',
      "request query_string=return_to=https://outside.example/path"
    ].join("\n"));
    const unsupportedPlainAlias = parseLogBatch("request query=next=https://evil.example/a");
    const json = parseLogBatch(jsonLines([
      { message: "request", query: "next=https://evil.example/a&source=mail" },
      { message: "request", http: { query_string: "redirect_uri=https://outside.example/callback" } }
    ]));

    assert.equal(labeled.events[0].http.query, "next=https://evil.example/a&next=https://other.example/b");
    assert.equal(labeled.events[1].http.query, "return_to=https://outside.example/path");
    assert.equal(unsupportedPlainAlias.events[0].http?.query, undefined);
    assert.equal(json.events[0].http.query, "next=https://evil.example/a&source=mail");
    assert.equal(json.events[1].http.query, "redirect_uri=https://outside.example/callback");
    assert.equal(matchEventAwareRule(labeled.events, "REDIR_001").count, 3);
  });

  it("preserves percent encoding and does not URL-decode REDIR_001 values", async () => {
    const encodedQuery = "next=https%3A%2F%2Fevil.example%2Fcallback";
    const text = parseLogBatch(`GET /go?${encodedQuery} HTTP/1.1`);
    const json = parseLogBatch(jsonLines([
      { message: "request", url: `https://app.example/go?${encodedQuery}` },
      { message: "second request" }
    ]));

    assert.equal(text.events[0].http.query, encodedQuery);
    assert.equal(json.events[0].http.query, encodedQuery);
    assert.equal(matchEventAwareRule(text.events, "REDIR_001"), null);
    assert.equal(matchEventAwareRule(json.events, "REDIR_001"), null);
    assert.equal(await rawMatch(`GET /go?${encodedQuery}`, "REDIR_001"), null);
  });

  it("retains repeated redirect parameters in one query string and counts both occurrences", async () => {
    const query = "next=https://one.example/a&next=https://two.example/b";
    const logs = `GET /go?${query} HTTP/1.1`;
    const batch = parseLogBatch(logs);
    const detection = await rawDetection(logs);
    const raw = detection.matchedRules.find((rule) => rule.id === "REDIR_001");
    const candidate = matchEventAwareRule(batch.events, "REDIR_001");
    const merged = mergeEventAwareMatches(detection, [candidate, candidate]);
    const redirMatches = merged.matchedRules.filter((rule) => rule.id === "REDIR_001");
    const finding = findingService.createFindings(merged).find((item) => item.ruleId === "REDIR_001");

    assert.equal(batch.events[0].http.query, query);
    assert.equal(redirMatches.length, 1);
    assert.equal(raw.count, 2);
    assert.equal(candidate.count, 2);
    assert.equal(candidate.evidence.length, 1);
    assert.equal(redirMatches[0].count, raw.count);
    assert.equal(finding.count, 2);
    assert.deepEqual(finding.eventIds, [batch.events[0].eventId]);
    assert.equal(finding.evidence[0].eventId, batch.events[0].eventId);
  });

  it("counts one redirect signal among multiple events and associates evidence only with that event", async () => {
    const logs = jsonLines([
      { message: "request", query: "page=2&sort=recent" },
      { message: "redirect request", query: "return_to=https://outside.example/path" },
      { message: "another request", query: "q=hello" }
    ]);
    const batch = parseLogBatch(logs);
    const raw = await rawMatch(logs, "REDIR_001");
    const candidate = matchEventAwareRule(batch.events, "REDIR_001");

    assert.equal(raw.count, 1);
    assert.equal(candidate.count, 1);
    assert.deepEqual(candidate.evidence.map((item) => item.eventId), [batch.events[1].eventId]);
  });

  it("leaves a malformed URL string available as http.url but cannot derive http.query", async () => {
    const malformed = "http://[broken/go?next=https://evil.example/path";
    const logs = `url=${malformed}`;
    const batch = parseLogBatch(logs);

    assert.equal(batch.events[0].http.url, malformed);
    assert.equal(batch.events[0].http.query, undefined);
    assert.ok(await rawMatch(logs, "REDIR_001"));
    assert.equal(matchEventAwareRule(batch.events, "REDIR_001"), null);
  });

  it("truncates a malformed whitespace-containing plain request target at the first space", () => {
    const batch = parseLogBatch("GET /go?next=https://evil.example/path with-space HTTP/1.1");

    assert.equal(batch.events[0].http.query, "next=https://evil.example/path");
  });

  it("leaves missing queries absent and shows raw REDIR_001 signals outside parsed request fields", async () => {
    const noQuery = parseLogBatch("GET /health HTTP/1.1");
    const rawOnly = "application note: redirect_uri=https://evil.example/callback";
    const rawOnlyBatch = parseLogBatch(rawOnly);

    assert.equal(noQuery.events[0].http.query, undefined);
    assert.ok(await rawMatch(rawOnly, "REDIR_001"));
    assert.equal(rawOnlyBatch.events[0].http?.query, undefined);
    assert.equal(matchEventAwareRule(rawOnlyBatch.events, "REDIR_001"), null);
  });

  it("preserves raw REDIR_001 count while candidate evidence remains event-bounded", async () => {
    const logs = jsonLines([
      { message: "request", query: "next=https://evil.example/a&next=https://other.example/b" },
      { message: "ordinary request", query: "page=2" }
    ]);
    const batch = parseLogBatch(logs);
    const raw = await rawMatch(logs, "REDIR_001");
    const candidate = matchEventAwareRule(batch.events, "REDIR_001");
    const merged = mergeEventAwareMatches(await logAnalysisService.analyzeLogs(logs), [candidate]);
    const finding = findingService.createFindings(merged).find((item) => item.ruleId === "REDIR_001");

    assert.equal(raw.count, 2);
    assert.equal(candidate.count, 2);
    assert.equal(finding.count, raw.count);
    assert.deepEqual(finding.eventIds, [batch.events[0].eventId]);
    assert.equal(finding.evidence.length, 1);
    assert.ok(finding.evidence[0].excerpt.length <= 200);
  });
});
