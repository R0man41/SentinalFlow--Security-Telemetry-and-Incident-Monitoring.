const net = require("net");
const detectionRules = require("../../data/detection_rules.json");
const { correlateEvents } = require("./correlationService");
const { countPatternMatches, findFirstPatternMatch } = require("./logAnalysisService");
const { parseIsoTimestamp } = require("./logParserService");
const {
  MAX_EVIDENCE_PER_RULE,
  createEvidence
} = require("./eventAwareMatcher");

const BF001_RULE_ID = "BF_001";
// Provisional five-minute window; no existing BF_001 window was documented.
const BF001_CORRELATION_WINDOW_MS = 5 * 60 * 1000;
const SEVERITY_WEIGHT = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const ruleById = new Map(detectionRules.map((rule) => [rule.id, rule]));
const ruleOrder = new Map(detectionRules.map((rule, index) => [rule.id, index]));
const bf001Rule = ruleById.get(BF001_RULE_ID);

if (!bf001Rule) throw new Error(`${BF001_RULE_ID} was not found in the detection rule catalog`);

function eventContent(event) {
  if (typeof event?.message === "string") return event.message;
  if (typeof event?.rawMessage === "string") return event.rawMessage;
  return "";
}

function hasRequiredContext(event) {
  const authenticationResult = event?.authentication?.result;
  return typeof event?.eventId === "string" && event.eventId.length > 0 &&
    typeof event?.clientIp === "string" && net.isIP(event.clientIp) !== 0 &&
    typeof authenticationResult === "string" && authenticationResult.trim().length > 0 &&
    Boolean(parseIsoTimestamp(event?.eventTime));
}

function makeContextMatch(qualifyingGroups, relevantEvents) {
  const threshold = Number(bf001Rule.repeatThreshold) || 1;
  const count = qualifyingGroups.reduce((total, group) => total + group.count, 0);
  const qualifyingEventIds = new Set(qualifyingGroups.flatMap((group) => group.eventIds));
  const events = relevantEvents.filter((event) => qualifyingEventIds.has(event.eventId));
  const evidence = [];

  for (const event of events) {
    if (evidence.length >= MAX_EVIDENCE_PER_RULE) break;
    const content = eventContent(event);
    const matchRange = findFirstPatternMatch(content, bf001Rule);
    if (matchRange) evidence.push(createEvidence(event.eventId, content, matchRange));
  }

  if (count < threshold) return null;
  return {
    id: bf001Rule.id,
    pattern: bf001Rule.pattern,
    type: bf001Rule.type || "Unknown",
    severity: (bf001Rule.severity || "MEDIUM").toUpperCase(),
    description: bf001Rule.description || "",
    count,
    eventIds: events.map((event) => event.eventId),
    evidence
  };
}

function evaluateBruteForceContext(rawInput, events) {
  if (typeof rawInput !== "string" || !Array.isArray(events)) {
    return { handled: false, match: null };
  }

  const legacyCount = countPatternMatches(rawInput, bf001Rule);
  const relevantEvents = [];
  let normalizedMatchCount = 0;

  for (const event of events) {
    const content = eventContent(event);
    const eventMatchCount = countPatternMatches(content, bf001Rule);
    if (!eventMatchCount) continue;

    normalizedMatchCount += eventMatchCount;
    // Multiple regex hits in one event cannot safely be timed/grouped as separate events.
    if (eventMatchCount !== 1 || !hasRequiredContext(event)) {
      return { handled: false, match: null };
    }
    relevantEvents.push(event);
  }

  // Every legacy regex hit must be represented by exactly one fully structured event.
  if (legacyCount !== normalizedMatchCount) return { handled: false, match: null };

  const groups = correlateEvents(relevantEvents, {
    field: "clientIp",
    windowMs: BF001_CORRELATION_WINDOW_MS
  });
  const threshold = Number(bf001Rule.repeatThreshold) || 1;
  const qualifyingGroups = groups.filter((group) => group.count >= threshold);

  return {
    handled: true,
    match: makeContextMatch(qualifyingGroups, relevantEvents)
  };
}

function applyBruteForceContext(detection, contextResult) {
  if (!contextResult?.handled) return detection;

  const originalMatches = Array.isArray(detection?.matchedRules) ? detection.matchedRules : [];
  const hadBruteForceMatch = originalMatches.some((rule) => rule.id === BF001_RULE_ID);
  const matchedRules = originalMatches.filter((rule) => rule.id !== BF001_RULE_ID);
  if (contextResult.match) {
    const targetOrder = ruleOrder.get(BF001_RULE_ID);
    const insertIndex = matchedRules.findIndex((rule) => (ruleOrder.get(rule.id) ?? Infinity) > targetOrder);
    if (insertIndex < 0) matchedRules.push(contextResult.match);
    else matchedRules.splice(insertIndex, 0, contextResult.match);
  }

  if (!hadBruteForceMatch && !contextResult.match) return detection;
  if (matchedRules.length === 0) {
    return {
      ...detection,
      status: "clean",
      type: "None",
      severity: "LOW",
      matchedRules
    };
  }

  const topRule = matchedRules
    .slice()
    .sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))[0];
  return {
    ...detection,
    status: "threat_detected",
    type: topRule.type,
    severity: topRule.severity,
    matchedRules
  };
}

module.exports = {
  BF001_CORRELATION_WINDOW_MS,
  evaluateBruteForceContext,
  applyBruteForceContext
};
