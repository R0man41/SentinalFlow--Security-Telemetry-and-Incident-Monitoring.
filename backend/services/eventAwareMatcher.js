const detectionRules = require("../../data/detection_rules.json");
const { countPatternMatches, findFirstPatternMatch } = require("./logAnalysisService");
const { EVENT_AWARE_RULES } = require("./eventAwareRules");

const MAX_EVIDENCE_EXCERPT_LENGTH = 200;
const MAX_EVIDENCE_PER_RULE = 5;
const SEVERITY_WEIGHT = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const ruleById = new Map(detectionRules.map((rule) => [rule.id, rule]));
const eventAwareRuleById = new Map(EVENT_AWARE_RULES.map((rule) => [rule.ruleId, rule]));
const ruleOrder = new Map(detectionRules.map((rule, index) => [rule.id, index]));

function readEventField(event, fieldPath) {
  let value = event;
  for (const field of fieldPath) value = value?.[field];
  return typeof value === "string" ? value : undefined;
}

function createEvidence(eventId, value, matchRange) {
  const matchLength = Math.min(matchRange.end - matchRange.start, MAX_EVIDENCE_EXCERPT_LENGTH);
  const excerptStart = value.length <= MAX_EVIDENCE_EXCERPT_LENGTH
    ? 0
    : Math.max(0, Math.min(
      matchRange.start - Math.floor((MAX_EVIDENCE_EXCERPT_LENGTH - matchLength) / 2),
      value.length - MAX_EVIDENCE_EXCERPT_LENGTH
    ));

  return {
    eventId,
    excerpt: value.slice(excerptStart, excerptStart + MAX_EVIDENCE_EXCERPT_LENGTH),
    start: matchRange.start,
    end: matchRange.end
  };
}

function matchEventAwareRule(events, ruleId) {
  const eventAwareRule = eventAwareRuleById.get(ruleId);
  const definition = ruleById.get(ruleId);
  if (!eventAwareRule || !definition || !Array.isArray(events)) return null;
  const matchingDefinition = eventAwareRule.pattern
    ? { ...definition, pattern: eventAwareRule.pattern }
    : definition;

  let count = 0;
  const evidence = [];
  for (const event of events) {
    let eventEvidence = null;
    for (const fieldPath of eventAwareRule.fields) {
      const value = readEventField(event, fieldPath);
      if (value === undefined) continue;
      const fieldMatchCount = countPatternMatches(value, matchingDefinition);
      count += fieldMatchCount;
      if (!eventEvidence && fieldMatchCount > 0 && typeof event?.eventId === "string" && event.eventId) {
        const matchRange = findFirstPatternMatch(value, matchingDefinition);
        if (matchRange) eventEvidence = createEvidence(event.eventId, value, matchRange);
      }
    }
    if (eventEvidence && evidence.length < MAX_EVIDENCE_PER_RULE) evidence.push(eventEvidence);
  }
  if (!count) return null;

  return {
    id: definition.id,
    pattern: definition.pattern,
    type: definition.type || "Unknown",
    severity: (definition.severity || "MEDIUM").toUpperCase(),
    description: definition.description || "",
    count,
    evidence
  };
}

function matchEventAwareRules(events) {
  return EVENT_AWARE_RULES
    .map(({ ruleId }) => matchEventAwareRule(events, ruleId))
    .filter(Boolean);
}

function mergeEventAwareMatches(detection, eventMatches) {
  if (!Array.isArray(eventMatches) || eventMatches.length === 0) return detection;

  const matchedRules = Array.isArray(detection?.matchedRules) ? detection.matchedRules.slice() : [];
  let changed = false;
  const seenEventMatchIds = new Set();

  for (const eventMatch of eventMatches) {
    if (!eventMatch || !eventAwareRuleById.has(eventMatch.id) || seenEventMatchIds.has(eventMatch.id)) continue;
    seenEventMatchIds.add(eventMatch.id);

    // Preserve the raw detector's match object and count when both paths match.
    const existingIndex = matchedRules.findIndex((rule) => rule.id === eventMatch.id);
    if (existingIndex >= 0) {
      if (Array.isArray(eventMatch.evidence) && eventMatch.evidence.length) {
        matchedRules[existingIndex] = { ...matchedRules[existingIndex], evidence: eventMatch.evidence };
        changed = true;
      }
      continue;
    }

    const targetOrder = ruleOrder.get(eventMatch.id) ?? Infinity;
    const insertIndex = matchedRules.findIndex((rule) => (ruleOrder.get(rule.id) ?? Infinity) > targetOrder);
    if (insertIndex < 0) matchedRules.push(eventMatch);
    else matchedRules.splice(insertIndex, 0, eventMatch);
    changed = true;
  }

  if (!changed) return detection;

  const topRule = matchedRules
    .slice()
    .sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))[0];

  return {
    ...detection,
    status: "threat_detected",
    type: topRule?.type || "Unknown",
    severity: topRule?.severity || "MEDIUM",
    matchedRules
  };
}

function stripInternalEvidence(detection) {
  if (!Array.isArray(detection?.matchedRules)) return detection;
  return {
    ...detection,
    matchedRules: detection.matchedRules.map(({ evidence, eventIds, ...rule }) => rule)
  };
}

module.exports = {
  MAX_EVIDENCE_EXCERPT_LENGTH,
  MAX_EVIDENCE_PER_RULE,
  createEvidence,
  matchEventAwareRule,
  matchEventAwareRules,
  mergeEventAwareMatches,
  stripInternalEvidence
};
