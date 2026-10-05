const {
  BF001_CORRELATION_WINDOW_MS,
  BF001_THRESHOLD,
  isBruteForceCorrelationEvent,
  evaluateBruteForceContext,
  applyBruteForceContext
} = require("./bruteForceCorrelationService");
const { correlateEvents } = require("./correlationService");
const { recentEventStore, isHttpRequestEvent } = require("./recentEventStore");
const { parseIsoTimestamp } = require("./logParserService");

function crossRequestBruteForce(context, store = recentEventStore) {
  if (context.useRecentEventState !== true || !Array.isArray(context.events) || context.events.length !== 1) return null;
  const current = context.events[0];
  const hasBruteForceContext = isBruteForceCorrelationEvent(current);
  let correlation = evaluateBruteForceContext(context.rawInput, context.events);

  if (hasBruteForceContext) {
    const currentTime = Date.parse(current.eventTime);
    const prior = store.getRecentEvents().filter((event) =>
      typeof event.message === "string" &&
      event.clientIp === current.clientIp &&
      Math.abs(Date.parse(event.eventTime) - currentTime) <= BF001_CORRELATION_WINDOW_MS
    );
    const ordered = [...prior, current].sort((left, right) =>
      Date.parse(left.eventTime) - Date.parse(right.eventTime) || left.eventId.localeCompare(right.eventId)
    );
    const group = correlateEvents(ordered, { field: "clientIp", windowMs: BF001_CORRELATION_WINDOW_MS })
      .find((candidate) => candidate.eventIds.includes(current.eventId));

    if (!group || group.count - 1 < BF001_THRESHOLD) {
      const groupEvents = group
        ? ordered.filter((event) => group.eventIds.includes(event.eventId))
        : [current];
      correlation = evaluateBruteForceContext(groupEvents.map((event) => event.message).join("\n"), groupEvents);
    } else {
      correlation = { handled: true, match: null };
    }
  }

  // The current normalized event enters shared recent state once before later detectors run.
  const hasTimedHttpContext = isHttpRequestEvent(current) && Boolean(parseIsoTimestamp(current.eventTime));
  if (typeof current.clientIp === "string" && (hasBruteForceContext || hasTimedHttpContext)) {
    store.add(current, { includeMessage: hasBruteForceContext });
  }
  // Freeze the request's view of state before the coordinator yields to a later detector.
  context.recentEvents = store.getRecentEvents();
  return correlation;
}

function detectBruteForceCorrelation(context) {
  const correlation = crossRequestBruteForce(context) || evaluateBruteForceContext(context.rawInput, context.events);
  return {
    detection: applyBruteForceContext(context.detection, correlation)
  };
}

module.exports = { detectBruteForceCorrelation, crossRequestBruteForce };
