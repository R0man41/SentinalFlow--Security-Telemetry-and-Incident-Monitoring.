const net = require("net");
const { parseIsoTimestamp } = require("./logParserService");
const { recentEventStore, isHttpRequestEvent, MAX_EVENTS } = require("./recentEventStore");

const DEFAULT_REQUEST_THRESHOLD = 20;
const MIN_REQUEST_THRESHOLD = 4;
const MAX_REQUEST_THRESHOLD = 1000;
const DEFAULT_REQUEST_WINDOW_MS = 60 * 1000;
const MIN_REQUEST_WINDOW_MS = 1000;
const MAX_REQUEST_WINDOW_MS = 4 * 60 * 1000;

function boundedInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

const REQUEST_THRESHOLD = boundedInteger(
  process.env.BEHAVIOR_REQUEST_THRESHOLD,
  DEFAULT_REQUEST_THRESHOLD,
  MIN_REQUEST_THRESHOLD,
  MAX_REQUEST_THRESHOLD
);
const REQUEST_WINDOW_MS = boundedInteger(
  process.env.BEHAVIOR_REQUEST_WINDOW_SECONDS,
  DEFAULT_REQUEST_WINDOW_MS / 1000,
  MIN_REQUEST_WINDOW_MS / 1000,
  MAX_REQUEST_WINDOW_MS / 1000
) * 1000;

function validTimestamp(event) {
  const normalized = parseIsoTimestamp(event?.eventTime);
  return normalized ? Date.parse(normalized) : null;
}

function createBehavioralDetector({
  store = recentEventStore,
  threshold = REQUEST_THRESHOLD,
  windowMs = REQUEST_WINDOW_MS,
  maxActiveIps = MAX_EVENTS
} = {}) {
  const requestThreshold = boundedInteger(threshold, REQUEST_THRESHOLD, MIN_REQUEST_THRESHOLD, MAX_REQUEST_THRESHOLD);
  const requestWindowMs = boundedInteger(windowMs, REQUEST_WINDOW_MS, MIN_REQUEST_WINDOW_MS, MAX_REQUEST_WINDOW_MS);
  const activeIpLimit = boundedInteger(maxActiveIps, MAX_EVENTS, 1, MAX_EVENTS);
  const activeAlerts = new Map();
  const stateVersions = new Map();
  let nextStateVersion = 0;

  function recordStateVersion(clientIp) {
    stateVersions.delete(clientIp);
    const version = ++nextStateVersion;
    stateVersions.set(clientIp, version);
    while (stateVersions.size > activeIpLimit) {
      stateVersions.delete(stateVersions.keys().next().value);
    }
    return version;
  }

  function capturePosition(clientIp) {
    const previous = activeAlerts.get(clientIp);
    return {
      previous,
      previousIndex: previous === undefined ? -1 : [...activeAlerts.keys()].indexOf(clientIp)
    };
  }

  function restorePosition(clientIp, previous, previousIndex) {
    activeAlerts.delete(clientIp);
    if (previous === undefined) return;

    const entries = [...activeAlerts.entries()];
    const index = Math.max(0, Math.min(previousIndex, entries.length));
    entries.splice(index, 0, [clientIp, previous]);
    activeAlerts.clear();
    for (const [key, value] of entries) activeAlerts.set(key, value);
    while (activeAlerts.size > activeIpLimit) {
      const evictedIp = activeAlerts.keys().next().value;
      activeAlerts.delete(evictedIp);
      if (evictedIp !== clientIp) recordStateVersion(evictedIp);
    }
  }

  function markActive(clientIp) {
    const { previous, previousIndex } = capturePosition(clientIp);
    activeAlerts.delete(clientIp);
    const version = recordStateVersion(clientIp);
    const entry = { version };
    activeAlerts.set(clientIp, entry);
    while (activeAlerts.size > activeIpLimit) {
      const evictedIp = activeAlerts.keys().next().value;
      activeAlerts.delete(evictedIp);
      if (evictedIp !== clientIp) recordStateVersion(evictedIp);
    }

    return () => {
      if (activeAlerts.get(clientIp) !== entry || stateVersions.get(clientIp) !== version) return;
      restorePosition(clientIp, previous, previousIndex);
      recordStateVersion(clientIp);
    };
  }

  function clearActive(clientIp) {
    if (!activeAlerts.has(clientIp)) return null;
    const { previous, previousIndex } = capturePosition(clientIp);
    activeAlerts.delete(clientIp);
    const version = recordStateVersion(clientIp);

    return () => {
      if (stateVersions.get(clientIp) !== version || activeAlerts.has(clientIp)) return;
      restorePosition(clientIp, previous, previousIndex);
      recordStateVersion(clientIp);
    };
  }

  function trackRollback(context, rollback) {
    if (rollback && Array.isArray(context.stateRollbackActions)) {
      context.stateRollbackActions.push(rollback);
    }
  }

  function detect(context) {
    if (context.useRecentEventState !== true || !Array.isArray(context.events) || context.events.length !== 1) {
      return { findingCandidates: [] };
    }

    const current = context.events[0];
    if (
      typeof current?.clientIp !== "string" ||
      net.isIP(current.clientIp) === 0 ||
      (current.httpRequest !== true && !isHttpRequestEvent(current))
    ) {
      return { findingCandidates: [] };
    }
    const currentTime = validTimestamp(current);
    if (currentTime === null) return { findingCandidates: [] };

    const eventsById = new Map();
    const recentEvents = Array.isArray(context.recentEvents) ? context.recentEvents : store.getRecentEvents();
    for (const event of recentEvents) {
      if (event.clientIp !== current.clientIp || event.httpRequest !== true) continue;
      const eventTime = validTimestamp(event);
      if (eventTime === null || eventTime < currentTime - requestWindowMs || eventTime > currentTime) continue;
      eventsById.set(event.eventId, event);
    }
    // The correlation stage stores before this detector. Set-by-ID makes inclusion explicit
    // without counting the current event twice if a custom pipeline already added it.
    eventsById.set(current.eventId, { ...current, httpRequest: true });

    const qualifyingEvents = [...eventsById.values()]
      .sort((left, right) => validTimestamp(left) - validTimestamp(right) || left.eventId.localeCompare(right.eventId));
    if (qualifyingEvents.length < requestThreshold) {
      trackRollback(context, clearActive(current.clientIp));
      return { findingCandidates: [] };
    }

    if (activeAlerts.has(current.clientIp)) {
      trackRollback(context, markActive(current.clientIp));
      return { findingCandidates: [] };
    }

    const candidate = {
      detectorType: "behavioral",
      detectorId: "request-volume",
      type: "High Request Volume",
      severity: "MEDIUM",
      summary: `Client ${current.clientIp} generated ${qualifyingEvents.length} HTTP requests within ${requestWindowMs / 1000} seconds.`,
      count: qualifyingEvents.length,
      eventIds: qualifyingEvents.map((event) => event.eventId),
      evidence: []
    };
    trackRollback(context, markActive(current.clientIp));
    return {
      findingCandidates: [candidate]
    };
  }

  return {
    detect,
    clearActiveAlerts() {
      activeAlerts.clear();
      stateVersions.clear();
    },
    activeAlertCount() { return activeAlerts.size; }
  };
}

const defaultDetector = createBehavioralDetector();

module.exports = {
  DEFAULT_REQUEST_THRESHOLD,
  MIN_REQUEST_THRESHOLD,
  MAX_REQUEST_THRESHOLD,
  DEFAULT_REQUEST_WINDOW_MS,
  MIN_REQUEST_WINDOW_MS,
  MAX_REQUEST_WINDOW_MS,
  REQUEST_THRESHOLD,
  REQUEST_WINDOW_MS,
  createBehavioralDetector,
  detect: defaultDetector.detect,
  clearActiveAlerts: defaultDetector.clearActiveAlerts,
  activeAlertCount: defaultDetector.activeAlertCount
};
