const { BF001_CORRELATION_WINDOW_MS } = require("./bruteForceCorrelationService");
const { HTTP_METHODS } = require("./logParserService");

const DEFAULT_MAX_EVENTS = 1000;
const HARD_MAX_EVENTS = 10000;
const DEFAULT_RETENTION_MS = 10 * 60 * 1000;
const MAX_RETENTION_MS = 60 * 60 * 1000;
const DEDUP_RETENTION_MS = 60 * 60 * 1000;
const EXTERNAL_IDENTITY_STATES = Object.freeze({
  PROCESSING: "PROCESSING",
  COMPLETED: "COMPLETED",
  FAILED: "FAILED"
});

function isHttpRequestEvent(event) {
  const http = event?.http;
  if (!http || typeof http !== "object" || Array.isArray(http)) return false;
  const method = typeof http.method === "string" ? http.method.toUpperCase() : "";
  return HTTP_METHODS.has(method) ||
    (typeof http.path === "string" && http.path.trim().length > 0) ||
    (typeof http.url === "string" && http.url.trim().length > 0);
}

function boundedInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

const MAX_EVENTS = boundedInteger(process.env.RECENT_EVENT_MAX_COUNT, DEFAULT_MAX_EVENTS, 1, HARD_MAX_EVENTS);
const RETENTION_MS = boundedInteger(
  process.env.RECENT_EVENT_RETENTION_MS,
  DEFAULT_RETENTION_MS,
  BF001_CORRELATION_WINDOW_MS,
  MAX_RETENTION_MS
);

function minimalEvent(event, { includeMessage = true } = {}) {
  const result = {
    eventId: event.eventId,
    eventTime: event.eventTime,
    clientIp: event.clientIp,
    httpRequest: isHttpRequestEvent(event)
  };
  if (includeMessage && typeof event?.authentication?.result === "string") {
    result.authentication = Object.freeze({ result: event.authentication.result });
  }
  if (includeMessage && typeof event.message === "string") result.message = event.message;
  return Object.freeze(result);
}

function createRecentEventStore({
  maxEvents = MAX_EVENTS,
  retentionMs = RETENTION_MS,
  dedupRetentionMs = DEDUP_RETENTION_MS,
  dedupMaxEntries,
  now = Date.now
} = {}) {
  const capacity = boundedInteger(maxEvents, MAX_EVENTS, 1, HARD_MAX_EVENTS);
  const ageLimit = boundedInteger(retentionMs, RETENTION_MS, BF001_CORRELATION_WINDOW_MS, MAX_RETENTION_MS);
  const records = [];
  const dedupCapacity = boundedInteger(dedupMaxEntries, capacity, 1, HARD_MAX_EVENTS);
  const dedupAgeLimit = boundedInteger(dedupRetentionMs, DEDUP_RETENTION_MS, 1, MAX_RETENTION_MS);
  const dedupRecords = new Map();

  function purgeExpired(at = now()) {
    const cutoff = at - ageLimit;
    let firstRetained = 0;
    while (firstRetained < records.length && records[firstRetained].storedAt <= cutoff) firstRetained += 1;
    if (firstRetained) records.splice(0, firstRetained);
  }

  function purgeExpiredDedupRecords(at = now()) {
    for (const [key, record] of dedupRecords) {
      if (record.receivedAt + dedupAgeLimit <= at) dedupRecords.delete(key);
    }
  }

  function identityKey(sourceService, externalEventId) {
    return JSON.stringify([sourceService, externalEventId]);
  }

  function registerProcessing({ sourceService, externalEventId, eventId, fingerprint }) {
    if ([sourceService, externalEventId, eventId, fingerprint].some((value) => typeof value !== "string" || !value)) {
      throw new TypeError("External event identity requires source, external ID, internal ID, and fingerprint");
    }

    const receivedAt = now();
    purgeExpiredDedupRecords(receivedAt);
    const key = identityKey(sourceService, externalEventId);
    const existing = dedupRecords.get(key);
    if (existing) {
      if (existing.fingerprint !== fingerprint) return { status: "conflict" };
      if (existing.state === EXTERNAL_IDENTITY_STATES.PROCESSING) {
        return { status: "processing", eventId: existing.eventId };
      }
      if (existing.state === EXTERNAL_IDENTITY_STATES.COMPLETED) {
        return { status: "completed", eventId: existing.eventId };
      }

      // Retrying a failed identity preserves both its original internal ID and
      // its original expiry time.
      existing.state = EXTERNAL_IDENTITY_STATES.PROCESSING;
      return { status: "retry", eventId: existing.eventId };
    }

    while (dedupRecords.size >= dedupCapacity) {
      dedupRecords.delete(dedupRecords.keys().next().value);
    }
    dedupRecords.set(key, {
      sourceService,
      externalEventId,
      eventId,
      receivedAt,
      fingerprint,
      state: EXTERNAL_IDENTITY_STATES.PROCESSING
    });
    return { status: "new", eventId };
  }

  function transitionIdentity(identity, state) {
    const { sourceService, externalEventId, eventId, fingerprint } = identity || {};
    const record = dedupRecords.get(identityKey(sourceService, externalEventId));
    if (!record || record.eventId !== eventId || record.fingerprint !== fingerprint ||
        record.state !== EXTERNAL_IDENTITY_STATES.PROCESSING) return false;
    record.state = state;
    return true;
  }

  function getExternalEventIdentity(sourceService, externalEventId) {
    purgeExpiredDedupRecords();
    const record = dedupRecords.get(identityKey(sourceService, externalEventId));
    if (!record) return null;
    return {
      state: record.state,
      eventId: record.eventId,
      fingerprint: record.fingerprint,
      receivedAt: record.receivedAt
    };
  }

  return {
    add(event, options) {
      const storedAt = now();
      purgeExpired(storedAt);
      if (records.length >= capacity) records.splice(0, records.length - capacity + 1);
      records.push({ storedAt, event: minimalEvent(event, options) });
    },
    removeEvent(eventId) {
      for (let index = records.length - 1; index >= 0; index -= 1) {
        if (records[index].event.eventId === eventId) records.splice(index, 1);
      }
    },
    getRecentEvents() {
      purgeExpired();
      return records.map(({ event }) => event);
    },
    size() {
      purgeExpired();
      return records.length;
    },
    registerProcessing,
    markCompleted(identity) {
      return transitionIdentity(identity, EXTERNAL_IDENTITY_STATES.COMPLETED);
    },
    markFailed(identity) {
      return transitionIdentity(identity, EXTERNAL_IDENTITY_STATES.FAILED);
    },
    getExternalEventIdentity,
    dedupSize() {
      purgeExpiredDedupRecords();
      return dedupRecords.size;
    },
    clear() {
      records.length = 0;
      dedupRecords.clear();
    }
  };
}

const recentEventStore = createRecentEventStore();

module.exports = {
  DEFAULT_MAX_EVENTS,
  HARD_MAX_EVENTS,
  DEFAULT_RETENTION_MS,
  MAX_RETENTION_MS,
  DEDUP_RETENTION_MS,
  EXTERNAL_IDENTITY_STATES,
  MAX_EVENTS,
  RETENTION_MS,
  createRecentEventStore,
  isHttpRequestEvent,
  recentEventStore
};
