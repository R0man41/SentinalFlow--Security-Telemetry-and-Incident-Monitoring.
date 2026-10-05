const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  createRecentEventStore,
  DEFAULT_MAX_EVENTS,
  DEFAULT_RETENTION_MS,
  HARD_MAX_EVENTS,
  MAX_EVENTS,
  RETENTION_MS,
  DEDUP_RETENTION_MS,
  EXTERNAL_IDENTITY_STATES
} = require("../backend/services/recentEventStore");

function event(eventId) {
  return {
    eventId,
    eventTime: "2026-10-04T10:00:00.000Z",
    clientIp: "203.0.113.10",
    authentication: { result: "failed", secret: "discard me" },
    message: "Login failed",
    rawMessage: "raw payload",
    http: { body: "sensitive request body" },
    arbitraryMetadata: { keep: false }
  };
}

describe("recent event store", () => {
  it("adds and retrieves a minimal immutable normalized event", () => {
    const store = createRecentEventStore();
    store.add(event("evt-1"));
    const [stored] = store.getRecentEvents();

    assert.equal(stored.eventId, "evt-1");
    assert.equal(stored.message, "Login failed");
    assert.equal(stored.authentication.result, "failed");
    assert.deepEqual(Object.keys(stored).sort(), ["authentication", "clientIp", "eventId", "eventTime", "httpRequest", "message"]);
    assert.equal(Object.isFrozen(stored), true);
    assert.equal(Object.isFrozen(stored.authentication), true);
    assert.equal(JSON.stringify(stored).includes("sensitive"), false);
  });

  it("excludes and cleans expired entries using arrival time", () => {
    let now = 1000;
    const store = createRecentEventStore({ retentionMs: 5 * 60 * 1000, now: () => now });
    store.add(event("evt-old"));
    now += 5 * 60 * 1000 + 1;

    assert.deepEqual(store.getRecentEvents(), []);
    assert.equal(store.size(), 0);
  });

  it("enforces capacity and evicts the oldest entry first", () => {
    const store = createRecentEventStore({ maxEvents: 2 });
    store.add(event("evt-1"));
    store.add(event("evt-2"));
    store.add(event("evt-3"));

    assert.deepEqual(store.getRecentEvents().map((item) => item.eventId), ["evt-2", "evt-3"]);
    assert.equal(store.size(), 2);
  });

  it("clears state and keeps separate store instances isolated", () => {
    const first = createRecentEventStore();
    const second = createRecentEventStore();
    first.add(event("evt-1"));

    assert.equal(first.size(), 1);
    assert.equal(second.size(), 0);
    first.clear();
    assert.equal(first.size(), 0);
  });

  it("deduplicates by source and external ID without extending first receipt expiry", () => {
    let now = 10_000;
    const store = createRecentEventStore({ now: () => now, dedupRetentionMs: 60 * 60 * 1000 });
    const identity = {
      sourceService: "demo-app",
      externalEventId: "APP-1",
      eventId: "internal-1",
      fingerprint: "fingerprint-a"
    };

    assert.deepEqual(store.registerProcessing(identity), { status: "new", eventId: "internal-1" });
    assert.equal(store.getExternalEventIdentity("demo-app", "APP-1").state, EXTERNAL_IDENTITY_STATES.PROCESSING);
    assert.deepEqual(store.registerProcessing({ ...identity, eventId: "concurrent-retry" }), {
      status: "processing", eventId: "internal-1"
    });
    assert.equal(store.markCompleted(identity), true);
    assert.equal(store.getExternalEventIdentity("demo-app", "APP-1").state, EXTERNAL_IDENTITY_STATES.COMPLETED);
    now += 30 * 60 * 1000;
    assert.deepEqual(store.registerProcessing({ ...identity, eventId: "internal-retry" }), {
      status: "completed", eventId: "internal-1"
    });
    assert.equal(store.dedupSize(), 1);

    now += 30 * 60 * 1000;
    assert.deepEqual(store.registerProcessing({ ...identity, eventId: "internal-after-expiry" }), {
      status: "new", eventId: "internal-after-expiry"
    });
  });

  it("keeps same external IDs separate across sources and reports fingerprint conflicts", () => {
    const store = createRecentEventStore();
    const common = { externalEventId: "APP-1", eventId: "internal-1", fingerprint: "fingerprint-a" };

    assert.equal(store.registerProcessing({ ...common, sourceService: "demo-app" }).status, "new");
    assert.deepEqual(store.registerProcessing({
      ...common, sourceService: "demo-app", eventId: "internal-2", fingerprint: "fingerprint-b"
    }), { status: "conflict" });
    assert.equal(store.registerProcessing({ ...common, sourceService: "another-app" }).status, "new");
    assert.equal(store.dedupSize(), 2);
  });

  it("bounds deduplication metadata with the configured recent-event capacity", () => {
    const store = createRecentEventStore({ maxEvents: 2 });
    for (const [sourceService, externalEventId, eventId] of [
      ["a", "1", "i1"], ["a", "2", "i2"], ["a", "3", "i3"]
    ]) {
      store.registerProcessing({ sourceService, externalEventId, eventId, fingerprint: eventId });
    }

    assert.equal(store.dedupSize(), 2);
    assert.equal(store.registerProcessing({
      sourceService: "a", externalEventId: "1", eventId: "i1-retry", fingerprint: "i1"
    }).status, "new");
  });

  it("retries a failed identity with the original event ID and original expiry", () => {
    let now = 10_000;
    const store = createRecentEventStore({ now: () => now, dedupRetentionMs: 60 * 60 * 1000 });
    const identity = {
      sourceService: "demo-app",
      externalEventId: "APP-FAILED",
      eventId: "internal-original",
      fingerprint: "fingerprint-a"
    };
    store.registerProcessing(identity);
    assert.equal(store.markFailed(identity), true);
    assert.equal(store.getExternalEventIdentity("demo-app", "APP-FAILED").state, EXTERNAL_IDENTITY_STATES.FAILED);

    now += 30 * 60 * 1000;
    assert.deepEqual(store.registerProcessing({ ...identity, eventId: "internal-new" }), {
      status: "retry", eventId: "internal-original"
    });
    assert.equal(store.getExternalEventIdentity("demo-app", "APP-FAILED").state, EXTERNAL_IDENTITY_STATES.PROCESSING);
    assert.equal(store.getExternalEventIdentity("demo-app", "APP-FAILED").receivedAt, 10_000);
  });

  it("uses finite demo defaults with a hard capacity ceiling", () => {
    assert.equal(DEFAULT_MAX_EVENTS, 1000);
    assert.equal(DEFAULT_RETENTION_MS, 10 * 60 * 1000);
    assert.equal(DEDUP_RETENTION_MS, 60 * 60 * 1000);
    assert.ok(MAX_EVENTS >= 1 && MAX_EVENTS <= HARD_MAX_EVENTS);
    assert.ok(RETENTION_MS >= 5 * 60 * 1000 && RETENTION_MS <= 60 * 60 * 1000);
  });
});
