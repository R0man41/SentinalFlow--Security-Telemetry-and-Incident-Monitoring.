const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { correlateEvents, GROUPING_FIELDS } = require("../backend/services/correlationService");

function event(eventId, fields = {}, eventTime) {
  return { eventId, ...fields, ...(eventTime === undefined ? {} : { eventTime }) };
}

function at(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function membership(groups) {
  return groups.map(({ key, eventIds, firstEventTime, lastEventTime, count }) => ({
    key, eventIds, firstEventTime, lastEventTime, count
  }));
}

describe("normalized event correlation service", () => {
  it("groups two events with the same explicit field value", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }),
      event("event-2", { clientIp: "192.0.2.10" })
    ], { field: "clientIp" });

    assert.equal(groups.length, 1);
    assert.match(groups[0].groupId, /^GROUP-[0-9a-f-]{36}$/i);
    assert.equal(groups[0].key, "clientIp=192.0.2.10");
    assert.deepEqual(groups[0].eventIds, ["event-1", "event-2"]);
    assert.equal(groups[0].count, 2);
    assert.equal(Object.hasOwn(groups[0], "firstEventTime"), false);
    assert.equal(Object.hasOwn(groups[0], "lastEventTime"), false);
  });

  it("creates separate groups for different keys", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }),
      event("event-2", { clientIp: "192.0.2.11" })
    ], { field: "clientIp" });
    assert.deepEqual(groups.map((group) => group.key), ["clientIp=192.0.2.10", "clientIp=192.0.2.11"]);
    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1"], ["event-2"]]);
  });

  it("preserves input order for group creation and member order", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }),
      event("event-2", { clientIp: "192.0.2.11" }),
      event("event-3", { clientIp: "192.0.2.10" }),
      event("event-4", { clientIp: "192.0.2.10" })
    ], { field: "clientIp" });

    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1", "event-3", "event-4"], ["event-2"]]);
  });

  it("splits same-key timestamped events when their total span exceeds the window", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }, at(0)),
      event("event-2", { clientIp: "192.0.2.10" }, at(10_000)),
      event("event-3", { clientIp: "192.0.2.10" }, at(120_000))
    ], { field: "clientIp", windowMs: 60_000 });

    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1", "event-2"], ["event-3"]]);
    assert.equal(groups[0].firstEventTime, at(0));
    assert.equal(groups[0].lastEventTime, at(10_000));
    assert.equal(groups[1].firstEventTime, at(120_000));
    assert.equal(groups[1].lastEventTime, at(120_000));
  });

  it("includes events exactly on the configured window boundary", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }, at(0)),
      event("event-2", { clientIp: "192.0.2.10" }, at(60_000)),
      event("event-3", { clientIp: "192.0.2.10" }, at(60_001))
    ], { field: "clientIp", windowMs: 60_000 });

    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1", "event-2"], ["event-3"]]);
  });

  it("keeps missing-time events in an untimed same-key group without borrowing timestamps", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }, at(0)),
      event("event-2", { clientIp: "192.0.2.10" }),
      event("event-3", { clientIp: "192.0.2.10" }, at(10_000)),
      event("event-4", { clientIp: "192.0.2.10" })
    ], { field: "clientIp", windowMs: 60_000 });

    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1", "event-3"], ["event-2", "event-4"]]);
    assert.equal(groups[0].firstEventTime, at(0));
    assert.equal(groups[0].lastEventTime, at(10_000));
    assert.equal(Object.hasOwn(groups[1], "firstEventTime"), false);
    assert.equal(Object.hasOwn(groups[1], "lastEventTime"), false);
  });

  it("treats invalid timestamps as untimed and does not mutate events", () => {
    const events = [
      event("event-1", { clientIp: "192.0.2.10" }, "not-a-timestamp"),
      event("event-2", { clientIp: "192.0.2.10" }),
      event("event-3", { clientIp: "192.0.2.10" }, at(5_000))
    ];
    const groups = correlateEvents(events, { field: "clientIp", windowMs: 1_000 });

    assert.deepEqual(groups.map((group) => group.eventIds), [["event-1", "event-2"], ["event-3"]]);
    assert.equal(Object.hasOwn(groups[0], "firstEventTime"), false);
    assert.equal(Object.hasOwn(groups[0], "lastEventTime"), false);
    assert.equal(events[0].eventTime, "not-a-timestamp");
    assert.equal(Object.hasOwn(events[1], "eventTime"), false);
  });

  it("groups by key without a window and records only valid event-time bounds", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }),
      event("event-2", { clientIp: "192.0.2.10" }, at(10_000)),
      event("event-3", { clientIp: "192.0.2.10" }, "invalid"),
      event("event-4", { clientIp: "192.0.2.10" }, at(5_000))
    ], { field: "clientIp" });

    assert.equal(groups.length, 1);
    assert.deepEqual(groups[0].eventIds, ["event-1", "event-2", "event-3", "event-4"]);
    assert.equal(groups[0].firstEventTime, at(5_000));
    assert.equal(groups[0].lastEventTime, at(10_000));
  });

  it("skips events missing the selected grouping field", () => {
    const groups = correlateEvents([
      event("event-1", { clientIp: "192.0.2.10" }),
      event("event-2", { actor: { user: "alice" } })
    ], { field: "clientIp" });
    assert.equal(groups.length, 1);
    assert.deepEqual(groups[0].eventIds, ["event-1"]);
  });

  for (const field of ["clientIp", "actor.user", "source.ip"]) {
    it(`supports the normalized grouping field ${field}`, () => {
      const fields = {
        clientIp: { clientIp: "192.0.2.10" },
        "actor.user": { actor: { user: "alice" } },
        "source.ip": { source: { ip: "198.51.100.5" } }
      }[field];
      const groups = correlateEvents([event("event-1", fields)], { field });
      assert.equal(groups.length, 1);
      assert.deepEqual(groups[0].eventIds, ["event-1"]);
      assert.equal(GROUPING_FIELDS[field] instanceof Function, true);
    });
  }

  it("returns no groups for an empty event list", () => {
    assert.deepEqual(correlateEvents([], { field: "clientIp" }), []);
  });

  it("produces equivalent membership for the same ordered input", () => {
    const events = [
      event("event-1", { actor: { user: "alice" } }, at(0)),
      event("event-2", { actor: { user: "bob" } }, at(10)),
      event("event-3", { actor: { user: "alice" } }, at(20))
    ];

    const first = correlateEvents(events, { field: "actor.user", windowMs: 60_000 });
    const second = correlateEvents(events, { field: "actor.user", windowMs: 60_000 });
    assert.deepEqual(membership(first), membership(second));
    assert.notEqual(first[0].groupId, second[0].groupId);
  });

  it("rejects unsupported fields and invalid time windows", () => {
    assert.throws(() => correlateEvents([], { field: "unknown.path" }), /Unsupported correlation field/);
    assert.throws(() => correlateEvents([], { field: "clientIp", windowMs: -1 }), /windowMs/);
    assert.throws(() => correlateEvents([], { field: "clientIp", windowMs: Infinity }), /windowMs/);
    assert.throws(() => correlateEvents({}, { field: "clientIp" }), /Events must be an array/);
  });
});
