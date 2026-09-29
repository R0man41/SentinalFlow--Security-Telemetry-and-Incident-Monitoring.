const { randomUUID } = require("crypto");
const { parseIsoTimestamp } = require("./logParserService");

const GROUPING_FIELDS = {
  clientIp: (event) => event?.clientIp,
  "actor.user": (event) => event?.actor?.user,
  "source.ip": (event) => event?.source?.ip
};

function normalizeEventTime(eventTime) {
  const normalized = parseIsoTimestamp(eventTime);
  if (!normalized) return null;
  const timestamp = Date.parse(normalized);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function makeGroup(key, timestamp) {
  const group = {
    groupId: `GROUP-${randomUUID()}`,
    eventIds: [],
    key,
    count: 0
  };
  const state = { group, timed: timestamp !== null, minTime: timestamp, maxTime: timestamp };
  if (timestamp !== null) {
    group.firstEventTime = new Date(timestamp).toISOString();
    group.lastEventTime = new Date(timestamp).toISOString();
  }
  return state;
}

function addEventToGroup(state, event, timestamp) {
  if (typeof event.eventId === "string" && event.eventId.length > 0) state.group.eventIds.push(event.eventId);
  state.group.count += 1;

  if (timestamp !== null) {
    if (!state.timed) {
      state.timed = true;
      state.minTime = timestamp;
      state.maxTime = timestamp;
    } else {
      state.minTime = Math.min(state.minTime, timestamp);
      state.maxTime = Math.max(state.maxTime, timestamp);
    }
    state.group.firstEventTime = new Date(state.minTime).toISOString();
    state.group.lastEventTime = new Date(state.maxTime).toISOString();
  }
}

function correlateEvents(events, options = {}) {
  if (!Array.isArray(events)) throw new TypeError("Events must be an array");
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Correlation options must be an object");
  }

  const { field, windowMs } = options;
  const readGroupingField = GROUPING_FIELDS[field];
  if (!readGroupingField) throw new RangeError(`Unsupported correlation field: ${field}`);
  if (windowMs !== undefined && (!Number.isFinite(windowMs) || windowMs < 0)) {
    throw new RangeError("windowMs must be a finite non-negative number");
  }

  const groups = [];
  const groupsByKey = new Map();

  for (const event of events) {
    const value = readGroupingField(event);
    if (typeof value !== "string" || !value.trim()) continue;

    const key = `${field}=${value}`;
    const timestamp = normalizeEventTime(event?.eventTime);
    let matchingGroup = null;
    const keyGroups = groupsByKey.get(key) || [];

    if (windowMs === undefined) {
      matchingGroup = keyGroups[0] || null;
    } else if (timestamp === null) {
      // Untimed events group by key, separately from timed groups; no time is inferred.
      matchingGroup = keyGroups.find((state) => !state.timed) || null;
    } else {
      matchingGroup = keyGroups.find((state) =>
        state.timed && Math.max(state.maxTime, timestamp) - Math.min(state.minTime, timestamp) <= windowMs
      ) || null;
    }

    if (!matchingGroup) {
      matchingGroup = makeGroup(key, timestamp);
      keyGroups.push(matchingGroup);
      groupsByKey.set(key, keyGroups);
      groups.push(matchingGroup.group);
    }

    addEventToGroup(matchingGroup, event, timestamp);
  }

  return groups;
}

module.exports = { correlateEvents, GROUPING_FIELDS };
