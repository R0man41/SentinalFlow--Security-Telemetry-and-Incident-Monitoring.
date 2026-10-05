const { createHash, randomUUID } = require("crypto");
const net = require("net");
const {
  parseIsoTimestamp,
  HTTP_METHODS,
  MAX_HTTP_BODY_BYTES_PER_EVENT
} = require("./logParserService");
const { HttpError } = require("../utils/httpError");

const EVENT_FIELDS = new Set([
  "timestamp", "source", "externalEventId", "message", "clientIp", "user", "result", "http", "process", "destination"
]);
const HTTP_FIELDS = new Set(["method", "url", "path", "query", "userAgent", "body"]);
const PROCESS_FIELDS = new Set(["name", "command"]);
const DESTINATION_FIELDS = new Set(["ip", "host"]);
const TIMESTAMP_FORMAT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/i;

const STRING_LIMITS = {
  timestamp: 64,
  source: 128,
  externalEventId: 128,
  message: 8192,
  clientIp: 45,
  user: 256,
  result: 128,
  "http.method": 16,
  "http.url": 2048,
  "http.path": 2048,
  "http.query": 4096,
  "http.userAgent": 1024,
  "process.name": 256,
  "process.command": 4096,
  "destination.ip": 45,
  "destination.host": 253
};

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isPlainObject(value)) throw new HttpError(400, `${label} must be a JSON object`);
}

function rejectUnknownFields(value, allowedFields, label) {
  const unknown = Object.keys(value).find((field) => !allowedFields.has(field));
  if (unknown) throw new HttpError(400, `Unsupported ${label} field: ${unknown}`);
}

function validateString(value, field, { allowEmpty = false, maxBytes = STRING_LIMITS[field] } = {}) {
  if (typeof value !== "string") throw new HttpError(400, `${field} must be a string`);
  if (!allowEmpty && !value.trim()) throw new HttpError(400, `${field} must be a non-empty string`);
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new HttpError(400, `${field} must not exceed ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function normalizeTimestamp(value) {
  const timestamp = validateString(value, "timestamp").trim();
  const normalized = parseIsoTimestamp(timestamp);
  if (!TIMESTAMP_FORMAT.test(timestamp) || !normalized) {
    throw new HttpError(400, "timestamp must be a valid ISO-8601 timestamp with an explicit timezone or offset");
  }
  return normalized;
}

function normalizeExternalEventId(value) {
  const rawExternalEventId = validateString(value, "externalEventId");
  if (/[\u0000-\u001f\u007f-\u009f]/.test(rawExternalEventId)) {
    throw new HttpError(400, "externalEventId must not contain control characters");
  }
  const externalEventId = rawExternalEventId.trim();
  if (!externalEventId) throw new HttpError(400, "externalEventId must be a non-empty string");
  return externalEventId;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== "object") return value;
  return Object.keys(value).sort().reduce((result, key) => {
    if (value[key] !== undefined) result[key] = canonicalize(value[key]);
    return result;
  }, {});
}

function fingerprintExternalEvent(event) {
  const senderEvent = Object.fromEntries(Object.entries(event || {}).filter(([key]) =>
    key !== "eventId" && key !== "externalEventId"
  ));
  return createHash("sha256").update(JSON.stringify(canonicalize(senderEvent))).digest("hex");
}

function normalizeHttp(value) {
  requireObject(value, "http");
  rejectUnknownFields(value, HTTP_FIELDS, "http");

  const http = {};
  for (const field of ["url", "path", "query", "userAgent"]) {
    if (value[field] === undefined) continue;
    const limitField = field === "userAgent" ? "http.userAgent" : `http.${field}`;
    http[field] = validateString(value[field], limitField).trim();
  }

  if (value.method !== undefined) {
    const method = validateString(value.method, "http.method").trim().toUpperCase();
    if (!HTTP_METHODS.has(method)) {
      throw new HttpError(400, "http.method must be a supported HTTP method");
    }
    http.method = method;
  }

  if (value.body !== undefined) {
    http.body = validateString(value.body, "http.body", {
      allowEmpty: true,
      maxBytes: MAX_HTTP_BODY_BYTES_PER_EVENT
    });
  }

  return Object.keys(http).length ? http : undefined;
}

function normalizeProcess(value) {
  requireObject(value, "process");
  rejectUnknownFields(value, PROCESS_FIELDS, "process");

  const process = {};
  for (const field of PROCESS_FIELDS) {
    if (value[field] !== undefined) process[field] = validateString(value[field], `process.${field}`).trim();
  }
  return Object.keys(process).length ? process : undefined;
}

function normalizeDestination(value) {
  requireObject(value, "destination");
  rejectUnknownFields(value, DESTINATION_FIELDS, "destination");

  const destination = {};
  if (value.ip !== undefined) {
    const ip = validateString(value.ip, "destination.ip").trim();
    if (net.isIP(ip) === 0) throw new HttpError(400, "destination.ip must be a valid IPv4 or IPv6 address");
    destination.ip = ip;
  }
  if (value.host !== undefined) destination.host = validateString(value.host, "destination.host").trim();
  return Object.keys(destination).length ? destination : undefined;
}

function createEventBatch(input) {
  requireObject(input, "Event body");
  rejectUnknownFields(input, EVENT_FIELDS, "event");

  const source = validateString(input.source, "source").trim();
  const message = validateString(input.message, "message");
  const batchId = `LOG-BATCH-${randomUUID()}`;
  const receivedAt = new Date().toISOString();
  const event = {
    eventId: `${batchId}-EVENT-1`,
    message,
    rawMessage: message,
    source: { service: source }
  };

  if (input.externalEventId !== undefined) {
    event.externalEventId = normalizeExternalEventId(input.externalEventId);
  }
  if (input.timestamp !== undefined) event.eventTime = normalizeTimestamp(input.timestamp);
  if (input.clientIp !== undefined) {
    const clientIp = validateString(input.clientIp, "clientIp").trim();
    if (net.isIP(clientIp) === 0) throw new HttpError(400, "clientIp must be a valid IPv4 or IPv6 address");
    event.clientIp = clientIp;
  }
  if (input.user !== undefined) event.actor = { user: validateString(input.user, "user").trim() };
  if (input.result !== undefined) {
    event.authentication = { result: validateString(input.result, "result").trim().toLowerCase() };
  }

  if (input.http !== undefined) {
    const http = normalizeHttp(input.http);
    if (http) event.http = http;
  }
  if (input.process !== undefined) {
    const process = normalizeProcess(input.process);
    if (process) event.process = process;
  }
  if (input.destination !== undefined) {
    const destination = normalizeDestination(input.destination);
    if (destination) event.destination = destination;
  }

  return {
    batchId,
    receivedAt,
    // The existing raw detector examines the supplied message. Structured
    // fields remain available to event-aware detectors through `events`.
    rawInput: message,
    events: [event]
  };
}

module.exports = { createEventBatch, fingerprintExternalEvent, STRING_LIMITS };
