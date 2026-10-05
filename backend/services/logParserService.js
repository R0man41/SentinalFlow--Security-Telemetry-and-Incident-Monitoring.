const { randomUUID } = require("crypto");
const net = require("net");

const ISO_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})(?=\s|$)/i;
const ISO_LIKE_PREFIX = /^\d{4}-\d{2}-\d{2}T/i;
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const MAX_HTTP_BODY_BYTES_PER_EVENT = 32 * 1024;
const MAX_HTTP_BODY_BYTES_PER_BATCH = 64 * 1024;
const MAX_HTTP_HEADER_BYTES_PER_EVENT = 16 * 1024;
const MAX_HTTP_HEADER_BYTES_PER_BATCH = 32 * 1024;
const MAX_HTTP_HEADER_VALUES_PER_EVENT = 32;
const SELECTED_HTTP_HEADERS = new Set(["content-type", "host", "x-forwarded-for"]);

function parseIsoTimestamp(value) {
  if (typeof value !== "string") return null;
  const match = value.trim().match(ISO_TIMESTAMP);
  if (!match) return null;

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , zone] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const isLeapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysByMonth = [31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  const daysInMonth = daysByMonth[month - 1];

  if (month < 1 || month > 12 || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  if (zone.toUpperCase() !== "Z") {
    const [, offsetHourText, offsetMinuteText] = zone.match(/^[+-](\d{2}):(\d{2})$/) || [];
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);
    if (offsetHour > 14 || offsetMinute > 59 || (offsetHour === 14 && offsetMinute !== 0)) return null;
  }

  const timestamp = Date.parse(match[0].trim());
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function labeledValue(text, labels) {
  const names = labels.map(escapeRegExp).join("|");
  const match = text.match(new RegExp(`(?:^|[\\s,;])(?:${names})\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s,;]+))`, "i"));
  if (!match) return undefined;
  return [match[1], match[2], match[3]].find((value) => value !== undefined)?.trim() || undefined;
}

function firstString(object, names) {
  for (const name of names) {
    const value = object?.[name];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function setIp(target, key, value) {
  if (typeof value === "string" && net.isIP(value.trim())) target[key] = value.trim();
}

function parseHttpUrl(value) {
  if (typeof value !== "string" || !/^https?:\/\//i.test(value)) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function addHttpFields(event, { method, url, path, query, userAgent, headers, body }) {
  const http = {};
  if (typeof method === "string" && HTTP_METHODS.has(method.toUpperCase())) http.method = method.toUpperCase();
  if (typeof url === "string" && url) http.url = url;
  if (typeof path === "string" && path) http.path = path;
  if (typeof query === "string" && query) http.query = query;
  if (typeof userAgent === "string" && userAgent) http.userAgent = userAgent;
  if (headers && Object.keys(headers).length) http.headers = headers;
  if (typeof body === "string") http.body = body;
  if (Object.keys(http).length) event.http = http;
}

function captureStructuredBody(httpInput, record, warnings, lineNumber, limits) {
  const body = typeof httpInput.body === "string"
    ? httpInput.body
    : typeof record.body === "string" ? record.body : undefined;
  if (body === undefined) return undefined;

  const bytes = Buffer.byteLength(body, "utf8");
  if (bytes > MAX_HTTP_BODY_BYTES_PER_EVENT || limits.bodyBytes + bytes > MAX_HTTP_BODY_BYTES_PER_BATCH) {
    warnings.push(`Line ${lineNumber}: HTTP body exceeded capture limits and was omitted`);
    return undefined;
  }

  limits.bodyBytes += bytes;
  return body;
}

function captureSelectedHeaders(httpInput, record, warnings, lineNumber, limits) {
  const headerInput = isPlainObject(httpInput.headers)
    ? httpInput.headers
    : isPlainObject(record.headers) ? record.headers : undefined;
  if (!headerInput) return undefined;

  const headers = {};
  let eventBytes = 0;
  let eventValues = 0;
  let warned = false;

  for (const [rawName, rawValues] of Object.entries(headerInput)) {
    const name = rawName.trim().toLowerCase();
    if (!SELECTED_HTTP_HEADERS.has(name)) continue;
    const values = Array.isArray(rawValues) ? rawValues : [rawValues];

    for (const value of values) {
      if (typeof value !== "string") continue;
      const bytes = Buffer.byteLength(value, "utf8");
      if (eventValues >= MAX_HTTP_HEADER_VALUES_PER_EVENT ||
          eventBytes + bytes > MAX_HTTP_HEADER_BYTES_PER_EVENT ||
          limits.headerBytes + bytes > MAX_HTTP_HEADER_BYTES_PER_BATCH) {
        warned = true;
        continue;
      }

      if (!headers[name]) headers[name] = [];
      headers[name].push(value);
      eventBytes += bytes;
      eventValues += 1;
      limits.headerBytes += bytes;
    }
  }

  if (warned) warnings.push(`Line ${lineNumber}: selected HTTP headers exceeded capture limits; excess values were omitted`);
  return Object.keys(headers).length ? headers : undefined;
}

function addDestinationFromUrl(event, value) {
  const parsed = parseHttpUrl(value);
  if (!parsed) return;
  const destination = {};
  if (net.isIP(parsed.hostname)) destination.ip = parsed.hostname;
  else if (parsed.hostname) destination.host = parsed.hostname;
  if (Object.keys(destination).length) event.destination = { ...event.destination, ...destination };
}

function extractTextFields(event, line) {
  const source = {};
  const sourceIp = labeledValue(line, ["source.ip", "source_ip", "sourceIp", "src_ip"]);
  setIp(source, "ip", sourceIp);
  const sourceHost = labeledValue(line, ["source.host", "source_host", "host", "hostname"]);
  const sourceService = labeledValue(line, ["source.service", "source_service", "service"]);
  if (sourceHost) source.host = sourceHost;
  if (sourceService) source.service = sourceService;
  if (Object.keys(source).length) event.source = source;

  const user = labeledValue(line, ["actor.user", "username", "user"]);
  if (user) event.actor = { user };

  const clientIp = labeledValue(line, ["client.ip", "client_ip", "clientIp", "remote_addr"]);
  setIp(event, "clientIp", clientIp);

  const methodLabel = labeledValue(line, ["http.method", "http_method", "method"]);
  const requestLine = line.match(/(?:^|\s)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/[^\s]*|https?:\/\/[^\s]+)(?:\s+HTTP\/\d(?:\.\d)?)?/i);
  const method = methodLabel || requestLine?.[1];
  const target = labeledValue(line, ["http.url", "http_url", "url"]) || requestLine?.[2];
  let pathValue = labeledValue(line, ["http.path", "request_path", "path"]);
  let query = labeledValue(line, ["http.query", "query_string"]);
  let url = target;

  if (target && target.startsWith("/")) {
    pathValue = pathValue || target.split("?", 1)[0];
    if (!query && target.includes("?")) query = target.slice(target.indexOf("?") + 1);
    url = undefined;
  } else if (target) {
    const parsed = parseHttpUrl(target);
    if (parsed) {
      pathValue = pathValue || parsed.pathname;
      query = query || parsed.search.replace(/^\?/, "") || undefined;
    }
  }

  const userAgent = labeledValue(line, ["http.userAgent", "user_agent", "userAgent"]) ||
    line.match(/(?:^|\s)User-Agent:\s*(.*)$/i)?.[1]?.trim();
  addHttpFields(event, { method, url, path: pathValue, query, userAgent });
  if (target) addDestinationFromUrl(event, target);

  const processName = labeledValue(line, ["process.name", "process_name", "process"]);
  const command = labeledValue(line, ["process.command", "process_command", "command", "cmd"]);
  if (processName || command) {
    event.process = {};
    if (processName) event.process.name = processName;
    if (command) event.process.command = command;
  }

  let authResult = labeledValue(line, ["authentication.result", "authentication_result", "auth_result", "login_result"]);
  if (!authResult) {
    const resultWords = "(?:success(?:ful)?|succeeded|failed|failure|incorrect|invalid|denied|rejected|unsuccessful)";
    const authWords = "(?:login|sign[- ]?in|authentication|auth)";
    const phrase = line.match(new RegExp(`\\b(?:${authWords}\\b[^\\n]*?\\b${resultWords}\\b|\\b${resultWords}\\b[^\\n]*?\\b${authWords}\\b)`, "i"));
    authResult = phrase?.[0];
  }
  if (authResult) {
    event.authentication = { result: authResult.toLowerCase() };
    if (!event.clientIp) {
      const authSource = line.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/i)?.[1];
      setIp(event, "clientIp", authSource);
    }
  }
}

function extractJsonFields(event, record, warnings, lineNumber, limits) {
  const sourceInput = isPlainObject(record.source) ? record.source : {};
  const actorInput = isPlainObject(record.actor) ? record.actor : {};
  const httpInput = isPlainObject(record.http) ? record.http : {};
  const destinationInput = isPlainObject(record.destination) ? record.destination : {};
  const processInput = isPlainObject(record.process) ? record.process : {};
  const authInput = isPlainObject(record.authentication) ? record.authentication : {};

  const source = {};
  setIp(source, "ip", firstString(sourceInput, ["ip"]) || firstString(record, ["sourceIp", "source_ip", "src_ip"]));
  const sourceHost = firstString(sourceInput, ["host", "hostname"]) || firstString(record, ["sourceHost", "source_host", "hostname", "host"]);
  const sourceService = firstString(sourceInput, ["service", "name"]) || firstString(record, ["sourceService", "source_service", "service"]);
  if (sourceHost) source.host = sourceHost;
  if (sourceService) source.service = sourceService;
  if (Object.keys(source).length) event.source = source;

  const user = firstString(actorInput, ["user", "username"]) || firstString(record, ["user", "username"]);
  if (user) event.actor = { user };

  const clientIp = firstString(record, ["clientIp", "client_ip", "remote_addr"]);
  setIp(event, "clientIp", clientIp);

  const method = firstString(httpInput, ["method"]) || firstString(record, ["httpMethod", "http_method", "method"]);
  const url = firstString(httpInput, ["url"]) || firstString(record, ["httpUrl", "http_url", "url"]);
  let pathValue = firstString(httpInput, ["path"]) || firstString(record, ["requestPath", "http_path", "path"]);
  let query = firstString(httpInput, ["query", "queryString", "query_string"]) || firstString(record, ["query", "queryString", "query_string"]);
  const userAgent = firstString(httpInput, ["userAgent", "user_agent"]) || firstString(record, ["userAgent", "user_agent"]);
  const headers = captureSelectedHeaders(httpInput, record, warnings, lineNumber, limits);
  const body = captureStructuredBody(httpInput, record, warnings, lineNumber, limits);
  const parsedUrl = parseHttpUrl(url);
  if (parsedUrl) {
    pathValue = pathValue || parsedUrl.pathname;
    query = query || parsedUrl.search.replace(/^\?/, "") || undefined;
  }
  addHttpFields(event, { method, url, path: pathValue, query, userAgent, headers, body });

  const destination = {};
  const destinationIp = firstString(destinationInput, ["ip"]) || firstString(record, ["destinationIp", "destination_ip"]);
  setIp(destination, "ip", destinationIp);
  const destinationHost = firstString(destinationInput, ["host", "hostname"]) || firstString(record, ["destinationHost", "destination_host"]);
  if (destinationHost) destination.host = destinationHost;
  if (parsedUrl && !destination.host && !destination.ip) {
    if (net.isIP(parsedUrl.hostname)) destination.ip = parsedUrl.hostname;
    else destination.host = parsedUrl.hostname;
  }
  if (Object.keys(destination).length) event.destination = destination;

  const processName = firstString(processInput, ["name"]) || firstString(record, ["processName", "process_name"]);
  const command = firstString(processInput, ["command", "cmd"]) || firstString(record, ["command", "cmd"]);
  if (processName || command) {
    event.process = {};
    if (processName) event.process.name = processName;
    if (command) event.process.command = command;
  }

  const authResult = firstString(authInput, ["result"]) || firstString(record, ["authenticationResult", "authentication_result", "authResult", "auth_result"]);
  if (authResult) event.authentication = { result: authResult.toLowerCase() };

  const timestamp = firstString(record, ["timestamp", "time", "@timestamp"]);
  if (timestamp) {
    const eventTime = parseIsoTimestamp(timestamp);
    if (eventTime) event.eventTime = eventTime;
    else warnings.push(`Line ${lineNumber}: timestamp field is not a supported ISO-8601 timestamp`);
  }
}

function parseJsonLines(lines, warnings) {
  const nonEmptyLines = lines.map((line, index) => ({ line, lineNumber: index + 1 })).filter(({ line }) => line.trim());
  if (nonEmptyLines.length < 2) return null;

  const looksLikeJsonObjectLines = nonEmptyLines.every(({ line }) => line.trim().startsWith("{") && line.trim().endsWith("}"));
  const records = [];
  for (const item of nonEmptyLines) {
    let record;
    try {
      record = JSON.parse(item.line.trim());
    } catch {
      if (looksLikeJsonObjectLines) warnings.push(`Line ${item.lineNumber}: malformed JSON Lines input; parsed as plain text`);
      return null;
    }
    if (!isPlainObject(record)) return null;
    records.push({ ...item, record });
  }
  return records;
}

function parseLogBatch(input, options = {}) {
  if (typeof input !== "string") throw new TypeError("Log input must be a string");
  const rawInput = input.trim();
  const batchId = options.batchId || `LOG-BATCH-${randomUUID()}`;
  const receivedAt = options.receivedAt || new Date().toISOString();
  const parseWarnings = [];
  const limits = { bodyBytes: 0, headerBytes: 0 };
  const lines = rawInput ? rawInput.split(/\r\n|\n|\r/) : [];
  const jsonRecords = parseJsonLines(lines, parseWarnings);
  const events = [];

  if (jsonRecords) {
    for (const { line, lineNumber, record } of jsonRecords) {
      const eventId = `${batchId}-EVENT-${events.length + 1}`;
      const event = { eventId, message: firstString(record, ["message", "msg"]) || line, rawMessage: line };
      extractJsonFields(event, record, parseWarnings, lineNumber, limits);
      events.push(event);
    }
  } else {
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (!line.trim()) continue;
      const event = { eventId: `${batchId}-EVENT-${events.length + 1}`, message: line, rawMessage: line };
      const timestampInput = line.trimStart();
      const timestampMatch = timestampInput.match(ISO_TIMESTAMP);
      if (timestampMatch) {
        const eventTime = parseIsoTimestamp(timestampMatch[0]);
        if (eventTime) event.eventTime = eventTime;
        else parseWarnings.push(`Line ${index + 1}: timestamp-like prefix is not a valid ISO-8601 timestamp`);
      } else if (ISO_LIKE_PREFIX.test(timestampInput)) {
        parseWarnings.push(`Line ${index + 1}: timestamp-like prefix is not a valid ISO-8601 timestamp`);
      }
      extractTextFields(event, line);
      events.push(event);
    }
  }

  const batch = { batchId, receivedAt, rawInput, events };
  if (parseWarnings.length) batch.parseWarnings = parseWarnings;
  return batch;
}

module.exports = {
  parseLogBatch,
  parseIsoTimestamp,
  HTTP_METHODS,
  MAX_HTTP_BODY_BYTES_PER_EVENT
};
