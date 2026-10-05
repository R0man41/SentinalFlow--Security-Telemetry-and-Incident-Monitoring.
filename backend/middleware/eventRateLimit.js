const { performance } = require("node:perf_hooks");

const DEFAULT_RATE_PER_MINUTE = 120;
const DEFAULT_BURST_CAPACITY = 30;
const MAX_CONFIGURED_LIMIT = 10_000;

function boundedInteger(value, fallback, min = 1, max = MAX_CONFIGURED_LIMIT) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function readRateLimitConfig(env = process.env) {
  return {
    ratePerMinute: boundedInteger(env.EVENT_RATE_LIMIT_PER_MINUTE, DEFAULT_RATE_PER_MINUTE),
    burstCapacity: boundedInteger(env.EVENT_RATE_LIMIT_BURST, DEFAULT_BURST_CAPACITY)
  };
}

function createEventRateLimiter({
  ratePerMinute = DEFAULT_RATE_PER_MINUTE,
  burstCapacity = DEFAULT_BURST_CAPACITY,
  now = () => performance.now()
} = {}) {
  const rate = boundedInteger(ratePerMinute, DEFAULT_RATE_PER_MINUTE);
  const capacity = boundedInteger(burstCapacity, DEFAULT_BURST_CAPACITY);
  const refillPerMs = rate / 60_000;
  let tokens = capacity;
  let lastRefillAt = now();

  return function eventRateLimit(req, res, next) {
    const currentTime = now();
    const elapsed = Math.max(0, currentTime - lastRefillAt);
    tokens = Math.min(capacity, tokens + elapsed * refillPerMs);
    lastRefillAt = Math.max(lastRefillAt, currentTime);

    if (tokens >= 1) {
      tokens -= 1;
      return next();
    }

    const retryAfterSeconds = Math.max(1, Math.ceil((1 - tokens) / refillPerMs / 1000));
    res.set("Retry-After", String(retryAfterSeconds));
    return res.status(429).json({ error: "rate_limit_exceeded" });
  };
}

const eventRateLimit = createEventRateLimiter(readRateLimitConfig());

module.exports = eventRateLimit;
module.exports.createEventRateLimiter = createEventRateLimiter;
module.exports.readRateLimitConfig = readRateLimitConfig;
module.exports.DEFAULT_RATE_PER_MINUTE = DEFAULT_RATE_PER_MINUTE;
module.exports.DEFAULT_BURST_CAPACITY = DEFAULT_BURST_CAPACITY;
module.exports.MAX_CONFIGURED_LIMIT = MAX_CONFIGURED_LIMIT;
