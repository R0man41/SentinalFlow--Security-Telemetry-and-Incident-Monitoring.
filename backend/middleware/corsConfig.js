const ALLOWED_METHODS = Object.freeze(["GET", "HEAD", "POST", "PUT", "DELETE"]);
const ALLOWED_HEADERS = Object.freeze(["Content-Type", "Authorization"]);

function parseAllowedOrigins(value) {
  if (typeof value !== "string") return [];
  return [...new Set(value
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin && origin !== "*"))];
}

function createCorsOptions(value) {
  const allowedOrigins = new Set(parseAllowedOrigins(value));

  return {
    origin(origin, callback) {
      if (typeof origin === "string" && allowedOrigins.has(origin)) {
        return callback(null, origin);
      }
      return callback(null, false);
    },
    methods: [...ALLOWED_METHODS],
    allowedHeaders: [...ALLOWED_HEADERS],
    credentials: false
  };
}

module.exports = { ALLOWED_METHODS, ALLOWED_HEADERS, parseAllowedOrigins, createCorsOptions };
