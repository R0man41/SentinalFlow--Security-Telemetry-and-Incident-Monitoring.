const { createHash, timingSafeEqual } = require("node:crypto");

const BEARER_TOKEN_PATTERN = /^[A-Za-z0-9._~+/-]+=*$/;
const AUTH_REALM = "Event Ingestion";

function constantTimeEqual(left, right) {
  const leftDigest = createHash("sha256").update(left, "utf8").digest();
  const rightDigest = createHash("sha256").update(right, "utf8").digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function createEventIngestionAuth(token) {
  const configured = typeof token === "string" && BEARER_TOKEN_PATTERN.test(token);

  return function eventIngestionAuth(req, res, next) {
    if (!configured) {
      return res.status(503).json({ error: "Event ingestion authentication is not configured" });
    }

    const header = req.get("authorization");
    const match = typeof header === "string"
      ? /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i.exec(header)
      : null;
    const provided = match?.[1] || "";
    if (!constantTimeEqual(provided, token)) {
      res.set("WWW-Authenticate", `Bearer realm="${AUTH_REALM}"`);
      return res.status(401).json({ error: "Authentication required" });
    }

    return next();
  };
}

module.exports = createEventIngestionAuth(process.env.EVENT_INGESTION_TOKEN);
module.exports.createEventIngestionAuth = createEventIngestionAuth;
