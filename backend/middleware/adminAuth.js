const { createHash, timingSafeEqual } = require("node:crypto");
const { TextDecoder } = require("node:util");

const AUTH_REALM = "Security Monitoring Admin";

function parseBasicCredentials(header) {
  if (typeof header !== "string") return null;
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(header);
  if (!match) return null;

  const encoded = match[1];
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) return null;

  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }

  const separator = decoded.indexOf(":");
  if (separator <= 0) return null;
  return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
}

function constantTimeEqual(left, right) {
  const leftDigest = createHash("sha256").update(left, "utf8").digest();
  const rightDigest = createHash("sha256").update(right, "utf8").digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function createAdminAuth({ username, password } = {}) {
  const configured = typeof username === "string" && username.length > 0 && !username.includes(":") &&
    typeof password === "string" && password.length > 0;

  return function adminAuth(req, res, next) {
    if (!configured) {
      return res.status(503).json({ error: "Admin authentication is not configured" });
    }

    const credentials = parseBasicCredentials(req.get("authorization"));
    const usernameMatches = constantTimeEqual(credentials?.username || "", username);
    const passwordMatches = constantTimeEqual(credentials?.password || "", password);
    if (!(usernameMatches & passwordMatches)) {
      res.set("WWW-Authenticate", `Basic realm="${AUTH_REALM}", charset="UTF-8"`);
      return res.status(401).json({ error: "Authentication required" });
    }

    return next();
  };
}

module.exports = createAdminAuth({
  username: process.env.ADMIN_AUTH_USERNAME,
  password: process.env.ADMIN_AUTH_PASSWORD
});
module.exports.createAdminAuth = createAdminAuth;
