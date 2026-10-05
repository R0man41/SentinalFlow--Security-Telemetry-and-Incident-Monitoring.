const UNSAFE_METHODS = new Set(["POST", "PUT", "DELETE"]);

function parseOrigin(value) {
  if (typeof value !== "string" || value === "null" || value.length === 0 || value.trim() !== value) {
    return null;
  }

  try {
    const url = new URL(value);
    if (url.origin === "null" || url.username || url.password ||
        url.pathname !== "/" || url.search || url.hash || value !== url.origin) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

function createAdminOriginGuard({ publicOrigin = process.env.PUBLIC_ORIGIN } = {}) {
  const configuredOrigin = typeof publicOrigin === "string" && publicOrigin.trim()
    ? parseOrigin(publicOrigin)
    : null;
  const hasConfiguredOrigin = typeof publicOrigin === "string" && publicOrigin.trim().length > 0;

  return function adminOriginGuard(req, res, next) {
    if (!UNSAFE_METHODS.has(req.method)) return next();

    const originHeader = req.get("origin");
    const fetchSite = req.get("sec-fetch-site");
    if (fetchSite !== undefined && fetchSite !== "same-origin") {
      return res.status(403).json({ error: "cross_origin_request" });
    }

    if (originHeader !== undefined) {
      const requestOrigin = parseOrigin(originHeader);
      const expectedOrigin = hasConfiguredOrigin
        ? configuredOrigin
        : parseOrigin(`${req.protocol}://${req.get("host") || ""}`);
      if (!requestOrigin || !expectedOrigin || requestOrigin !== expectedOrigin) {
        return res.status(403).json({ error: "cross_origin_request" });
      }
    }

    // Requests with neither browser-origin header remain available to authenticated
    // CLI clients. A supplied Sec-Fetch-Site value was checked above.
    return next();
  };
}

module.exports = createAdminOriginGuard();
module.exports.createAdminOriginGuard = createAdminOriginGuard;
module.exports.parseOrigin = parseOrigin;
