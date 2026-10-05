const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

console.log("🔥 EXPRESS APP LOADED");

const express = require("express");
const cors = require("cors");
const { createCorsOptions } = require("./middleware/corsConfig");

const app = express();
const DEFAULT_PORT = 3001;
const SHUTDOWN_TIMEOUT_MS = 10_000;

function resolvePort(value) {
  if (value === undefined || value.trim() === "") return DEFAULT_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("PORT must be an integer between 0 and 65535");
  }
  return port;
}

function createRequestLogger(logger = console) {
  return function requestLogger(req, res, next) {
    const startedAt = process.hrtime.bigint();
    const method = req.method;
    const requestPath = req.path;
    res.once("finish", () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      logger.log(`${new Date().toISOString()} - ${method} ${requestPath} ${res.statusCode} ${durationMs.toFixed(1)}ms`);
    });
    next();
  };
}

function registerShutdownHandlers(server, {
  processLike = process,
  logger = console,
  timeoutMs = SHUTDOWN_TIMEOUT_MS
} = {}) {
  let shuttingDown = false;

  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.log(`${new Date().toISOString()} - Received ${signal}; closing HTTP server`);

    const timeout = setTimeout(() => {
      logger.error(`Shutdown exceeded ${timeoutMs}ms; closing remaining connections`);
      server.closeAllConnections?.();
      processLike.exit(1);
    }, timeoutMs);
    timeout.unref?.();

    server.close((error) => {
      clearTimeout(timeout);
      if (error) {
        logger.error("HTTP server shutdown failed:", error);
        processLike.exitCode = 1;
        return;
      }
      logger.log(`${new Date().toISOString()} - HTTP server closed cleanly`);
    });
  }

  processLike.once("SIGTERM", () => shutdown("SIGTERM"));
  processLike.once("SIGINT", () => shutdown("SIGINT"));
}

// Middleware
app.use(cors(createCorsOptions(process.env.CORS_ALLOWED_ORIGINS)));
// Log request metadata after completion. Do not log headers, bodies, or query values.
app.use(createRequestLogger());
app.use(express.static(path.join(__dirname, "../frontend")));

// Health check
app.get("/health", (req, res) => {
  res.json({
    message: "API is running"
  });
});

// Routes
const incidentsRoutes = require("./routes/incidents");
const dashboardRoutes = require("./routes/dashboard");
const escalationRoutes = require("./routes/escalations");
const logAnalysisRoutes = require("./routes/logAnalysis");
const eventsRoutes = require("./routes/events");
const { HttpError } = require("./utils/httpError");
const adminAuth = require("./middleware/adminAuth");
const adminOriginGuard = require("./middleware/adminOriginGuard");
const eventIngestionAuth = require("./middleware/eventIngestionAuth");
const eventRateLimit = require("./middleware/eventRateLimit");

// Gate admin paths before parsing request bodies or entering route handlers.
app.use("/incidents", adminAuth);
app.use("/incidents", adminOriginGuard);
app.use("/dashboard", adminAuth);
app.use("/escalations", adminAuth);
app.use("/escalations", adminOriginGuard);
app.use("/analyze-logs", adminAuth);
app.use("/analyze-logs", adminOriginGuard);
app.post("/events", eventIngestionAuth);
app.post("/events", eventRateLimit);

app.use(express.json({ limit: "100kb" }));

app.use("/incidents", incidentsRoutes);
app.use("/dashboard", dashboardRoutes);
app.use("/escalations", escalationRoutes);
app.use("/analyze-logs", logAnalysisRoutes);
app.use("/events", eventsRoutes);

// Catch-all
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  let statusCode = 500;
  let message = "Internal server error";
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    message = "Invalid JSON request body";
  } else if (err.type === "entity.too.large") {
    statusCode = 413;
    message = "Request body is too large";
  } else if (err instanceof HttpError) {
    statusCode = err.statusCode;
    message = err.message;
  } else {
    console.error("Unhandled request error:", err);
  }
  res.status(statusCode).json({ error: message });
});

function startLocalServer(port = resolvePort(process.env.PORT), options = {}) {
  const { processLike = process, logger = console } = options;
  const server = app.listen(port, () => {
    logger.log(`Server running on port ${server.address().port}`);
    registerShutdownHandlers(server, { ...options, processLike, logger });
  });

  server.on("error", (err) => {
    logger.error("Failed to start server:", err);
    processLike.exit(1);
  });

  return server;
}

if (require.main === module) {
  startLocalServer();
}

module.exports = app;
module.exports.DEFAULT_PORT = DEFAULT_PORT;
module.exports.SHUTDOWN_TIMEOUT_MS = SHUTDOWN_TIMEOUT_MS;
module.exports.resolvePort = resolvePort;
module.exports.createRequestLogger = createRequestLogger;
module.exports.registerShutdownHandlers = registerShutdownHandlers;
module.exports.startLocalServer = startLocalServer;
