const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

console.log("🔥 EXPRESS APP LOADED");

const express = require("express");
const cors = require("cors");

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "../frontend")));

// Logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

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
const { HttpError } = require("./utils/httpError");

app.use("/incidents", incidentsRoutes);
app.use("/dashboard", dashboardRoutes);
app.use("/escalations", escalationRoutes);
app.use("/analyze-logs", logAnalysisRoutes);

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

const basePort = parseInt(process.env.PORT, 10) || 3001;
const maxPort = basePort + 5;

function startLocalServer(port) {
  const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });

  server.on("error", (err) => {
    if (err.code === "EADDRINUSE" && port < maxPort) {
      console.warn(`Port ${port} is in use. Trying ${port + 1}...`);
      startLocalServer(port + 1);
    } else {
      console.error("Failed to start server:", err);
      process.exit(1);
    }
  });
}

if (require.main === module) {
  startLocalServer(basePort);
}

module.exports = app;
