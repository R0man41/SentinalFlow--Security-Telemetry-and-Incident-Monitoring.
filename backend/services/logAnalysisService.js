const fs = require("fs");
const path = require("path");
const { HttpError } = require("../utils/httpError");

const RULES_PATH = path.join(__dirname, "../../data/detection_rules.json");
const SEVERITY_WEIGHT = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

let cachedRules = null;

async function analyzeLogs(logs) {
  if (typeof logs !== "string" || !logs.trim()) {
    throw new HttpError(400, "Logs must be a non-empty string");
  }

  return analyzeLogsLocally(logs);
}

function loadDetectionRules() {
  if (cachedRules) {
    return cachedRules;
  }

  const raw = fs.readFileSync(RULES_PATH, "utf8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("Detection rules must contain a JSON array");
  cachedRules = parsed;
  return cachedRules;
}

function countPatternMatches(logs, rule) {
  if (!rule || !rule.pattern) {
    return 0;
  }

  if (rule.regex) {
    try {
      let pattern = String(rule.pattern);
      let flags = "g";

      const inlineFlagsMatch = pattern.match(/^\(\?([a-zA-Z-]+)\)/);
      if (inlineFlagsMatch) {
        pattern = pattern.replace(/^\(\?[a-zA-Z-]+\)/, "");
        const inlineFlags = inlineFlagsMatch[1].replace(/-/g, "");
        const validFlags = inlineFlags
          .split("")
          .filter((flag) => "imsuy".includes(flag))
          .join("");
        flags += validFlags;
      }

      if (!flags.includes("i")) {
        flags += "i";
      }

      const dedupedFlags = Array.from(new Set(flags.split(""))).join("");
      const regex = new RegExp(pattern, dedupedFlags);
      const matches = logs.match(regex);
      return matches ? matches.length : 0;
    } catch (err) {
      console.warn(`Invalid detection rule regex ${rule.id || "unknown"}:`, err.message);
      return 0;
    }
  }

  const needle = String(rule.pattern).toLowerCase();
  const haystack = logs.toLowerCase();
  if (!needle) {
    return 0;
  }

  let count = 0;
  let start = 0;
  while (true) {
    const idx = haystack.indexOf(needle, start);
    if (idx === -1) {
      break;
    }
    count += 1;
    start = idx + needle.length;
  }

  return count;
}

function findFirstPatternMatch(value, rule) {
  if (typeof value !== "string" || !rule || !rule.pattern) return null;

  if (rule.regex) {
    try {
      let pattern = String(rule.pattern);
      let flags = "g";
      const inlineFlagsMatch = pattern.match(/^\(\?([a-zA-Z-]+)\)/);
      if (inlineFlagsMatch) {
        pattern = pattern.replace(/^\(\?[a-zA-Z-]+\)/, "");
        const inlineFlags = inlineFlagsMatch[1].replace(/-/g, "");
        const validFlags = inlineFlags
          .split("")
          .filter((flag) => "imsuy".includes(flag))
          .join("");
        flags += validFlags;
      }
      if (!flags.includes("i")) flags += "i";
      const dedupedFlags = Array.from(new Set(flags.split(""))).join("");
      const match = new RegExp(pattern, dedupedFlags).exec(value);
      return match ? { start: match.index, end: match.index + match[0].length } : null;
    } catch (err) {
      console.warn(`Invalid detection rule regex ${rule.id || "unknown"}:`, err.message);
      return null;
    }
  }

  const needle = String(rule.pattern).toLowerCase();
  if (!needle) return null;
  const start = value.toLowerCase().indexOf(needle);
  return start < 0 ? null : { start, end: start + needle.length };
}

function analyzeLogsLocally(logs) {
  const rules = loadDetectionRules();
  const matchedRules = [];

  for (const rule of rules) {
    const count = countPatternMatches(logs, rule);
    const repeatThreshold = Number(rule.repeatThreshold) || 1;

    if (count >= repeatThreshold && count > 0) {
      matchedRules.push({
        id: rule.id,
        pattern: rule.pattern,
        type: rule.type || "Unknown",
        severity: (rule.severity || "MEDIUM").toUpperCase(),
        description: rule.description || "",
        count
      });
    }
  }

  if (matchedRules.length === 0) {
    return {
      status: "clean",
      type: "None",
      severity: "LOW",
      matchedRules: []
    };
  }

  const topRule = matchedRules
    .slice()
    .sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))[0];

  return {
    status: "threat_detected",
    type: topRule.type,
    severity: topRule.severity,
    matchedRules
  };
}

module.exports = {
  analyzeLogs,
  countPatternMatches,
  findFirstPatternMatch
};
