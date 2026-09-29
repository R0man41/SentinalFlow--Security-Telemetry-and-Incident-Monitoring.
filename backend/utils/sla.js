function calculateSLADeadline(severity, createdAt) {
  const hoursBySeverity = {
    LOW: 72,
    MEDIUM: 24,
    HIGH: 8,
    CRITICAL: 2
  };

  const normalizedSeverity = String(severity || "LOW").toUpperCase();
  const baseDate = new Date(createdAt);
  const hoursToAdd = hoursBySeverity[normalizedSeverity] ?? 72;
  const deadline = new Date(baseDate.getTime() + hoursToAdd * 60 * 60 * 1000);
  return deadline.toISOString();
}

module.exports = { calculateSLADeadline };
