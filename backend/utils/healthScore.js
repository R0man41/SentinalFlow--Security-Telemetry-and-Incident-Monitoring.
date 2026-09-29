function computeHealthScore(incidents) {
  const weights = {
    LOW: 1,
    MEDIUM: 3,
    HIGH: 7,
    CRITICAL: 15
  };

  const activeIncidents = (Array.isArray(incidents) ? incidents : []).filter(
    (incident) => incident.status !== "RESOLVED"
  );

  const score = activeIncidents.reduce((sum, incident) => {
    return sum + (weights[incident.severity] || 0);
  }, 0);

  if (score === 0) {
    return { value: 0, label: "Healthy", color: "green" };
  }

  if (score >= 1 && score <= 9) {
    return { value: score, label: "Degraded", color: "yellow" };
  }

  if (score >= 10 && score <= 29) {
    return { value: score, label: "At Risk", color: "orange" };
  }

  return { value: score, label: "Critical", color: "red" };
}

module.exports = { computeHealthScore };
