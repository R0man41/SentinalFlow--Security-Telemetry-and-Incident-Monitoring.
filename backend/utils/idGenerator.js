function generateId(existingIncidents) {
  const year = new Date().getFullYear();
  const incidents = Array.isArray(existingIncidents) ? existingIncidents : [];

  const maxForYear = incidents.reduce((max, incident) => {
    const id = String(incident?.incidentId || "").trim();
    const match = id.match(/^INC-(\d{4})-(\d+)$/);
    if (!match) {
      return max;
    }

    const [, idYear, sequenceStr] = match;
    if (Number(idYear) !== year) {
      return max;
    }

    const sequenceNum = Number(sequenceStr);
    if (!Number.isFinite(sequenceNum)) {
      return max;
    }

    return Math.max(max, sequenceNum);
  }, 0);

  const sequence = String(maxForYear + 1).padStart(4, "0");
  return `INC-${year}-${sequence}`;
}

module.exports = { generateId };
