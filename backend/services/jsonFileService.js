const fs = require("fs/promises");
const path = require("path");

const DATA_FILE = process.env.INCIDENTS_FILE
  ? path.resolve(process.env.INCIDENTS_FILE)
  : path.join(__dirname, "..", "incidents.json");
let writeQueue = Promise.resolve();
let temporaryFileCounter = 0;

async function readIncidents() {
  let raw;
  try {
    raw = await fs.readFile(DATA_FILE, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Incident storage contains invalid JSON: ${err.message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error("Incident storage must contain a JSON array");
  }

  const ids = new Set();
  for (const incident of parsed) {
    if (!incident || typeof incident !== "object" || Array.isArray(incident) || typeof incident.incidentId !== "string") {
      throw new Error("Incident storage contains an invalid incident record");
    }
    if (ids.has(incident.incidentId)) {
      throw new Error(`Incident storage contains duplicate ID ${incident.incidentId}`);
    }
    ids.add(incident.incidentId);
  }
  return parsed;
}

async function writeIncidents(incidents) {
  const directory = path.dirname(DATA_FILE);
  const temporaryFile = path.join(
    directory,
    `.incidents.${process.pid}.${++temporaryFileCounter}.tmp`
  );
  try {
    await fs.writeFile(temporaryFile, `${JSON.stringify(incidents, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
    await fs.rename(temporaryFile, DATA_FILE);
  } catch (err) {
    await fs.rm(temporaryFile, { force: true }).catch(() => {});
    throw err;
  }
}

function serializeWrite(operation) {
  const result = writeQueue.then(operation);
  writeQueue = result.catch(() => {});
  return result;
}

async function getAllIncidents() {
  return readIncidents();
}

async function getIncidentById(id) {
  const incidents = await readIncidents();
  return incidents.find((incident) => incident.incidentId === id) || null;
}

function createIncident(data) {
  return serializeWrite(async () => {
    const incidents = await readIncidents();
    if (incidents.some((incident) => incident.incidentId === data.incidentId)) {
      const error = new Error(`Incident ${data.incidentId} already exists`);
      error.statusCode = 409;
      throw error;
    }
    incidents.push(data);
    await writeIncidents(incidents);
    return data;
  });
}

function updateIncident(id, updates) {
  return serializeWrite(async () => {
    const incidents = await readIncidents();
    const index = incidents.findIndex((incident) => incident.incidentId === id);
    if (index === -1) return null;

    const updated = {
      ...incidents[index],
      ...updates,
      incidentId: incidents[index].incidentId,
      updatedAt: new Date().toISOString()
    };
    incidents[index] = updated;
    await writeIncidents(incidents);
    return updated;
  });
}

function deleteIncident(id) {
  return serializeWrite(async () => {
    const incidents = await readIncidents();
    const index = incidents.findIndex((incident) => incident.incidentId === id);
    if (index === -1) return false;
    incidents.splice(index, 1);
    await writeIncidents(incidents);
    return true;
  });
}

module.exports = {
  createIncident,
  getAllIncidents,
  getIncidentById,
  updateIncident,
  deleteIncident
};
