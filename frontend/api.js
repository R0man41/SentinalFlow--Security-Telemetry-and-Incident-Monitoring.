async function apiRequest(path, options = {}) {
  const { allow404 = false, ...fetchOptions } = options;

  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json"
    },
    ...fetchOptions
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const rawBody = await response.text();
  const result = isJson && rawBody ? JSON.parse(rawBody) : null;

  if (response.status === 404 && allow404) {
    return null;
  }

  if (!response.ok) {
    const statusText = `HTTP ${response.status}`;
    const responseMessage = result?.error || result?.message;
    const bodyPreview = rawBody ? rawBody.replace(/\s+/g, " ").slice(0, 180) : "";
    const fallbackMessage = bodyPreview ? `${statusText}: ${bodyPreview}` : statusText;
    throw new Error(responseMessage || fallbackMessage || "Request failed");
  }

  if (!isJson) {
    throw new Error(
      `Expected JSON response but received '${contentType || "unknown"}'. Check the local Express server.`
    );
  }

  return result;
}

async function fetchDashboard() {
  return apiRequest("/dashboard", { method: "GET" });
}

async function runEscalationCheck() {
  return apiRequest("/escalations/run", { method: "POST" });
}

async function fetchIncidents(filters = {}) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.append(key, value);
    }
  });

  const query = params.toString();
  const path = query ? `/incidents?${query}` : "/incidents";
  return apiRequest(path, { method: "GET" });
}

async function fetchIncidentById(id) {
  return apiRequest(`/incidents/${id}`, { method: "GET", allow404: true });
}

async function createIncident(data) {
  return apiRequest("/incidents", {
    method: "POST",
    body: JSON.stringify(data)
  });
}

async function analyzeLogs(logs) {
  return apiRequest("/analyze-logs", {
    method: "POST",
    body: JSON.stringify({ logs })
  });
}

async function updateIncident(id, data) {
  return apiRequest(`/incidents/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
    allow404: true
  });
}

async function deleteIncident(id) {
  return apiRequest(`/incidents/${id}`, {
    method: "DELETE",
    allow404: true
  });
}
