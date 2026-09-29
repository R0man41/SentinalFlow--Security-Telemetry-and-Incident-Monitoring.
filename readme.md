# Incident Management App

This is a local-first incident-management and security-log analysis application. It uses a vanilla JavaScript frontend served by Express, local detection rules, and JSON-file incident storage. Cloud and deployment instructions from earlier versions are not part of the current runtime.

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3001`. The server uses the `PORT` value from the root `.env` when set; otherwise it starts on port 3001 and tries the next five ports if that port is busy. The frontend and API are served from the same Express process.

The default incident file is `backend/incidents.json`. It can be changed with `INCIDENTS_FILE`. The optional `.env.example` contains the local port setting; do not commit `.env` values.

## Features

- Incident create, read, update, and delete operations, with timelines and SLA deadlines.
- Dashboard summaries and an explicit escalation endpoint.
- Local log analysis using `data/detection_rules.json`.
- Raw-text detection with additive event-aware matching for selected rules, plus BF_001 correlation where its required event context is available.
- Internal Findings and bounded evidence; the public log-analysis response remains `{ detection, incident }`.

The log-analysis route is `POST /analyze-logs` with a JSON body containing a `logs` string. Other routes include `GET /health`, `/incidents`, `/dashboard`, and `POST /escalations/run`.

## Storage and limitations

Incident data is stored locally as JSON. Writes are atomic and serialized within one Node.js process. Concurrent writes from multiple application processes are not coordinated, so this storage is intended for local development or a single process.

The detector identifies text matching its rules; a match does not by itself prove that the corresponding SQL, browser, template, deserialization, or network action succeeded. Some rules remain on the legacy raw-text path.

Run the test suite with:

```bash
npm test
```
