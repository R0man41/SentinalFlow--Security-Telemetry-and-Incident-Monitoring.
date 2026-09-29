# Project Documentation

> **Superseded after Phase 2:** This document is a Phase 0 snapshot. Its cloud adapters, deployment files, provider switching, remote log-analysis, and folder-structure descriptions were removed or changed afterward. Do not use it as current architecture guidance; inspect the current source and the local startup instructions in `readme.md`.

This document describes the files present in this workspace as inspected on 2026-09-28. It is based primarily on executable source and configuration. Older notes, diagrams, archives, and presentation material are identified as such where they disagree with the current source.

**Status labels used below:**

- **Implemented:** source code for the behavior is present. This does not by itself prove a production deployment works.
- **Partially implemented / potentially incomplete:** a code path exists, but important validation, operational support, or end-to-end pieces are absent or uncertain.
- **Planned / described only:** mentioned in notes or diagrams but not implemented in this workspace.
- **Unknown from the current codebase:** the repository does not provide enough evidence to determine the answer.

## 1. Project Overview

This is a small incident-management web application. An operator can create and track incidents, view counts and a severity-weighted health score, change an incident's status or assignee, inspect its activity timeline, and submit text logs for rule-based threat detection. A detected threat can automatically create an incident.

The backend is a Node.js/Express application. It can use a local JSON file, AWS DynamoDB, or Azure Cosmos DB for incident data. A separate log-analysis HTTP service can be configured; when it is not configured or fails in `auto` mode, the backend applies local rules from `data/detection_rules.json`.

The likely users are an operations, DevOps, or security analyst team using this as a demo or coursework project. Its main goal is to put a basic incident workflow and log triage screen behind one browser interface, with selectable storage providers.

**Reality check:** the code implements a useful prototype, not a complete production incident-response platform. There is no login, role-based access, notification system, background worker, or automated test suite in the workspace. The current workspace does not contain the Python/GCP function referred to by several other project files.

## 2. Beginner Explanation

Think of the application as a small service desk:

1. `frontend/index.html` draws the forms, dashboard, and incident table in a browser.
2. `frontend/app.js` reacts to clicks and form submissions. `frontend/api.js` sends HTTP requests to the backend.
3. `backend/server.js` receives those requests and forwards them to route handlers.
4. Route handlers call service functions, which contain the incident workflow rules.
5. Those functions read and write incidents through one selected storage adapter: JSON, DynamoDB, or Cosmos DB.

For example, when an operator creates an incident, the browser sends a title, severity, description, and assignee. The server checks that the title, severity, and assignee are present, generates an ID, computes an SLA deadline, adds a `CREATED` timeline entry, and asks the selected data provider to save the record. The saved incident is returned to the browser and appears after the next refresh.

The storage adapter is like a plug on a power cord: the service layer uses the same small set of operations (`getAllIncidents`, `createIncident`, and so on), while `backend/db.js` selects which adapter provides them. Only one provider is selected for a running backend; the code does not replicate or synchronize data across clouds.

## 3. Technology Stack

| Technology | Use in this project | Where it appears |
|---|---|---|
| JavaScript, CommonJS | Backend modules and plain browser scripts | `backend/`, `frontend/` |
| Node.js 22 (container image) | Runs the Express server and backend scripts | `Dockerfile`; Node version outside Docker is not pinned |
| Express 4 | HTTP server, middleware, API routing, and static frontend hosting | `backend/server.js`, `backend/routes/` |
| `cors` | Adds permissive CORS middleware; no origin allowlist is configured | `backend/server.js` |
| `dotenv` | Loads root `.env` for non-Lambda runs | `backend/server.js` |
| `serverless-http` | Exposes the Express app as `module.exports.handler` for Lambda-style invocation | `backend/server.js` |
| AWS SDK v3 (`@aws-sdk/client-dynamodb`, `@aws-sdk/lib-dynamodb`) | DynamoDB reads/writes and local table initialization | `backend/services/dynamoService.js`, `backend/initDynamoDB.js` |
| `@azure/cosmos` | Cosmos DB SDK and container/document operations | `backend/services/azureCosmosService.js` |
| HTML, CSS, vanilla browser JavaScript | UI structure, style, browser interaction, and `fetch` calls | `frontend/` |
| Google Fonts | External font downloads for Space Grotesk and JetBrains Mono | `frontend/index.html` |
| Docker / Docker Compose | Container configuration for a Node backend, DynamoDB Local, and a referenced Python service | `Dockerfile`, `docker-compose.yml` |
| Python and `python-pptx` | Generates the presentation artifact; not part of the web application's runtime | `generate_ppt.py`; no Python dependency manifest is present |
| Mermaid | Source text for architecture and design diagrams | `diagrams/*.mmd` |

Dependencies declared in `package.json` are `@azure/cosmos`, `@aws-sdk/client-dynamodb`, `@aws-sdk/lib-dynamodb`, `cors`, `dotenv`, `express`, `serverless-http`, and `uuid`. `uuid` is declared but no use was found in the application source. The package scripts are `start` and `dev`; `nodemon` is not declared, so the `dev` script may fail unless it happens to be installed outside the declared package dependencies. No test script or test files were found.

## 4. Complete Folder Structure

Important application and project files in the current workspace:

```text
.
├── backend/
│   ├── routes/
│   │   ├── dashboard.js
│   │   ├── incidents.js
│   │   └── logAnalysis.js
│   ├── services/
│   │   ├── azureCosmosService.js
│   │   ├── dynamoService.js
│   │   ├── escalationService.js
│   │   ├── incidentService.js
│   │   ├── jsonFileService.js
│   │   ├── logAnalysisService.js
│   │   └── timelineService.js
│   ├── utils/
│   │   ├── healthScore.js
│   │   ├── idGenerator.js
│   │   └── sla.js
│   ├── db.js
│   ├── incidents.json
│   ├── initDynamoDB.js
│   └── server.js
├── data/
│   └── detection_rules.json
├── diagrams/
│   └── 01 through 07 *.mmd
├── frontend/
│   ├── api.js
│   ├── app.js
│   ├── index.html
│   └── style.css
├── .dockerignore
├── .env
├── CLAUDE_PROJECT_CONTEXT.md
├── DEPLOYMENT_CONFIG_AWS.md
├── DEPLOYMENT_CONFIG_AZURE.md
├── Dockerfile
├── docker-compose.yml
├── deploy.ps1
├── generate_ppt.py
├── Incident_Management_Project_Presentation.pptx
├── package.json
├── package-lock.json
├── readme.md
├── tree.txt
├── web.config
└── three ZIP archives
```

The actual root also contains `node_modules/` and `.venv/`, which are installed/generated environments rather than application source. The ZIP files are large bundled artifacts that include dependency/environment files; they are not imported or referenced by the application. They were not unpacked. `.env` contains local configuration; its values are intentionally not reproduced here.

The structure above is the current filesystem, not the stale `tree.txt` listing. That listing contains a `gcp_function/` directory absent from this workspace and omits the Azure Cosmos adapter and several current files. `readme.md`, `docker-compose.yml`, deployment notes, and diagrams also refer to `gcp_function/`, whose implementation cannot be inspected here.

## 5. System Architecture

```text
Operator's browser
  ├── index.html + style.css: page and presentation
  └── app.js ── api.js: UI state and HTTP requests
                     │ HTTP/JSON
                     ▼
               Express app (server.js)
                 ├── /incidents       ── incidentService ──┐
                 ├── /dashboard       ── escalation/score ─┤
                 ├── /analyze-logs    ── logAnalysisService│
                 └── /api/... aliases                       │
                                                           ▼
                                                 selected db.js adapter
                                                ├── JSON file
                                                ├── DynamoDB
                                                └── Azure Cosmos DB

logAnalysisService ── configured remote HTTP endpoint (optional)
                   └── local regex/literal rules in data/detection_rules.json
```

This is a layered monolith: one backend process contains the API, business services, and provider selection. The browser and backend are separate HTTP participants, but the frontend is also served as static files by Express in the normal local/container setup. A deployed static frontend can instead be configured with an API base URL.

**Implemented:** provider selection and the local rules engine exist in code. **Partially implemented / uncertain:** remote log analysis is only an HTTP client in this workspace; the service it expects is not present. **Described only:** running all three container services is shown in diagrams/Compose, but the GCP service build files are missing from the current workspace.

## 6. Complete Application Flow

### Startup

1. `npm start` runs `node backend/server.js`.
2. Unless Lambda mode is detected by `AWS_LAMBDA_FUNCTION_NAME` or `IS_LAMBDA=true`, `server.js` loads root `.env` using `dotenv`.
3. Express installs CORS, JSON request parsing, and static serving from `frontend/`.
4. It strips a leading `/prod` from request URLs, logs requests, registers `/api/health`, and mounts each API router both at its short path and under `/api`.
5. Outside `IS_LAMBDA=true`, it listens at `PORT` or 3001. If that port is busy, it tries up to five ports above it. The app also exports a `serverless-http` handler.
6. When the first route imports `backend/db.js`, the database adapter is selected from environment variables. Local development defaults to JSON; Lambda defaults to DynamoDB; Azure host detection without Cosmos credentials fails at module load.

`backend/initDynamoDB.js` is a separate initializer. The Dockerfile runs it before the server. Plain `npm start` does not run it.

### Read dashboard and incidents

The browser calls `syncData()` on page load, every 10 seconds, and when a hidden tab becomes visible. It fetches dashboard metrics and incidents concurrently, then refreshes an open timeline. The dashboard route runs the SLA escalation check before it reads incident data and computes metrics. Incident filters and sorting are performed in memory by `incidentService.getAllIncidents()` after the selected provider returns all records.

### Create an incident

The create form's submit handler in `frontend/app.js` sends `{title, description, severity, assignedTo}` using `frontend/api.js`. `POST /incidents` (or `/api/incidents`) calls `incidentService.createIncident()`. The service requires title, severity, and assignee, uppercases severity, scans current records to choose a yearly ID, calculates the severity-based deadline, creates an `OPEN` record with `escalated: false` and a `CREATED` timeline event, and calls the chosen adapter's `createIncident()`. The route responds with JSON. It does not explicitly set HTTP 201, so Express uses 200.

### Update or delete an incident

The table's Edit action loads a record, then sends status, assignee, and `by: "UI User"`. The route delegates to `incidentService.updateIncident()`. The service performs separate updates for a changed status and changed assignee and adds timeline events through `timelineService`. Delete asks the browser for confirmation, then calls the provider's delete operation. The route returns a message for both successful and already-absent deletes. Status values are not validated against the UI's three choices at the backend.

### Analyze logs

The Analyze button sends `{logs}` to `POST /analyze-logs` (or `/api/analyze-logs`). The route rejects a missing/blank string. `logAnalysisService` chooses local rules or a remote HTTP POST according to `LOG_ANALYSIS_PROVIDER` and URL configuration. In `auto`, an absent URL or remote error uses local rules. In `gcp`, a URL is required and remote errors are returned as a service error. If the returned status is exactly `threat_detected`, the route creates an `OPEN` incident assigned to `Auto-System`, using the detected severity and a description containing matched rules plus a truncated log snippet. The API response is `{detection, incident}`; `incident` is `null` when no incident is created.

### Escalation

There is no timer or background scheduler in the code. `GET /dashboard` is what calls `runEscalationCheck()`. That function finds overdue active incidents with `escalated === false`, raises LOW to MEDIUM, MEDIUM to HIGH, HIGH to CRITICAL (CRITICAL stays CRITICAL), sets `escalated`, and appends an `ESCALATED` timeline entry. It escalates each incident at most once.

## 7. File-by-File Responsibilities

### Backend entry point, routes, and selection

- `backend/server.js` — Builds Express, installs middleware, serves `frontend/`, applies `/prod` stripping, defines health check, mounts route modules, provides a 404 JSON response, starts a local listener, and exports the Lambda handler. Be careful to preserve router mounts and the distinction between `IS_LAMBDA` and AWS's automatic Lambda environment variable.
- `backend/db.js` — Chooses one provider based on `DB_PROVIDER`, Lambda/Azure detection, and Cosmos settings. It exports that provider's functions directly. Unsupported explicit providers throw during import.
- `backend/routes/incidents.js` — HTTP wrappers for create/list/get/update/delete, including basic error-to-status mapping and compatibility responses for missing records. It calls `incidentService`.
- `backend/routes/dashboard.js` — Calls escalation, reads incidents, computes counts and health score, and returns a JSON summary. A dashboard read can mutate incident records because it triggers escalation.
- `backend/routes/logAnalysis.js` — Validates the log field, calls log analysis, conditionally creates an incident, and builds the response. It calls `logAnalysisService` and `incidentService`.
- `backend/initDynamoDB.js` — Waits for a DynamoDB endpoint, checks for a table, and creates it with `incidentId` as string hash key if missing. The default endpoint is localhost:8000; it is not called by `npm start`.

### Backend services and utilities

- `backend/services/incidentService.js` — Core incident validation and workflow: ID, SLA, defaults, filtering/sorting, update audit events, and delete results. It calls `db`, ID/SLA helpers, and timeline service. Validation is currently limited to required create fields.
- `backend/services/timelineService.js` — Appends one of four allowed event types (`CREATED`, `STATUS_CHANGE`, `REASSIGNED`, `ESCALATED`) with timestamp, from/to, and actor. Creation writes its initial event directly in `incidentService`; this helper is used for later events.
- `backend/services/escalationService.js` — Finds overdue, active, not-yet-escalated records and raises severity once. It calls the selected database and timeline service.
- `backend/services/logAnalysisService.js` — Implements provider choice, local rule loading/caching, regex/literal match counting, severity choice, remote POST and response validation, and fallback. It expects `fetch` from the Node runtime; the Docker base uses Node 22.
- `backend/services/jsonFileService.js` — Reads/writes the complete incident array in `backend/incidents.json`, returning `null`/`false` for missing IDs. This is the local fallback and has no locking or atomic-write scheme.
- `backend/services/dynamoService.js` — Implements provider operations with AWS SDK document commands. List uses a table scan; individual reads use the `incidentId` key; writes use Put/Update/Delete. It configures a custom endpoint when present, except for localhost endpoints in Lambda.
- `backend/services/azureCosmosService.js` — Lazily creates the configured Cosmos database/container with partition path `/incidentId`; queries documents and normalizes them to application incident objects. It includes fallbacks for records with legacy ID/partition-key layouts. Review partition key compatibility carefully before changing it.
- `backend/utils/idGenerator.js` — Scans supplied incidents for the largest `INC-<year>-<sequence>` sequence and returns the next padded ID.
- `backend/utils/sla.js` — Sets deadlines: LOW 72h, MEDIUM 24h, HIGH 8h, CRITICAL 2h; unknown severities use 72h.
- `backend/utils/healthScore.js` — Scores non-resolved incidents with weights LOW 1, MEDIUM 3, HIGH 7, CRITICAL 15, then maps totals to Healthy/Degraded/At Risk/Critical labels and colors.

### Frontend, rules, and project support files

- `frontend/index.html` — Defines dashboard, filters, incident table, create/edit forms, log-analysis panel, timeline panel, and script/style references. It contains API base URL meta tags; the AWS-specific tag has a configured public endpoint in the file, so change it only as part of a deliberate deployment update.
- `frontend/app.js` — Binds UI events, refreshes data, renders incidents and logs, submits forms, handles edit/delete, and displays a selected incident timeline. `escapeHtml()` is used for some dynamic fields, but timeline values are currently interpolated without escaping.
- `frontend/api.js` — Chooses the API base URL from query parameter, cloud-specific globals/meta tags, generic config, file-protocol fallback, or same origin. Sends JSON fetch requests and retries short API paths under `/api` on a 404. The query string can override the API URL and is intended for debugging/configuration.
- `frontend/style.css` — Layout, colors, component styling, responsive behavior, and animation. UI-only changes generally belong here.
- `data/detection_rules.json` — Rule catalog with IDs, patterns, type, severity, optional repeat thresholds, and descriptions. Rules are regular expressions in this catalog; editing a regex changes what is detected.
- `backend/incidents.json` — Current local JSON storage data; it contains one sample incident. When JSON is selected, this file is application data and can be rewritten by normal app operations.
- `package.json` / `package-lock.json` — Runtime dependencies and two npm scripts; lock file records resolved dependency versions.
- `Dockerfile` — Builds a production-dependency Node image and starts DynamoDB table initialization followed by Express.
- `docker-compose.yml` — Declares DynamoDB Local, a Python/GCP function build, and backend with local endpoints. The GCP build points at missing files in the current workspace, so this topology is not currently runnable as written.
- `.dockerignore` — Excludes `node_modules`, logs, Docker files, Git, and Python bytecode/venv path. It does **not** exclude `.env`.
- `.env` — Local environment configuration loaded by `server.js` outside Lambda. Its values are not copied into this documentation. Keep secrets out of source and deployment artifacts.
- `web.config` — IIS/iisnode rewrite configuration intended for an Azure/IIS host; it removes WebDAV handling for PUT/DELETE and rewrites requests to the Node server. Actual hosting behavior is not verified here.
- `deploy.ps1` — Azure zip-deployment helper. It expects `deploy.zip` in the current directory and an Azure CLI login, then requests `/api/health`. `deploy.zip` is not present in the workspace.
- `DEPLOYMENT_CONFIG_AWS.md`, `DEPLOYMENT_CONFIG_AZURE.md` — Human deployment notes. They contain examples and assumptions that must be compared with current code and environment before use.
- `readme.md` — Run/deployment instructions, including references to an absent `gcp_function/` directory.
- `CLAUDE_PROJECT_CONTEXT.md` — Narrative/context document. It contains useful design intent but also asserts behavior that source does not establish; use current source as authority.
- `diagrams/*.mmd` — Architecture, deployment, lifecycle, sequence, provider switching, and two ER diagrams. Several show planned or older models (for example separate timeline/escalation/result tables and extra lifecycle states) that do not match the embedded incident object currently used in code.
- `generate_ppt.py` — Uses `python-pptx` to regenerate the presentation file. The slide text is project narrative, not proof of runtime features. There is no `requirements.txt` in this workspace.
- `Incident_Management_Project_Presentation.pptx` — Generated/presentation artifact.
- `tree.txt` — Stale directory listing, not a reliable guide to present files.
- `papapap.zip`, `jajaja.zip`, `newwwwwww.zip` — Archive artifacts containing large dependency or environment trees. They are not referenced by runtime code.
- `.venv/`, `node_modules/` — Local installed environments; do not edit these to change application behavior. Recreate from manifests if needed.

## 8. Important Classes and Functions

The project uses functions and modules rather than application classes.

- `createIncident(body)` — Validates minimum create fields, assigns ID, SLA, initial status and timeline, then persists.
- `getAllIncidents(query)` — Reads all records, then applies exact-value severity/status filters and severity/date sort in memory.
- `updateIncident(id, body)` — Changes status and assignment separately; each change adds a timeline event. It does not validate allowed status/severity values or update the SLA when severity changes.
- `runEscalationCheck()` — Performs one-time escalation of overdue active incidents. It is called as part of dashboard retrieval, not on a schedule.
- `addTimelineEntry(...)` — Reads the current incident, appends one valid event, and persists the whole timeline field.
- `analyzeLogs(logs)` — Selects local/remote analysis. Local rules are cached after first load; remote output must include string `status`, `type`, and `severity`.
- `computeHealthScore(incidents)` — Produces `{value,label,color}` from weighted active incident count. It is an indicator formula, not a measured service availability metric.
- `resolveBaseUrl()` — Chooses the frontend's API host according to browser location, configuration meta tags/globals, and optional `apiBaseUrl` query parameter.
- Provider methods (`getAllIncidents`, `getIncidentById`, `createIncident`, `updateIncident`, `deleteIncident`) — Shared de-facto interface implemented in each storage adapter.

## 9. Data Flow

### Incident create/update

```text
Form input
  → browser app.js trims values
  → api.js JSON HTTP request
  → Express route
  → incidentService validation / business rules
  → db.js-selected adapter
  → JSON file or cloud database
  → JSON response
  → browser refreshes dashboard/list
```

### Log analysis

```text
Text logs
  → browser api.js POST {logs}
  → logAnalysis route validates non-empty string
  → logAnalysisService chooses remote HTTP endpoint or local rule file
  → detection response
  → if status is threat_detected: incidentService creates incident
  → {detection, incident|null} returned to browser
```

No network device protocol, agent, polling integration, or direct device command is present. Log input is submitted by a user as text; the optional remote analyzer is called using HTTP `POST` with JSON and no authentication header in this code.

## 10. Database

There is no relational database, SQL schema, migration tool, or ORM. The incident is a JSON document with fields such as `incidentId`, `title`, `description`, `severity`, `status`, `assignedTo`, `slaDeadline`, `escalated`, `timeline`, `createdAt`, and `updatedAt`. Timeline entries are embedded in each incident; there are no separate timeline, escalation, or analysis tables in the current implementation.

| Provider | Storage shape and behavior | Configuration |
|---|---|---|
| File | One JSON array in `backend/incidents.json`; every operation reads or rewrites the file | `DB_PROVIDER=file` or `local`; default for local mode when no other provider applies |
| DynamoDB | Table keyed by string `incidentId`; list is `Scan`, get is `Get`, create is `Put`, update is generated `Update`, delete is conditional | `DYNAMODB_TABLE`, `AWS_REGION`, optional `DYNAMODB_ENDPOINT`; AWS credentials normally supplied by AWS environment/role, local endpoint path supplies fallback local credentials |
| Azure Cosmos DB | Database/container created if absent; container uses partition key `/incidentId`; incident documents also set Cosmos `id` to `incidentId` | `AZURE_COSMOS_ENDPOINT`, `AZURE_COSMOS_KEY`, optional database/container names |

`backend/initDynamoDB.js` creates a DynamoDB table if absent, with `incidentId` as its string hash key and on-demand billing. Cosmos uses `createIfNotExists`; local JSON needs no setup beyond writable storage. There is no data migration or replication between providers. Switching `DB_PROVIDER` changes where subsequent calls go; it does not copy records.

The ER diagrams are design illustrations, not actual schema: the current code stores timeline entries inside an incident and does not persist `LOG_ANALYSIS_RESULT` or `ESCALATION_RECORD` entities.

## 11. APIs and External Services

### Application API

All endpoints accept/return JSON. Routes are mounted at both short and `/api` paths unless noted. No authentication or authorization is implemented.

| Method and path | Purpose and input | Response / behavior |
|---|---|---|
| `GET /api/health` | Deployment health probe | `{message, deploymentMarker}`. The marker is a hardcoded string. No short `/health` endpoint is defined. |
| `GET /incidents` or `/api/incidents` | List; optional exact `severity`, `status`, and `sort=date\|severity` query parameters | Array of incidents, filtered/sorted in memory |
| `POST /incidents` or `/api/incidents` | Create; JSON `{title, description?, severity, assignedTo}` | Incident object. Route currently responds with default HTTP 200. |
| `GET /incidents/:id` or `/api/incidents/:id` | Fetch one record | Incident object; missing record returns JSON `null` with HTTP 200 |
| `PUT /incidents/:id` or `/api/incidents/:id` | Optional `status`, `assignedTo`, `by` fields | Updated incident; missing record is represented by a message with HTTP 200. |
| `DELETE /incidents/:id` or `/api/incidents/:id` | Delete by ID | `{message: ...}`; already-missing record is idempotent-friendly. |
| `GET /dashboard` or `/api/dashboard` | Trigger escalation check and summarize incidents | `{total,open,inProgress,resolved,critical,healthScore,escalatedCount}` |
| `POST /analyze-logs` or `/api/analyze-logs` | JSON `{logs: "..."}` | `{detection,incident}`; creates an incident on `threat_detected` |

The `/prod` URL prefix is stripped by server middleware to support a particular API Gateway stage convention. The frontend also retries with `/api` after a 404 from the short route.

### External services

- **DynamoDB / DynamoDB Local:** incident persistence. AWS SDK calls are in `backend/services/dynamoService.js`; local table initialization is in `backend/initDynamoDB.js`. AWS authentication is delegated to the SDK's configured credentials/provider chain for AWS; local custom endpoints use placeholder local credentials. No credentials are documented here.
- **Azure Cosmos DB:** incident persistence via `@azure/cosmos`, authenticated with endpoint and key in environment variables. The secret key must be configured outside source-controlled documentation.
- **Optional log-analysis HTTP service (described as GCP):** `backend/services/logAnalysisService.js` sends `POST` JSON `{logs}` to `GCP_LOG_ANALYSIS_URL` or `LOG_ANALYSIS_URL`, expects JSON fields `status`, `type`, `severity`, optionally `matchedRules`, and sends no auth header. No concrete service implementation or authentication scheme is present in the current workspace. Service identity, endpoint availability, and deployment are **Unknown from the current codebase**.
- **Google Fonts:** browser requests font files from Google Fonts when the page loads with network access.

## 12. Network/Device Communication

The application has ordinary HTTP communication only: browser-to-Express JSON API calls, and optionally Express-to-log-analyzer HTTP `POST`. Database adapters use their cloud SDK network clients. There is no SSH, SNMP, Netconf, serial, socket command protocol, or direct network-device integration in the source. If device communication is intended, it is **Planned / described only or unknown**, not implemented in this workspace.

The remote log endpoint URL is environment-driven. Its request body is `{logs}` and the client expects a JSON detection result. The source has no bearer token, API key header, or other remote service authentication. It rejects a localhost endpoint when in Lambda, but does not otherwise establish endpoint identity or add a timeout in this code.

## 13. Configuration

### Backend environment variables

| Variable | Purpose / behavior |
|---|---|
| `PORT` | Local listener base port; defaults to 3001. Server can try up to five higher ports if occupied. |
| `IS_LAMBDA` | String `true` disables local listener; used along with `AWS_LAMBDA_FUNCTION_NAME` in some Lambda detection checks. |
| `AWS_LAMBDA_FUNCTION_NAME` | AWS-provided runtime indicator used for provider selection and local endpoint handling. |
| `DB_PROVIDER` | `aws`/`dynamo`, `azure`, `file`/`local`; unknown explicit value throws. |
| `AWS_REGION` | AWS SDK region; defaults to `us-east-1`. |
| `DYNAMODB_TABLE` | DynamoDB table; defaults to `Incidents`. |
| `DYNAMODB_ENDPOINT` | Optional custom DynamoDB endpoint; local development/container use. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Used in local endpoint client setup or supplied by AWS environment; never place actual values in docs. |
| `AZURE_COSMOS_ENDPOINT`, `AZURE_COSMOS_KEY` | Required when Azure provider is selected; key is a secret. |
| `AZURE_COSMOS_DATABASE`, `AZURE_COSMOS_CONTAINER` | Cosmos resource names; default to `IncidentManagement` and `Incidents`. |
| `WEBSITE_SITE_NAME`, `WEBSITE_INSTANCE_ID` | Used to detect Azure App Service when no explicit database provider is set. |
| `LOG_ANALYSIS_PROVIDER` | `local`, `gcp`, or `auto` (default). Unknown values are not explicitly rejected and currently follow the remote/auto-style path. |
| `GCP_LOG_ANALYSIS_URL`, `LOG_ANALYSIS_URL` | Remote log analyzer URL; first nonempty value wins. Do not use localhost from Lambda. |

`server.js` loads root `.env` only when it does not detect Lambda using its initial check. The `.env` file exists in this workspace; its values are intentionally excluded from this document. Store real deployment secrets in an appropriate secret/configuration store. The current `.dockerignore` does not exclude `.env`, so Docker build context can include it.

### Frontend configuration

`frontend/api.js` checks, in order: `apiBaseUrl` URL query parameter, cloud-specific config globals/meta (`awsApiBaseUrl` or `azureApiBaseUrl`), generic globals/meta (`apiBaseUrl`), `http://localhost:3001` for `file:` pages, then same-origin. `frontend/index.html` defines `api-base-url`, `aws-api-base-url`, and `azure-api-base-url` meta tags; the AWS tag currently contains a configured endpoint, while the others are blank. The API URL is public client configuration, not a place for secrets.

### Container and hosting configuration

- Backend container exposes port 3001 and runs DynamoDB init then the server.
- Compose maps DynamoDB Local 8000, described log function 8080, and backend 3001. It sets AWS placeholder credentials for the local database, table name, and remote analyzer URL.
- AWS/Azure notes are examples, not proof of an active cloud deployment. `deploy.ps1` expects an external `deploy.zip`.
- `web.config` describes IIS/iisnode routing; actual platform behavior is unverified.

## 14. How To Run The Project

### Local backend and UI (the path supported by current files)

1. Install a compatible Node.js runtime. Node 22 is used in Docker; a minimum local Node version is not declared.
2. From the project root, run `npm install`.
3. Review `.env` privately. For the JSON provider, leave `DB_PROVIDER` unset or set `DB_PROVIDER=file`; do not copy secrets into shared files. If port 3001 is occupied, the app may select a port up to 3006.
4. Run `npm start`.
5. Open `http://localhost:3001` (or the port printed by the server). The backend serves the browser files.
6. Use `GET http://localhost:3001/api/health` to inspect the health response. No automated test command is supplied in `package.json`.
7. Stop with Ctrl+C.

This local path does not start a GCP function or DynamoDB. The JSON adapter writes to `backend/incidents.json` when selected. If selecting DynamoDB, start/configure a reachable DynamoDB first; `npm start` does not initialize its table. `npm run dev` is declared but `nodemon` is not declared in `package.json`.

### Docker (configuration exists but is currently incomplete)

`readme.md` documents `docker compose up --build` and `docker compose down`, but current `docker-compose.yml` asks Docker to build `gcp_function/Dockerfile` from a directory absent in this workspace. Therefore the full Compose startup is **not supported by the current checked-in files as they stand**. The standalone Dockerfile also runs DynamoDB initialization and expects the database endpoint to be reachable. Restore/confirm the missing function files and review `.dockerignore` before relying on these instructions.

### External cloud deployments

AWS Lambda/API Gateway and Azure App Service/Cosmos instructions are documented in `DEPLOYMENT_CONFIG_AWS.md`, `DEPLOYMENT_CONFIG_AZURE.md`, and `web.config`, but deployment infrastructure and current cloud state are not included. Treat those as operator-specific procedures; actual deployed URLs, IAM roles, CORS policy, secret configuration, and successful operation are **Unknown from the current codebase**. Never paste keys/tokens into this documentation.

## 15. Current Features

| Feature | Status and implementation |
|---|---|
| Browser incident list, filters, sort, create/edit/delete | **Implemented in source:** `frontend/index.html`, `frontend/app.js`, `frontend/api.js`, and incident route/service. End-to-end runtime verification was not performed. |
| Incident identifiers and SLA deadlines | **Implemented:** `idGenerator.js`, `sla.js`, and `incidentService.js`. IDs are generated by scanning existing data. |
| Timeline entries for create, status change, assignment, escalation | **Implemented:** embedded timeline array and `timelineService.js`; creation seeds the first entry. |
| Dashboard counts and health score | **Implemented:** `backend/routes/dashboard.js`, `healthScore.js`; dashboard GET also checks/escalates SLAs. |
| One-time SLA escalation | **Implemented with limitation:** `escalationService.js`, triggered only by dashboard requests. |
| Local log threat rules and auto-created incident | **Implemented in source:** rules file, `logAnalysisService.js`, and log-analysis route. Detection quality is heuristic and not validated by tests in this workspace. |
| Remote log-analysis HTTP integration | **Client implemented; service unavailable/uncertain:** route client exists but the expected Python/GCP function code is missing from current files. |
| JSON, DynamoDB, and Cosmos storage adapters | **Implemented in source:** provider selector plus three adapters. Deployment credentials, schema compatibility, and live cloud behavior are not verified. |
| Lambda handler export / API Gateway stage compatibility | **Partially implemented:** `serverless-http` handler and `/prod` stripping are present; actual Lambda/API Gateway configuration is external. |
| Azure IIS/iisnode support | **Configuration present, unverified:** `web.config`, Azure notes and deployment helper exist; no deployment package is present. |

## 16. Current Limitations

- No authentication or authorization: any caller that can reach the API can use its operations.
- CORS is enabled without an origin allowlist.
- Escalation depends on someone or something requesting the dashboard; no scheduler or worker runs it independently.
- One overdue incident is escalated only once. A CRITICAL incident remains CRITICAL and is marked escalated; no further escalation state exists.
- Create validation only checks for truthy title, severity, and assignee. There is no schema validation, severity/status allowlist, length limit, or strong type validation in business logic.
- The log analyzer is a small static ruleset. It can have false positives/negatives and should not be treated as a full SIEM or proof that logs are safe.
- The remote analyzer has no authentication header or explicit request timeout in this source.
- File storage rewrites the whole JSON file and has no concurrency protection. It is suitable only for local/demo use.
- DynamoDB list and ID generation rely on scans; this can become slow and costly as data grows.
- ID generation is not a robust distributed sequence. Concurrent creates can choose the same ID; DynamoDB `PutCommand` has no conditional expression, so a collision can replace an existing record. Retry logic only helps if the provider actually reports a conflict.
- There is no cross-provider data migration, replication, failover, or dual-write behavior.
- No test suite, CI configuration, migrations, or observability stack is present in this workspace.
- Compose and README refer to absent `gcp_function/` files. Deployment zip referenced by `deploy.ps1` is absent.
- `tree.txt`, some ER/lifecycle diagrams, and narrative project context do not match the current implementation.
- `.dockerignore` does not exclude `.env`; a Docker build can include local environment values in its build context/image unless handled outside current config.

## 17. Known Bugs / Potential Issues

These are source-based risks; they have not been reproduced by running the app.

| Location | Issue and possible consequence |
|---|---|
| `docker-compose.yml` references `gcp_function/Dockerfile`; current workspace has no `gcp_function/` directory | Compose build is expected to fail before startup. README's Python function instructions have no matching source/requirements file here. |
| `.dockerignore` | `.env` is not excluded, although the Dockerfile copies the project context. Local configuration or secrets may be included in a built image. |
| `frontend/app.js`, `renderTimelineEntries()` | Timeline fields (`from`, `to`, `by`, and action text) are inserted into `innerHTML` without escaping. Since API update inputs can influence assignment/status/actor fields, crafted values may become browser markup/script. |
| `backend/services/incidentService.js` + `idGenerator.js`; `dynamoService.js` | ID allocation scans existing incidents and is race-prone; DynamoDB Put has no conditional create. Under concurrent requests an ID collision may overwrite a record. |
| `backend/services/incidentService.js` | `updateIncident()` accepts arbitrary status strings and create accepts arbitrary severity strings after uppercasing. Unexpected values can appear in counts/UI and receive default SLA behavior. |
| `backend/services/incidentService.js` + `sla.js` | Changing severity does not recalculate `slaDeadline`. An incident's SLA therefore remains based on its creation severity after escalation or manual data changes. |
| `backend/services/jsonFileService.js` | Whole-file read/modify/write operations can race and lose one request's changes if concurrent writes overlap; writes are not atomic. |
| `backend/services/escalationService.js` | The dashboard response triggers persistence changes. Opening the dashboard may unexpectedly change overdue incident severity/timeline; no separate scheduled run exists. |
| `backend/server.js` | Lambda detection for starting the listener checks `IS_LAMBDA` only, while other Lambda logic also checks `AWS_LAMBDA_FUNCTION_NAME`. A deployment that omits `IS_LAMBDA=true` may attempt `app.listen()` during Lambda module initialization. |
| `frontend/api.js` | `apiBaseUrl` query parameter is accepted before configured hosts. Anyone with a crafted URL may direct browser API calls to another host; this also risks sending log/incident data to an unintended endpoint. |
| `backend/routes/incidents.js` | Missing GET and PUT records are returned as JSON messages/null with HTTP 200, which can make clients treat failures as normal success unless they inspect the body. |
| `backend/services/logAnalysisService.js` | Remote `fetch` has no timeout and parses JSON before checking `response.ok`; an unresponsive service can hold a request for an extended time, and non-JSON errors become generic parse errors. |
| `backend/server.js` / API | No request-rate limiting, authentication, authorization, or restrictive CORS is present. Public deployment could expose incident data and operations to untrusted callers. |
| `backend/incidents.json` | The checked-in sample incident has a historical SLA deadline and `escalated:false`. With JSON storage, the next dashboard request is expected to mark it overdue and escalate it. |
| `package.json` | `dev` invokes `nodemon`, but it is not a declared dependency; a clean `npm install` may not provide that executable. |

## 18. Future Modification Guide

- Change page layout or available form fields → `frontend/index.html`.
- Change colors, spacing, breakpoints, or visual states → `frontend/style.css`.
- Change browser interactions, rendering, refresh cadence, or form payloads → `frontend/app.js`.
- Change API URL selection, paths, HTTP handling, or JSON requests → `frontend/api.js`.
- Add/change an HTTP route → add or update a module in `backend/routes/`, then mount it in `backend/server.js` (and add its `/api` alias if desired).
- Change incident validation, ID assignment, default values, filters, updates, or deletion behavior → `backend/services/incidentService.js` and the relevant utility.
- Change SLA duration → `backend/utils/sla.js`; consider how existing records and severity updates should behave.
- Change escalation conditions or frequency → `backend/services/escalationService.js` and the caller/scheduling design. It is currently invoked by `backend/routes/dashboard.js` only.
- Change dashboard counts or health scoring → `backend/routes/dashboard.js` and `backend/utils/healthScore.js`.
- Add/change detection patterns → `data/detection_rules.json`; change provider/fallback/response handling → `backend/services/logAnalysisService.js`.
- Change log-analysis incident creation → `backend/routes/logAnalysis.js` and `backend/services/incidentService.js`.
- Change how timeline entries are stored → `backend/services/timelineService.js` and the incident record shape in each provider. Preserve compatibility for existing embedded timelines.
- Change storage selection → `backend/db.js`; change a specific storage implementation → its adapter under `backend/services/`. Preserve the common provider method interface.
- Change DynamoDB table key/initialization → `backend/initDynamoDB.js` and `backend/services/dynamoService.js` together.
- Change Cosmos partitioning/resource setup → `backend/services/azureCosmosService.js`; existing Cosmos containers may have partitioning that differs from the current default.
- Change local startup dependencies or package scripts → `package.json` and `package-lock.json`.
- Change container topology → `Dockerfile`, `docker-compose.yml`, and `.dockerignore` together. Confirm the referenced function directory exists before using Compose.
- Change cloud deployment setup → deployment note files and external platform settings; do not put actual keys in repository files.
- Change presentation content → `generate_ppt.py`, then regenerate the PPTX in an environment with `python-pptx` installed.

Before changing stored data shapes or provider behavior, inspect all three adapters and the route/service assumptions. Provider switching does not migrate data.

## 19. Dependency Map

```text
frontend/index.html ──loads──> frontend/style.css
       │
       ├──loads──> frontend/api.js ──HTTP──> backend/server.js
       └──loads──> frontend/app.js ──calls──> API helpers in api.js

backend/server.js
  ├──middleware: express, cors, dotenv
  ├──serves: frontend/
  ├──routes/incidents.js ──> services/incidentService.js
  ├──routes/dashboard.js ──> services/escalationService.js
  │                            ├──> services/timelineService.js
  │                            └──> db.js + utils/healthScore.js
  └──routes/logAnalysis.js ──> services/logAnalysisService.js
                                ├──> data/detection_rules.json (local)
                                └──> configured HTTP endpoint (remote)

services/incidentService.js ──> db.js + utils/idGenerator.js + utils/sla.js
                               + services/timelineService.js
db.js ──selects one──> jsonFileService.js | dynamoService.js | azureCosmosService.js
```

The three data adapters must continue to expose the operations expected by services (`getAllIncidents`, `getIncidentById`, `createIncident`, `updateIncident`, `updateIncidentStatus`, and `deleteIncident`; `updateIncidentStatus` is currently compatibility/helper API and is not central to the service flow).

## 20. Current Project State

- **Definitely present in source:** an Express API, static browser UI, incident CRUD logic, embedded timeline, dashboard aggregation, one-time SLA escalation logic, local regex/literal log rules, and three storage adapter implementations.
- **Appears incomplete:** remote/GCP log analysis container, full Compose stack, Azure zip package, dev script dependency, validation/security controls, and any automated testing/CI.
- **Uncertain:** whether AWS, Azure, or remote analyzer deployments are currently active or correctly configured; whether the documented web.config setup works on the intended host; exact external service URL/authentication; any live behavior not represented in this workspace.
- **Use care before changing:** incident record shape, `incidentId` keys/partitioning, duplicated short and `/api` route mounts, Lambda flags, frontend API base URL selection, and timeline interpolation/rendering.

No runtime test or deployment was performed for this documentation task. The project source was inspected and the documentation claims above were cross-checked against the files in the current workspace. Presence of code is not presented as proof of successful cloud deployment.

## 21. AI Developer Handover

Before editing, trace one request through `backend/server.js` → route → service → `backend/db.js` → selected provider, and trace its browser call through `frontend/app.js` → `frontend/api.js`. This is the key architecture boundary.

Important constraints for a future assistant:

1. Treat the current source as authoritative over `CLAUDE_PROJECT_CONTEXT.md`, `readme.md`, `tree.txt`, diagrams, and presentation. Those materials describe some intended or older components. In particular, there is no `gcp_function/` directory in this workspace.
2. Preserve the common storage adapter interface. A change to the incident shape may require updates to JSON, DynamoDB, Cosmos, routes, UI rendering, and diagrams/docs.
3. The database provider switch selects a single backend. Do not describe it as live failover, multi-cloud replication, or migration.
4. SLA checks happen only when `/dashboard` is requested. Do not assume incidents are escalated on a timer.
5. Timeline entries are embedded in the incident, not separate database rows. Keep them safe to render; current `renderTimelineEntries()` does not escape all fields.
6. Severity/status validation is minimal. If changing these values, inspect dashboard counts, CSS classes, sorting, SLA logic, and persisted old records.
7. Never include `.env` contents or credentials in documentation, logs, generated files, or commits. `.dockerignore` currently does not exclude `.env`.
8. Check whether a deployment target, remote analyzer, or missing archive component is actually supplied before claiming it works. `docker-compose.yml` currently references a missing build directory, and `deploy.ps1` expects a missing `deploy.zip`.
9. Keep the absence of authentication, authorization, tests, and network-device protocols explicit unless later code adds them.

For common work, start with the map in Section 18 and review the relevant provider/route/browser layers together. Do not assume the narrative diagrams are a schema migration plan.
