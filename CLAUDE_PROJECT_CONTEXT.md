# Incident Management System - Complete Project Context

> **Historical document:** This context describes an earlier multi-cloud/deployment version and is not authoritative for the current local-only application. AWS, Azure, GCP, Lambda, Docker, and deployment claims below no longer describe the current runtime. Inspect the current source and `readme.md` before making changes.

Use the current source and `readme.md` as authoritative; this file is historical context only.

## 1. What this project is

This is a full-stack Incident Management System for SOC/DevOps-style operations.
It helps teams:
- create and track incidents,
- prioritize by severity and SLA,
- monitor health metrics on a dashboard,
- auto-detect threats from raw logs,
- and auto-escalate overdue incidents.

Core idea: the same business logic can run on multiple cloud backends by switching providers via environment variables, without changing route/service code.

## 2. Business problem solved

In many teams, incidents are tracked manually (spreadsheets/chats), which causes:
- missed SLAs,
- weak audit trails,
- delayed escalation,
- inconsistent severity handling,
- and no automated threat detection from logs.

This project solves that through structured incident lifecycle management, timeline tracking, dashboard KPIs, and pluggable cloud persistence.

## 3. Architecture style

- Pattern: layered monolith (frontend + API + service layer + pluggable data provider).
- Backend: Node.js + Express, optionally wrapped for AWS Lambda using serverless-http.
- Frontend: vanilla HTML/CSS/JS served as static assets.
- Data Access: provider abstraction selected at runtime (`DB_PROVIDER`).
- Analytics/Detection: log analysis abstraction selected at runtime (`LOG_ANALYSIS_PROVIDER`).

## 4. High-level component map

1. Frontend UI
- Displays health banner and incident statistics.
- Supports filters (severity/status/sort), create/edit/delete, timeline view.
- Sends raw logs for threat analysis.

2. API Layer
- Health endpoint for deployment verification.
- Incident CRUD endpoints.
- Dashboard endpoint for computed metrics.
- Log-analysis endpoint that can auto-create incident on threat detection.

3. Service Layer
- Incident service: validation, ID generation, SLA assignment, updates, deletion behavior.
- Escalation service: checks SLA breaches, increases severity, marks escalated.
- Timeline service: appends immutable activity entries (created, reassigned, status change, escalated).
- Log analysis service: remote GCP call or local rule-engine fallback.

4. Data Providers (pluggable)
- AWS DynamoDB provider.
- Azure Cosmos DB provider.
- Local JSON file provider (development-safe fallback).

5. Detection Rules Engine
- Security rule catalog includes SQLi, XSS, command injection, SSRF, Log4Shell, brute force, etc.
- Rules are regex/literal patterns with severity and optional repeat threshold.

## 5. Clouds and services used

### AWS (primary compatibility path)
- DynamoDB used for incident persistence when `DB_PROVIDER=aws`.
- Lambda compatibility built into backend (through `serverless-http` and lambda-mode checks).
- API Gateway path-prefix handling is built in (`/prod` stripping + `/api/*` aliases).
- Local development can run with DynamoDB Local.

### Azure (secondary provider + hosting)
- Cosmos DB used when `DB_PROVIDER=azure` (or when Azure Cosmos env vars are present).
- Azure App Service deployment is supported (zip deploy script present).
- IIS/Node integration is configured using `web.config` (including WebDAV removal so PUT/DELETE work).

### GCP (log analysis integration)
- Log analysis supports calling a remote GCP-style HTTP function endpoint.
- If remote endpoint fails/unavailable and provider mode is `auto`, backend falls back to local rule engine.

Important implementation note:
- In this workspace, backend integration for remote GCP endpoint exists, but local fallback also fully works.
- If `LOG_ANALYSIS_PROVIDER=gcp` is forced, endpoint availability is mandatory.

## 6. Runtime provider-switch logic (key viva point)

### Database provider
Selection happens at runtime:
- `DB_PROVIDER=aws` -> DynamoDB
- `DB_PROVIDER=azure` -> Cosmos DB
- `DB_PROVIDER=file` -> local JSON file
- if unset:
  - Lambda mode -> DynamoDB
  - local/dev mode -> JSON fallback
  - Azure host detected without Cosmos config -> startup error (guardrail)

Why this matters:
- same API/service codebase,
- no vendor lock in at route/business layer,
- safer cloud migration and A/B deployments.

### Log analysis provider
- `LOG_ANALYSIS_PROVIDER=local` -> always local rule engine
- `LOG_ANALYSIS_PROVIDER=gcp` -> always remote endpoint (hard requirement)
- `LOG_ANALYSIS_PROVIDER=auto` -> remote when URL exists, else local fallback

Why this matters:
- resilient behavior under external-service downtime,
- deterministic behavior when strict mode required.

## 7. Main API behavior

1. Incident CRUD
- Create validates required fields and generates ID format `INC-YYYY-XXXX`.
- SLA deadline auto-calculated from severity.
- Update supports status and assignment changes with timeline tracking.
- Delete is idempotent-friendly (already deleted returns safe message).

2. Dashboard
- Returns total/open/in-progress/resolved/critical counts.
- Runs escalation check before responding.
- Computes health score from active incidents using weighted severity.

3. Analyze logs
- Accepts raw logs.
- Runs detection (remote or local).
- On threat detection, auto-creates incident with summarized matched rules and log snippet.

## 8. Incident lifecycle and governance

1. Create incident
- status = OPEN
- escalated = false
- timeline starts with CREATED event

2. Work incident
- status transitions OPEN -> IN_PROGRESS -> RESOLVED
- reassignment tracked as timeline event

3. SLA breach handling
- if active incident crosses SLA and not yet escalated:
  - LOW -> MEDIUM
  - MEDIUM -> HIGH
  - HIGH -> CRITICAL
- marks `escalated=true`
- writes ESCALATED timeline event

4. Resolution
- incident remains auditable via timeline history

## 9. Data model (practical implementation)

Incident object includes:
- incidentId,
- title, description,
- severity, status,
- assignedTo,
- slaDeadline,
- escalated,
- timeline[],
- createdAt, updatedAt.

Timeline entry includes:
- timestamp,
- action (CREATED / STATUS_CHANGE / REASSIGNED / ESCALATED),
- from,
- to,
- by.

## 10. Deployment topologies

### Local Docker stack
- backend container (Node/Express)
- DynamoDB Local container
- optional GCP-function container endpoint for remote analysis tests

### AWS-oriented serverless topology
- API Gateway -> Lambda (Express handler)
- Lambda -> DynamoDB
- Lambda -> remote log-analysis URL (must not be localhost)

### Azure web-app topology
- Azure App Service hosts Node backend
- Backend uses Cosmos DB when provider is azure
- health endpoint used for post-deploy validation

## 11. Security and reliability highlights

- Rule-based detection includes broad attack families (SQLi, XSS, SSRF, command injection, Log4Shell, etc.).
- Fallback strategies prevent total feature outage when remote detection unavailable.
- Provider abstraction isolates cloud-specific code.
- Error normalization prevents blank/opaque API errors.
- Conditional delete/update behavior distinguishes not-found vs success in DB operations.

## 12. Known practical constraints to mention honestly

- No authentication/authorization layer yet (reviewer may ask).
- No background queue/event bus; escalation runs on dashboard call, not scheduler/cron.
- Current architecture is strong for coursework/demo and moderate scale; enterprise scale would add:
  - auth,
  - message queue,
  - worker services,
  - observability stack,
  - CI/CD quality gates,
  - automated tests at higher depth.

## 13. Suggested 1-minute viva pitch

"This project is a multi-cloud incident management platform built with a layered Node.js architecture. The frontend offers live incident operations and log analysis. The backend keeps business logic cloud-agnostic, while persistence is switched at runtime between AWS DynamoDB, Azure Cosmos DB, or local JSON for safe development. For threat detection, logs are analyzed via remote GCP-style endpoint or local fallback rules. The system automatically assigns SLA deadlines, escalates breached incidents, tracks every change in a timeline, and provides real-time operational dashboard metrics. The main strength is provider abstraction and resilience: the same codebase supports different cloud backends with environment-driven configuration."

## 14. Ready-to-paste prompt for Claude

Copy this exactly:

"You are my project-review assistant. I built a multi-cloud Incident Management System with Node.js/Express backend and vanilla JS frontend.

Key implementation facts:
- Runtime DB provider switching via env var: aws (DynamoDB), azure (Cosmos DB), file (local JSON).
- If DB_PROVIDER unset: Lambda mode defaults to DynamoDB; local/dev mode defaults to JSON fallback.
- Log analysis provider switching via env var: gcp (remote URL required), local (rules file), auto (remote if configured else local fallback).
- Main API capabilities: incident CRUD, dashboard metrics, and log analysis endpoint that can auto-create incidents.
- Incident fields: incidentId, title, description, severity, status, assignedTo, slaDeadline, escalated, timeline, createdAt, updatedAt.
- Timeline actions tracked: CREATED, STATUS_CHANGE, REASSIGNED, ESCALATED.
- SLA breach escalation logic: LOW->MEDIUM->HIGH->CRITICAL for active, non-escalated incidents.
- Dashboard computes health score from active incidents and severity weights.
- Deployment supports local Docker, AWS Lambda/API Gateway compatibility, and Azure App Service + Cosmos setup.

Your job:
1) Ask me probable viva questions and ideal model answers.
2) Generate architecture explanations at beginner, intermediate, and expert depth.
3) Challenge me with cross-cloud tradeoff questions (AWS vs Azure choices, failover, cost, lock-in).
4) Help me defend design decisions and acknowledge limitations professionally.
5) Keep answers concise but technically strong and viva-ready."

## 15. Likely examiner questions and strong answers

Q1. Why call it multi-cloud if one backend runs at a time?
A: Because business and API layers are cloud-agnostic and persistence is provider-switched by configuration. This enables deploying same codebase on different clouds with minimal code changes.

Q2. How did you avoid vendor lock-in?
A: Cloud-specific SDK usage is isolated in provider modules. Services/routes consume a common CRUD interface, so migration affects provider implementation only.

Q3. What happens if remote log-analysis service is down?
A: In `auto` mode it falls back to local detection rules. In strict `gcp` mode it fails fast by design to guarantee deterministic dependency behavior.

Q4. How is SLA enforcement implemented?
A: SLA deadline is calculated at creation from severity. Escalation service checks overdue active incidents, raises severity one step, marks escalated, and appends timeline event.

Q5. Why timeline tracking?
A: For auditability and operational traceability. Every critical state/assignment/escalation change is recorded with timestamp and actor.

Q6. Biggest improvement if this became production?
A: Add auth/RBAC, scheduled background escalations, test coverage expansion, centralized logs/metrics/traces, and CI/CD policy gates.

---

If asked "which cloud is used?" answer clearly:
- Architecture is cloud-flexible.
- Data can run on AWS DynamoDB or Azure Cosmos DB.
- Log analysis can integrate with GCP endpoint.
- Current active cloud depends on environment variables in deployment.
