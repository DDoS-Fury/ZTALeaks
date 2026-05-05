# ZTALeaks

## Zero Trust Architecture for Nuclear Plant Management Systems

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Model](#security-model)
4. [Project Structure](#project-structure)
5. [Services](#services)
6. [Infrastructure](#infrastructure)
7. [Data Model](#data-model)
8. [API Reference](#api-reference)
9. [Deployment](#deployment)
10. [Kubernetes Migration](#kubernetes-migration)
11. [Testing](#testing)
12. [Configuration](#configuration)
13. [Observability](#observability)
14. [License](#license)

---

## Overview

ZTALeaks is a microservices-based platform that implements a Zero Trust Architecture (ZTA) compliant with NIST SP 800-207 principles, applied to the management and monitoring of a simulated nuclear power plant. The project serves as both a functional management system and a reference implementation for adaptive, risk-based access control in critical infrastructure contexts.

The system manages seven categories of sensitive operational data: personnel records, physical access badges, plant zones, reactor telemetry parameters, maintenance work orders, technical documents, and nuclear material inventories. Every resource carries a classification level and is subject to continuous policy evaluation before access is granted.

The architecture enforces a strict separation between the Policy Enforcement Point (PEP) and the Policy Decision Point (PDP), implemented through distinct containerized services that communicate over isolated network segments. No single component has unrestricted access to another; every inter-service communication is subject to defined trust boundaries.

---

## Architecture

The system is composed of the following containerized components:

### Policy Enforcement Point (PEP)

**Firewall (nftables):** The outermost layer. Implements stateful packet filtering with default-drop policy on incoming traffic. Accepts connections exclusively on the Envoy-configured port. Logs accepted and rejected packets via ulogd for forwarding to the observability stack. Runs with elevated Linux capabilities (`NET_ADMIN`, `NET_RAW`, `SYSLOG`, `SYS_ADMIN`) required for kernel-level packet manipulation.

**Envoy Proxy:** Terminates TLS and implements mTLS. Extracts the JA3 fingerprint from each TLS handshake via the TLS Inspector listener filter. Forwards this fingerprint and the original request path as HTTP headers (`x-ja3-fingerprint`, `x-original-uri`) to the Security Orchestrator via the external authorization (`ext_authz`) HTTP service. Routes authenticated requests to the Identity Service or the Business Logic service based on path. Configured with short timeouts and fail-closed behavior: if the Security Orchestrator is unreachable, access is denied.

**Snort IDS (external):** Listens on the shared network interface of the Firewall container. Detects TCP port scanning based on SYN packet thresholds. Outputs alerts in fast format, which are parsed to JSON by an embedded Go parser and written to a shared log volume.

**Snort IDS (internal):** A second Snort instance dedicated to internal traffic between the Firewall and Envoy. Detects mTLS violations (missing client certificate patterns in TLS 1.2 handshakes), deprecated cipher suites associated with anomalous JA3 fingerprints, obsolete TLS versions (TLS 1.0 record header detection), and SYN flood conditions targeting the Envoy port.

### Policy Decision Point (PDP)

**Security Orchestrator (Go):** The central policy coordination service. Receives metadata from Envoy, computes a simulated AI risk score for the requesting identity, assembles an input document for the OPA policy engine, and returns an allow or deny verdict. When OPA is unreachable, the orchestrator applies a fail-safe deny. Exposes a health endpoint and a catch-all evaluation endpoint to which Envoy forwards all requests for authorization.

**Open Policy Agent (OPA):** Evaluates Rego policies against the input provided by the Security Orchestrator. The policy package `envoy.authz` implements path-based access logic distinguishing public paths (login, registration) from business API paths, applying a risk score threshold to each category. The default policy is deny.

### Business Layer

**Business Logic Service (Go):** Provides a RESTful JSON API over seven domain collections. Implements the repository pattern with full CRUD operations for each resource type. Computes SHA-256 data integrity hashes for all records before persistence, enabling tamper detection. Serves a minimal HTML frontend for browser-based interaction. Logs all HTTP requests in structured JSON format including the `X-Request-ID` propagated by Envoy for end-to-end traceability.

**Identity Service (Go):** Handles user authentication. Stores user records in the dedicated Security Database, separate from business data. Verifies credentials using Argon2id password hashing with constant-time comparison to prevent timing attacks. On successful authentication, generates a JWT signed with HMAC-SHA256, valid for 15 minutes, containing user identity, role, MFA status, secure enclave validity, and the JA3 fingerprint of the authenticating client. Sets the token as an HttpOnly, Secure, SameSite=Strict cookie.

### Data Layer

**Business Database (MongoDB 7):** Stores all operational plant data across seven collections with JSON Schema validators enforcing required fields, enumeration constraints, and identifier format patterns. Role-based database users follow least-privilege: the Envoy service account has read-write access, the Splunk reader and PDP reader accounts have read-only access, and the seed service account is intended for initial data population only.

**Security Database (MongoDB 7):** Stores user identity records in the `identity_users` collection. Physically and logically separate from the Business Database. Accessible only from the Auth-Net segment, reachable by the Identity Service and Security Orchestrator, but not by the Business Logic service or any external component.

### Observability

**Splunk / Splunk Universal Forwarder:** Centralizes all structured logs. The Universal Forwarder monitors log volumes written by the Firewall, Envoy, both Snort instances, the Business Logic service, the Identity Service, and both databases. All logs are forwarded to the Splunk indexer over TCP port 9997. The `X-Request-ID` header propagated by all services enables end-to-end event correlation across components.

---

## Security Model

### Network Segmentation

Three isolated Docker networks enforce traffic boundaries:

- **front-net:** Connects the Firewall (with Envoy and Snort co-located via `network_mode: service:firewall`) and the Security Orchestrator. External traffic enters exclusively through this segment.
- **auth-net:** Connects the Security Orchestrator, the Identity Service, OPA, and the Security Database. The Business Logic service also connects to this segment to receive authorization decisions.
- **back-net:** Connects the Business Logic service, the Business Database, the Seeder, and Splunk. The Business Database is reachable only from this segment, making it inaccessible to the Security Orchestrator and all external parties.

### Classification Levels

All resources carry a `classification_level` field with one of five values forming a strict hierarchy:

```
PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET
```

Classification levels drive access control decisions at the OPA policy layer. Reactor telemetry is classified SECRET. Nuclear material inventory is classified TOP_SECRET.

### Identity Trust Model

Each personnel record includes a `ztna_metadata` subdocument containing:

- `trust_score`: A floating-point value between 0.0 and 1.0 derived from behavioral analytics. Long-tenured internal staff are calibrated at 0.85–0.95. External inspectors are calibrated at 0.65–0.75 due to reduced behavioral history.
- `risk_flags`: Active risk indicators such as `qualification_expiring_soon` or `external_entity`.
- `mfa_enrolled`, `last_successful_auth`, `failed_auth_count`, `access_review_date`.

Each zone carries a `ztna_policy` subdocument specifying the minimum trust score, MFA requirement, maximum session duration, permitted device types, and permitted network segments for access to that zone's resources.

### Data Integrity

All repository implementations compute a SHA-256 hash of critical record fields before every insert or update. This `data_integrity_hash` field enables detection of unauthorized data modifications between persistence and consumption. Reactor parameter records carry a hash computed from reactor ID, timestamp, thermal power, electrical power, neutron flux, and reactor status.

### Authentication Security Measures

- Password hashing uses Argon2id with 64 MB memory, 3 iterations, and 4-degree parallelism.
- Constant-time comparison (`crypto/subtle.ConstantTimeCompare`) prevents timing-based credential enumeration.
- When a username is not found, the service performs a dummy Argon2id comparison to equalize response timing and prevent username enumeration.
- JWT tokens have a 15-minute validity window, consistent with strict Zero Trust session requirements.
- The JWT includes the JA3 fingerprint of the client that authenticated, enabling device continuity verification on subsequent requests.
- Cookies carrying the session token are set with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes.
- The HTTP server enforces `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` to mitigate slow-connection attacks such as Slowloris.

---

## Project Structure

```
ZTALeaks-master/
├── api/
│   └── ext_authz.proto             # Protobuf definition for ext_authz RPC
├── certs/                          # TLS certificates and generation script
│   ├── ca.crt / ca.key             # Internal Root CA
│   ├── server.crt / server.key     # Envoy server certificate
│   ├── client.crt / client.key     # Test client certificate
│   └── gen-certs.sh                # Certificate generation script
├── deployments/
│   ├── docker/
│   │   ├── docker-compose.yaml     # Primary deployment composition
│   │   └── docker-compose.test.yaml
│   └── kubernetes/                 # Kubernetes manifests
│       ├── 01-configs.yaml
│       ├── 02-secrets.yaml
│       ├── 03-business-db.yaml
│       ├── 04-security-db.yaml
│       ├── 05-pep-edge.yaml
│       ├── 06-pdp.yaml
│       ├── 07-business.yaml
│       ├── 08-network-policies.yaml
│       └── kustomization.yaml
├── infra/
│   ├── databases/
│   │   ├── business/               # MongoDB init scripts and configuration
│   │   └── security/               # Security DB initialization
│   ├── envoy/
│   │   └── envoy.yaml              # Envoy listener, filter chain, cluster definitions
│   ├── nftables/                   # Firewall rules, ulogd configuration, log parser
│   ├── opa/
│   │   └── policy.rego             # Rego authorization policy
│   ├── snort/                      # External IDS rules and alert parser
│   ├── snort-internal/             # Internal IDS rules and alert parser
│   └── splunk-uf/                  # Universal Forwarder inputs and outputs
├── services/
│   ├── business-logic/             # Plant data API service
│   │   ├── cmd/server/main.go
│   │   ├── config/
│   │   ├── internal/
│   │   │   ├── db/                 # MongoDB repository implementations
│   │   │   ├── handler/            # HTTP handlers and route registration
│   │   │   ├── middleware/         # Logging middleware
│   │   │   └── models/             # Go structs and enumeration constants
│   │   ├── static/css/
│   │   └── templates/              # HTML templates
│   ├── identity-service/           # Authentication and JWT issuance
│   │   ├── cmd/identity/main.go
│   │   └── internal/
│   │       ├── crypto/             # Argon2id and JWT implementation
│   │       ├── db/                 # User repository
│   │       ├── handler/            # Login API handler
│   │       ├── logger/             # Structured JSON logger
│   │       └── models/             # User and LoginInfo structs
│   └── security-orchestrator/      # PDP coordination and OPA integration
│       └── cmd/orchestrator/main.go
├── tasks/
│   └── todo.md                     # Kubernetes migration task tracking
├── tests/
│   ├── clients/                    # Go and Python test clients
│   └── dashboard-app/              # Internal dashboard for testing API access
└── tools/
    └── seeder/                     # Database population tool
        ├── cmd/seeder/main.go
        ├── models/                 # Seed data struct definitions
        └── seeders/                # Per-collection seed functions
```

---

## Services

### Business Logic Service

Written in Go. Exposes a JSON REST API on port 8080 (configurable via `BUSINESS_LOGIC_PORT`). Connects to the Business Database using the `seed_service` account by default (configurable via `MONGO_URI` and `MONGO_DB`). Serves HTML templates for the home, login, materials, and reserved pages. Logs all requests in structured JSON to both stdout and `/var/log/ztaleaks/business-logic/app.jsonl`, which is forwarded to Splunk by the Universal Forwarder.

**Graceful shutdown:** Intercepts `SIGINT` and `SIGTERM`, waits up to 5 seconds for active connections to complete, then disconnects from MongoDB.

### Identity Service

Written in Go. Exposes a single endpoint `POST /api/v1/auth/login` on port 8082 (configurable via `PORT`). Connects to the Security Database (`securitydb`) at the address specified by `SECURITY_DB_URI`. On startup, seeds a default admin user with a hashed password if the `identity_users` collection is empty. Logs events in structured JSON to `/var/log/ztaleaks/identity/identity_events.json`. Implements graceful shutdown with a 10-second timeout.

### Security Orchestrator

Written in Go. Exposes an evaluation endpoint on port 8081 (configurable via `SECURITY_ORCHESTRATOR_PORT`). Queries OPA at the address specified by `OPA_URL` (default: `http://opa:8181/v1/data/envoy/authz/allow`). Assembles an OPA input document containing the simulated AI risk score and the request attributes forwarded by Envoy. Returns `{"allowed": true}` or `{"allowed": false, "reason": "policy denied"}` to Envoy. On OPA failure, returns 503 with a policy-engine-unavailable message, enforcing fail-closed behavior.

---

## Infrastructure

### Envoy Configuration

Envoy listens on port 8443 with the TLS Inspector listener filter enabled and `enable_ja3_fingerprinting: true`. The filter chain requires client certificates (`require_client_certificate: false` in the primary configuration, `true` in the Kubernetes variant). The HTTP connection manager inserts the JA3 fingerprint and original URI into request headers before routing. The ext_authz filter calls the Security Orchestrator with a 0.5-second timeout. If the orchestrator does not respond, `failure_mode_allow: false` ensures the request is blocked.

Routes:
- `POST /api/v1/auth/login` → Identity Service cluster (port 8082)
- `GET|POST|PUT|DELETE /api/v1/*` → Business Logic cluster (port 8080)
- `/` → Business Logic cluster

### OPA Policy

The Rego policy in `infra/opa/policy.rego` under package `envoy.authz`:

- Default rule: `allow = false`
- Public paths (`/`, `/login`, `/register`, `/api/v1/auth/login`) are permitted when `input.risk_score < 0.3`
- Business API paths (prefix `/api/v1`) are permitted when `input.risk_score < 0.5`
- An unconditional `allow if { true }` rule exists as a permissive baseline for the current development state, intended to be replaced by role and clearance-based rules in production

### Certificate Management

The `certs/gen-certs.sh` script generates a 4096-bit RSA Root CA, a 2048-bit server certificate for Envoy with Subject Alternative Names for `ztaleaks_envoy`, `localhost`, and `127.0.0.1`, and a 2048-bit client test certificate. All certificates are valid for 3650 days. The script uses OpenSSL extension files to enforce appropriate key usage and extended key usage constraints.

---

## Data Model

### Collections

| Collection | Classification Range | Primary Key Format | Key ZTNA Fields |
|---|---|---|---|
| `personnel` | CONFIDENTIAL | `NP-YYYY-NNNN` | `ztna_metadata` (trust score, risk flags, MFA) |
| `access_badges` | CONFIDENTIAL | `BDG-NNNNN` | `access_log` with `AccessContext` |
| `zones` | INTERNAL to SECRET | `ZONE-*` | `ztna_policy` (min trust score, MFA, device types) |
| `reactor_parameters` | SECRET | `REACTOR-*` | `data_integrity_hash`, `scram_status` |
| `maintenance_orders` | INTERNAL to CONFIDENTIAL | `MO-YYYY-NNNN` | `safety_classification`, `approval_chain` |
| `documents` | INTERNAL to TOP_SECRET | `DOC-*` | `applicable_roles`, `classification_level` |
| `nuclear_materials` | SECRET to TOP_SECRET | `NM-*` | `iaea_safeguards`, `accountability` |

### Operational Roles

```
operator
maintenance_technician
radiation_protection_officer
security_officer
plant_manager
inspector
```

### Zone Types

```
public < controlled < restricted < exclusion
```

### Reactor States

```
shutdown | startup | power_operation | hot_standby | emergency_shutdown
```

### Maintenance Order Lifecycle

```
created → approved → scheduled → in_progress → completed | cancelled
```

---

## API Reference

All endpoints are prefixed with `/api/v1` and return `application/json`. All responses are subject to authorization by the Security Orchestrator before reaching the Business Logic service.

### Personnel

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/personnel` | List all personnel records |
| GET | `/api/v1/personnel/{id}` | Retrieve a personnel record by employee ID |
| POST | `/api/v1/personnel` | Create a personnel record |
| PUT | `/api/v1/personnel/{id}` | Update a personnel record |
| DELETE | `/api/v1/personnel/{id}` | Delete a personnel record |

### Zones

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/zones` | List all zones |
| GET | `/api/v1/zones/{id}` | Retrieve a zone by zone ID |
| POST | `/api/v1/zones` | Create a zone |
| PUT | `/api/v1/zones/{id}` | Update a zone |
| DELETE | `/api/v1/zones/{id}` | Delete a zone |

### Access Badges

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/badges` | List all access badges |
| GET | `/api/v1/badges/{id}` | Retrieve a badge by badge ID |
| POST | `/api/v1/badges` | Create an access badge |
| PUT | `/api/v1/badges/{id}` | Update an access badge |
| DELETE | `/api/v1/badges/{id}` | Delete an access badge |

### Reactor Parameters

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/reactor-parameters` | List all reactor parameter readings |
| GET | `/api/v1/reactor-parameters/{id}` | Retrieve a reading by reactor ID |
| POST | `/api/v1/reactor-parameters` | Insert a reactor parameter reading |
| PUT | `/api/v1/reactor-parameters/{id}` | Update a reactor parameter reading |
| DELETE | `/api/v1/reactor-parameters/{id}` | Delete a reactor parameter reading |

### Maintenance Orders

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/maintenance-orders` | List all maintenance orders |
| GET | `/api/v1/maintenance-orders/{id}` | Retrieve an order by order ID |
| POST | `/api/v1/maintenance-orders` | Create a maintenance order |
| PUT | `/api/v1/maintenance-orders/{id}` | Update a maintenance order |
| DELETE | `/api/v1/maintenance-orders/{id}` | Delete a maintenance order |

### Documents

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/documents` | List all documents |
| GET | `/api/v1/documents/{id}` | Retrieve a document by document ID |
| POST | `/api/v1/documents` | Create a document record |
| PUT | `/api/v1/documents/{id}` | Update a document record |
| DELETE | `/api/v1/documents/{id}` | Delete a document record |

### Nuclear Materials

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/nuclear-materials` | List all nuclear material records |
| GET | `/api/v1/nuclear-materials/{id}` | Retrieve a material by material ID |
| POST | `/api/v1/nuclear-materials` | Create a nuclear material record |
| PUT | `/api/v1/nuclear-materials/{id}` | Update a nuclear material record |
| DELETE | `/api/v1/nuclear-materials/{id}` | Delete a nuclear material record |

### Authentication

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Authenticate and receive a JWT |

Request body: `{"username": "string", "password": "string"}`

Successful response: `{"token": "<jwt>"}` with an `HttpOnly` session cookie `ztaleaks_session`.

---

## Deployment

### Prerequisites

- Docker Engine 24 or later
- Docker Compose v2
- OpenSSL (for certificate generation)

### Initial Setup

**1. Generate TLS certificates:**

```bash
bash certs/gen-certs.sh
```

**2. Configure the environment file:**

Create `.env` in the project root with the following variables:

```
ENVOY_PORT=8443
BUSINESS_LOGIC_PORT=8080
SECURITY_ORCHESTRATOR_PORT=8081
SPLUNK_PASSWORD=<your_splunk_admin_password>
SPLUNK_HEC_TOKEN=<your_splunk_hec_token>
SECURITY_DB_URI=mongodb://ztadmin:ztpassword@security-db:27017/securitydb?authSource=admin
```

**3. Build and start all services:**

```bash
docker compose -f deployments/docker/docker-compose.yaml up -d --build
```

**4. Verify service health:**

```bash
docker compose -f deployments/docker/docker-compose.yaml ps
```

The Business Database and Security Database include health checks. Dependent services (Identity Service, Seeder) will not start until their respective databases report healthy.

**5. Populate the Business Database:**

The Seeder container runs automatically on startup if the Business Database is healthy. It inserts seed data across all seven collections in dependency order: zones, personnel, access badges, reactor parameters, maintenance orders, documents, nuclear materials. The seeder exits after completion (`restart: "no"`).

**6. Access the interface:**

- Frontend: `https://localhost:8443/`
- Splunk: `http://localhost:8000` (credentials: `admin` / value of `SPLUNK_PASSWORD`)
- Envoy admin: `http://localhost:9901`

---

## Kubernetes Migration

A full set of Kubernetes manifests is provided under `deployments/kubernetes/`. The migration from Docker Compose is complete and includes the following resources:

| File | Contents |
|---|---|
| `01-configs.yaml` | ConfigMaps for Envoy, nginx, OPA policy, nftables, ulogd, Snort rules, and database initialization scripts |
| `02-secrets.yaml` | Opaque Secret for database passwords, Splunk HEC token, and base64-encoded TLS certificates |
| `03-business-db.yaml` | StatefulSet and headless Service for the Business Database |
| `04-security-db.yaml` | StatefulSet and headless Service for the Security Database |
| `05-pep-edge.yaml` | Deployment containing Envoy, Firewall, Snort, and Snort-internal as co-located containers; NodePort Service |
| `06-pdp.yaml` | Deployments and Services for the Security Orchestrator and OPA |
| `07-business.yaml` | Deployments and Services for the Business Logic service and the Frontend |
| `08-network-policies.yaml` | NetworkPolicies implementing strict zero-trust segmentation across Front-Net, Auth-Net, and Back-Net |

**Apply with Kustomize:**

```bash
kubectl apply -k deployments/kubernetes/
```

The NetworkPolicy `default-deny-all` drops all ingress and egress by default. Explicit allow rules are defined for each service following the same segmentation model as the Docker network configuration.

---

## Testing

### Automated Test Client

Two test clients are provided under `tests/clients/`:

**Go client (`main.go`):** Executes six test scenarios in sequence:
1. Valid request with standard TLS 1.2 and no client certificate (triggers Snort mTLS violation detection)
2. Anomalous request using deprecated cipher `TLS_RSA_WITH_AES_128_CBC_SHA` (triggers JA3 anomaly detection)
3. Obsolete protocol test using TLS 1.0 (triggers obsolete TLS version detection)
4. SYN flood simulation against port 8443 with 40 concurrent connections (triggers volumetric attack detection)
5. Request with a valid client certificate against the CA-trusted endpoint
6. Port scan simulation against ports 8000–8014 (triggers port scanning detection)

**Python client (`main.py`):** Equivalent test scenarios using the Python `ssl` and `socket` modules.

Both clients require the CA, client certificate, and client key to be mounted at `/app/certs/`.

**Run the test client:**

```bash
docker compose -f deployments/docker/docker-compose.test.yaml up
```

### Internal Dashboard

`tests/dashboard-app/` provides a minimal Go web application that fetches personnel, reactor, and zone data from the Business Logic API using a client certificate and renders the results in an HTML table. If access is denied by the Zero Trust PEP, the table displays a clear denial message. The dashboard listens on port 8080 and requires certificates mounted at `/certs/`.

### Database Seeder

`tools/seeder/` is a standalone Go application that connects directly to MongoDB and populates all seven collections with realistic seed data. It is idempotent: each seeder function checks whether the target collection is non-empty before inserting data. The seeder runs as a non-root user (`seeduser`, UID 1001) in a minimal Alpine container. It exits with code 0 after successful population.

---

## Configuration

### Environment Variables

| Variable | Service | Default | Description |
|---|---|---|---|
| `BUSINESS_LOGIC_PORT` | business-logic | `8080` | HTTP port for the Business Logic API |
| `MONGO_URI` | business-logic | `mongodb://seed_service:...@business-db:27017/...` | MongoDB connection string for Business DB |
| `MONGO_DB` | business-logic | `nuclear_plant_db` | MongoDB database name |
| `SECURITY_DB_URI` | identity-service | `mongodb://ztadmin:ztpassword@security-db:27017/...` | MongoDB connection string for Security DB |
| `PORT` | identity-service | `8082` | HTTP port for the Identity Service |
| `LOG_DIR` | identity-service | `/var/log/ztaleaks/identity` | Directory for JSON log output |
| `SECURITY_ORCHESTRATOR_PORT` | security-orchestrator | `8081` | HTTP port for the Security Orchestrator |
| `OPA_URL` | security-orchestrator | `http://opa:8181/v1/data/envoy/authz/allow` | OPA policy evaluation endpoint |
| `ENVOY_PORT` | firewall | `8443` | Port for Envoy listener (injected into nftables and Snort rules) |
| `SPLUNK_PASSWORD` | splunk | `AdminPass2026!` | Splunk admin password |
| `SPLUNK_HEC_TOKEN` | splunk | — | HTTP Event Collector token |
| `MONGO_URI` | seeder | `mongodb://seed_service:...@localhost:27017/...` | MongoDB connection string for seeding |
| `MONGO_DB` | seeder | `nuclear_plant_db` | Target database for seed data |

---

## Observability

### Log Volumes

Each service writes structured JSON logs to a named Docker volume:

| Volume | Contents |
|---|---|
| `firewall-logs` | nftables accept/reject events parsed to JSON |
| `envoy-logs` | Envoy access logs with JA3 fingerprint, request ID, response code |
| `snort-logs` | External IDS alerts (port scanning) |
| `snort-internal-logs` | Internal IDS alerts (mTLS violations, cipher anomalies, SYN floods) |
| `business-logs` | Business Logic HTTP request logs |
| `identity-logs` | Identity Service authentication events |
| `business-db-logs` | MongoDB operational logs |
| `security-db-logs` | Security MongoDB operational logs |

All volumes are mounted read-only by the Splunk Universal Forwarder, which forwards their contents to the Splunk indexer.

### Traceability

Every component propagates the `X-Request-ID` header. The value is extracted from the incoming request (inserted by Envoy) and included in every structured log entry as `x_request_id`. This enables correlation of all log events related to a single client request across the Firewall, Envoy, Security Orchestrator, and Business Logic service in a single Splunk query.

### Logging Middleware

The Business Logic service wraps all HTTP handlers with a `LoggingMiddleware` that captures the HTTP method, path, remote address, response status code, and request duration. The middleware also extracts the `X-Request-ID` header for inclusion in the log entry, defaulting to `unknown_request` if absent.

---

## License

This project is released under the MIT License.

Copyright (c) 2026 DDoS-Fury
