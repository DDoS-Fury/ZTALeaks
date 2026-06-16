# ZTALeaks

![Copertina](docs/images/rdm1.png)

<div align="center">
  <img src="https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python" />
  <img src="https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white" alt="PyTorch" />
  <img src="https://img.shields.io/badge/scikit--learn-%23F7931E.svg?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes" />
  <img src="https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB" />
  <img src="https://img.shields.io/badge/envoy-%23242424.svg?style=for-the-badge&logo=envoyproxy&logoColor=white" alt="Envoy" />
  <img src="https://img.shields.io/badge/OPA-%23323D47.svg?style=for-the-badge&logo=open-policy-agent&logoColor=white" alt="Open Policy Agent" />
  <img src="https://img.shields.io/badge/splunk-%23000000.svg?style=for-the-badge&logo=splunk&logoColor=white" alt="Splunk" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT" />
</div>

<br/>

## Summary

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

The system exposes four categories of sensitive operational data through its REST API: personnel records, technical documents, nuclear material inventories, and reactor telemetry parameters. Every resource carries a classification level and is subject to continuous policy evaluation before access is granted, combining role-based rules with a real-time AI anomaly score produced by a Temporal Graph Network.

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

**Security Orchestrator (Go):** The central policy coordination service. Receives metadata from Envoy, obtains a real-time AI anomaly score for the requesting identity from the AI Inference service, assembles an input document for the OPA policy engine, and returns an allow or deny verdict. When OPA is unreachable, the orchestrator applies a fail-safe deny; when the AI Inference service is unreachable, a fail-secure anomaly score of 0.99 is assumed. Exposes a health endpoint and a catch-all evaluation endpoint to which Envoy forwards all requests for authorization.

**AI Inference Service (Graphagate):** A Python/PyTorch microservice (maintained as a git submodule at `infra/ai-inference`) that performs unsupervised anomaly detection over the continuous stream of Zero Trust access events using a Temporal Graph Network (TGN). Each access (IP/device → resource) is modeled as a temporal edge carrying Zero Trust signals; the model maintains a recurrent memory of each entity's behavior and scores every event sequentially (`anomaly score = 1 − P(benign)`). It detects three anomaly classes: contextual (compromised TLS trust, IDS alerts), policy (entity acting outside its role/clearance/tier), and lateral movement (authorized but unusual access patterns). Served as a FastAPI REST/JSON service queried by the Security Orchestrator via the `/infer` endpoint.

**Open Policy Agent (OPA):** Evaluates Rego policies against the input provided by the Security Orchestrator. The policy package `envoy.authz` implements a risk-impact security matrix: each (route, method) pair declares an operation impact, the set of admitted roles, and an accepted risk threshold. A request is allowed only if the user's role is admitted and `ai_score − impact < accepted_risk`. The default policy is deny.

### Business Layer

**Business Logic Service (Go):** Provides a RESTful JSON API over four domain collections (personnel, documents, nuclear materials, reactor parameters). Implements the repository pattern, with each repository bound to a role-scoped MongoDB connection (operator, manager, or admin database account) so that least privilege is enforced at the data layer as well. Computes SHA-256 data integrity hashes for all records before persistence, enabling tamper detection. Serves a minimal HTML frontend for browser-based interaction. Logs all HTTP requests in structured JSON format including the `X-Request-ID` propagated by Envoy for end-to-end traceability.

**Identity Service (Go):** Handles user registration and authentication. Stores user records in the dedicated Security Database, separate from business data. New users self-register with the default `guest` role and email-based OTP enabled. Verifies credentials using Argon2id password hashing with constant-time comparison to prevent timing attacks, and applies per-IP rate limiting on failed logins. On successful authentication, generates a JWT signed with RS256, valid for 15 minutes, containing user identity, role, MFA status, secure enclave validity, and the JA3 fingerprint of the authenticating client. Sets the token as an HttpOnly, Secure, SameSite=Strict cookie.

**MailHog:** A development SMTP sink used by the Identity Service to deliver OTP emails. Its web UI (port 8025) allows manual inspection of one-time passwords during testing.

### Data Layer

**Business Database (MongoDB 7):** Stores all operational plant data across seven collections with JSON Schema validators enforcing required fields, enumeration constraints, and identifier format patterns. Database accounts follow least-privilege through custom MongoDB roles: `operator_client` can access only `personnel`; `manager_client` adds `documents` and `nuclear_materials`; `admin_client` additionally accesses `reactor_parameters`. The Splunk reader and PDP reader accounts have read-only access, and the seed service account is intended for initial data population only.

**Security Database (MongoDB 7):** Stores user identity records in the `identity_users` collection, along with the per-IP `rate_limits` collection used for brute-force protection. Physically and logically separate from the Business Database. Accessible only from the Auth-Net segment, reachable by the Identity Service, the Security Orchestrator, and the Seeder (for default user provisioning), but not by the Business Logic service or any external component.

### Observability

**Splunk / Splunk Universal Forwarder:** Centralizes all structured logs. The Universal Forwarder monitors log volumes written by the Firewall, Envoy, both Snort instances, the Business Logic service, the Identity Service, and both databases. All logs are forwarded to the Splunk indexer over TCP port 9997. The `X-Request-ID` header propagated by all services enables end-to-end event correlation across components.

---

## Security Model

### Network Segmentation

Three isolated Docker networks enforce traffic boundaries:

- **front-net:** Connects the Firewall (with Envoy and Snort co-located via `network_mode: service:firewall`) and the Security Orchestrator. External traffic enters exclusively through this segment.
- **auth-net:** Connects the Security Orchestrator, the Identity Service, OPA, the AI Inference service, MailHog, and the Security Database. The Business Logic service also connects to this segment to receive authorization decisions, and the Seeder reaches the Security Database through it for default user provisioning.
- **back-net:** Connects the Business Logic service, the Business Database, the Seeder, and Splunk. The Business Database is reachable only from this segment, making it inaccessible to the Security Orchestrator and all external parties.

### Classification Levels

All resources carry a `classification_level` field with one of five values forming a strict hierarchy:

```
PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET
```

Classification levels drive access control decisions at the OPA policy layer. Reactor telemetry is classified SECRET. Nuclear material inventory is classified TOP_SECRET.

### Identity Roles and Access Domains

Identity-level roles form a strict hierarchy with associated default clearances:

| Role | Clearance | Accessible API domains |
|---|---|---|
| `guest` | — | Public paths only (default role assigned at self-registration) |
| `operator` | CONFIDENTIAL | Personnel |
| `manager` | SECRET | Personnel, Documents, Nuclear Materials |
| `admin` | TOP_SECRET | All of the above plus Reactor Parameters and the Trusted Guard |

The API surface is organized into three domains:

1. **Business & management (hierarchical RBAC):** Personnel, documents, and nuclear materials follow standard hierarchical role-based access where higher roles inherit lower-level access.
2. **Reactor core (strict Bell–LaPadula):** Reactor parameters are accessible exclusively by `admin`; lower roles cannot read up.
3. **Trusted Guard (sanitization gateway):** A dedicated endpoint (`POST /api/v1/trusted-guard/sanitized-delete-personnel/{id}`) allows `admin` to delete personnel records — a formal Bell–LaPadula write-down violation — by routing the operation through an explicit sanitization process.

The role separation is mirrored at the database layer: each Business Logic repository uses a MongoDB account whose custom role grants access only to the collections its domain requires.

### Risk-Based Authorization

Every authorization decision combines RBAC with a real-time AI anomaly score. The OPA policy defines a security matrix assigning to each (route, method) pair an operation impact, an admitted role set, and an accepted risk threshold. Access is granted only if:

```
role ∈ admitted_roles  AND  (ai_score − impact) < accepted_risk
```

The anomaly score is produced by the Graphagate Temporal Graph Network from the event stream of access requests (TLS fingerprint, IDS alerts, role/clearance posture, request method and path). Sub-routes with path parameters (e.g. `/api/v1/personnel/{id}`) are dynamically resolved to their base route by the policy. Public paths (login, registration, static assets) also undergo a lighter AI-score check before being admitted. If the AI Inference service is unreachable, the orchestrator assumes a fail-secure score of 0.99, effectively denying all risk-gated operations.

### Identity Trust Model

Each personnel record includes a `ztna_metadata` subdocument containing:

- `trust_score`: A floating-point value between 0.0 and 1.0 derived from behavioral analytics. Long-tenured internal staff are calibrated at 0.85–0.95. External inspectors are calibrated at 0.65–0.75 due to reduced behavioral history.
- `risk_flags`: Active risk indicators such as `qualification_expiring_soon` or `external_entity`.
- `mfa_enrolled`, `last_successful_auth`, `failed_auth_count`, `access_review_date`.

Each zone carries a `ztna_policy` subdocument specifying the minimum trust score, MFA requirement, maximum session duration, permitted device types, and permitted network segments for access to that zone's resources.

### Data Integrity

All repository implementations compute a SHA-256 hash of critical record fields before every insert or update. This `data_integrity_hash` field enables detection of unauthorized data modifications between persistence and consumption. Reactor parameter records carry a hash computed from reactor ID, timestamp, thermal power, electrical power, neutron flux, and reactor status.

### Authentication Security Measures

- **Self-registration:** New users register via `POST /api/v1/auth/register` and are assigned the minimal `guest` role with email-based OTP (2FA) enabled by default; privilege elevation requires administrative intervention.
- **Brute-force protection:** Per-IP rate limiting on failed logins (5 attempts, 5-minute block) backed by the `rate_limits` collection in the Security Database. The counter resets on successful authentication. The client IP used is the one validated by Envoy (`x-envoy-external-address`), not the spoofable `X-Forwarded-For`.
- **Password hashing:** Uses Argon2id with 64 MB memory, 3 iterations, and 4-degree parallelism, ensuring resistance to both GPU and ASIC-based attacks.
- **Timing attack resistance:** Employs constant-time comparison (`crypto/subtle.ConstantTimeCompare`) for credential verification. When a username is not found, a dummy Argon2id computation is performed to equalize response timing and prevent username enumeration.
- **JWT signing:** RS256 algorithm with asymmetric key pairs. Private key held exclusively by Identity Service; public key published at `/.well-known/jwks.json` for verification by downstream services.
- **Token claims:** Each JWT includes user identity (subject), assigned role, MFA enrollment status, device tier, and the TLS JA3 fingerprint of the authenticating client.
- **Token validity:** 15-minute expiration window enforces strict Zero Trust session requirements, mitigating the impact of token compromise.
- **Device continuity:** The JA3 fingerprint embedded in the JWT is verified on subsequent requests to detect device switching attacks or credential sharing across different TLS profiles.
- **Cookie attributes:** Session tokens set with `HttpOnly`, `Secure`, and `SameSite=Strict` flags to prevent XSS-based theft and CSRF attacks.
- **HTTP timeouts:** The HTTP server enforces `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` to mitigate slow-connection attacks such as Slowloris.
- **WebAuthn support:** Users can enroll FIDO2 credentials for passwordless authentication, bypassing password compromise vectors entirely.

---

## Project Structure

```
ZTALeaks/
├── api/
│   └── ext_authz.proto             # Protobuf definition for ext_authz RPC
├── deployments/
│   ├── docker/
│   │   ├── docker-compose.yaml     # Primary deployment composition
│   │   ├── docker-compose.test.yaml # Automated test execution
│   │   ├── docker-compose.cpu.yaml # CPU-only configuration (no GPU for AI inference)
│   │   └── docker-compose.arm.yaml # ARM64 platform configuration
│   └── kubernetes/                 # Kubernetes manifests with Kustomize
│       ├── 01-configs.yaml         # ConfigMaps for infrastructure services
│       ├── 02-secrets.yaml         # Opaque secrets for credentials and TLS
│       ├── 03-business-db.yaml     # Business Database StatefulSet
│       ├── 04-security-db.yaml     # Security Database StatefulSet
│       ├── 05-pep-edge.yaml        # PEP layer deployment (Firewall, Envoy, Snort)
│       ├── 06-pdp.yaml             # PDP layer (Security Orchestrator, OPA)
│       ├── 07-business.yaml        # Business Logic and Frontend services
│       ├── 08-network-policies.yaml # Zero Trust network segmentation
│       └── kustomization.yaml      # Kustomize entry point
├── infra/
│   ├── ai-inference/               # Graphagate TGN anomaly scorer (git submodule)
│   ├── databases/
│   │   ├── business/               # Business Database initialization
│   │   │   ├── Dockerfile
│   │   │   ├── mongod.conf         # MongoDB configuration with authorization
│   │   │   └── init-scripts/       # Collection schemas and role definitions
│   │   └── security/               # Security Database initialization
│   │       ├── Dockerfile
│   │       ├── mongod.conf
│   │       └── db_init/            # Identity user collection initialization
│   ├── envoy/
│   │   ├── Dockerfile
│   │   └── envoy.yaml              # Complete Envoy v3 API configuration
│   ├── nftables/
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh           # Firewall bootstrap and rule installation
│   │   ├── nftables.conf           # Stateful packet filtering rules
│   │   ├── ulogd.conf              # Netfilter logging configuration
│   │   └── parser.go               # JSON parser for ulogd LOGEMU output
│   ├── opa/
│   │   ├── policy.rego             # Risk-impact security matrix authorization engine
│   │   ├── policy_test.rego        # OPA policy unit tests
│   │   └── data.json               # Static policy data
│   ├── snort/
│   │   ├── Dockerfile
│   │   ├── parser.go               # Alert parser with rate limiting
│   │   └── rules/                  # Port scanning detection rules
│   ├── snort-internal/
│   │   ├── Dockerfile
│   │   ├── parser.go               # Alert parser for internal threats
│   │   └── rules/                  # mTLS violations, cipher anomaly, SYN flood rules
│   ├── snort-mid/
│   │   ├── Dockerfile
│   │   ├── parser.go
│   │   └── rules/                  # Mid-tier traffic inspection rules
│   └── splunk-uf/
│       ├── inputs.conf             # Log source definitions
│       └── outputs.conf            # Splunk indexer forwarding targets
├── services/
│   ├── business-logic/             # REST API for operational plant data
│   │   ├── Dockerfile
│   │   ├── go.mod
│   │   ├── cmd/server/main.go      # Entry point
│   │   ├── config/config.go        # Configuration loading
│   │   ├── internal/
│   │   │   ├── db/                 # MongoDB repository implementations
│   │   │   ├── handler/            # HTTP handlers with route registration
│   │   │   ├── middleware/         # Request logging and correlation
│   │   │   └── models/             # Domain models and enumerations
│   │   ├── static/                 # Stylesheet and JavaScript assets
│   │   └── templates/              # HTML templates for browser UI
│   ├── iam-service/           # Authentication and credential management
│   │   ├── Dockerfile
│   │   ├── go.mod
│   │   ├── cmd/identity/main.go    # Entry point
│   │   ├── config/config.go        # Configuration loading
│   │   ├── internal/
│   │   │   ├── crypto/             # Argon2id hashing and RS256 JWT generation
│   │   │   ├── db/                 # User and device repositories
│   │   │   ├── handler/            # Authentication endpoints
│   │   │   ├── logger/             # Structured JSON logging
│   │   │   ├── mailer/             # Email notification service
│   │   │   ├── seed/               # Default user provisioning
│   │   │   └── webauthn/           # WebAuthn/FIDO2 credential management
│   │   └── templates/              # Authentication UI templates
│   └── security-orchestrator/      # Policy Decision Point coordinator
│       ├── Dockerfile
│       ├── go.mod
│       ├── cmd/orchestrator/main.go # Entry point
│       ├── config/config.go         # Configuration loading
│       └── internal/
│           ├── aiscorer/           # Simulated risk score computation
│           ├── cache/              # Snort alert cache with TTL
│           ├── db/                 # MongoDB connection management
│           ├── handler/            # Authorization evaluation handler
│           ├── jwt/                # JWT verification and token extraction
│           ├── opa/                # OPA policy engine client
│           ├── snortlistener/      # Snort alert ingestion
│           └── tpm/                # TPM device verification lookup
├── tests/
│   ├── alerts/                     # Snort alert generation tests
│   │   ├── Dockerfile
│   │   ├── conftest.py             # Pytest configuration
│   │   ├── pytest.ini              # Test runner options
│   │   ├── requirements.txt        # Python dependencies
│   │   ├── snort-test.conf         # Snort configuration for testing
│   │   └── test_snort_*.py         # Detection rule validation tests
│   ├── clients/                    # End-to-end test clients
│   │   ├── Dockerfile              # Go client container
│   │   ├── Dockerfile.python       # Python client container
│   │   ├── go.mod
│   │   ├── main.go                 # Go test scenarios
│   │   └── main.py                 # Python test scenarios
│   ├── dashboard-app/              # Data visualization test application
│   │   ├── Dockerfile
│   │   ├── main.go
│   │   └── index.html
│   ├── e2e/                        # End-to-end security policy tests
│   │   ├── abac.sh                 # Attribute-based access control tests
│   │   ├── auth.sh                 # Authentication flow tests
│   │   ├── lib.sh                  # Shared testing utilities
│   │   ├── nftables.sh             # Firewall rule validation
│   │   ├── pep.sh                  # Policy enforcement tests
│   │   ├── rbac.sh                 # Role-based access control tests
│   │   ├── tier.sh                 # Device tier admission tests
│   │   ├── run_all.sh              # Master test runner
│   │   └── REPORT.md               # Test execution documentation
│   ├── opa/                        # OPA policy tests
│   ├── scripts/                    # Utility scripts
│   └── snort_live/                 # Live Snort integration tests
├── tools/
│   └── seeder/                     # Database initialization utility
│       ├── Dockerfile
│       ├── go.mod
│       ├── cmd/
│       ├── crypto/                 # Argon2id hashing for default user passwords
│       ├── models/                 # Seed data structures
│       └── seeders/                # Per-collection seed logic (incl. identity users)
├── .env                            # Environment configuration
├── install_operator_certs.sh       # Client certificate installer (CA + per-role certs)
├── .github/
│   ├── copilot-instructions.md     # Workspace guidelines
│   ├── instructions/
│   │   └── golang.instructions.md  # Go development standards
│   └── workflows/                  # CI/CD pipeline definitions
├── go.mod                          # Go workspace module definition
├── LICENSE                         # MIT License
└── README.md                       # This file
```

---

## Services

### Business Logic Service

Written in Go. Exposes a JSON REST API on port 8080 (configurable via `BUSINESS_LOGIC_PORT`). Implements the repository pattern across four MongoDB collections: personnel, documents, nuclear materials, and reactor parameters. Each collection is backed by a MongoDB repository implementation enforcing JSON Schema validation at the database layer.

**Role-scoped database connections:** Maintains three separate MongoDB connections (configurable via `MONGO_ADMIN_URI`, `MONGO_MANAGER_URI`, `MONGO_OPERATOR_URI`), each authenticated with a least-privilege database account. The personnel repository uses the operator account, the reactor parameters repository uses the admin account, and the documents and nuclear materials repositories use the manager account, mirroring the API-level role hierarchy at the data layer.

**Trusted Guard:** Exposes `POST /api/v1/trusted-guard/sanitized-delete-personnel/{id}`, an admin-only sanitization gateway that mediates write-down operations (admin deleting low-classification personnel records) which would otherwise violate the Bell–LaPadula model.

All records are persisted with SHA-256 data integrity hashes computed from critical fields, enabling tamper detection during data retrieval. Serves HTML templates for browser-based interaction and logs all HTTP requests in structured JSON format to both stdout and `/var/log/ztaleaks/business-logic/app.jsonl` for Splunk ingestion.

**Request traceability:** Propagates the `X-Request-ID` header throughout the request lifecycle, enabling end-to-end correlation of events across all system components.

**Graceful shutdown:** Intercepts `SIGINT` and `SIGTERM` signals, waits up to 5 seconds for active connections to complete, then disconnects from MongoDB.

### Identity Service

Written in Go. Exposes authentication endpoints on port 8082 (configurable via `PORT`). Manages user registration, credentials, device enrollment, and token lifecycle. Connects to the Security Database at the address specified by `SECURITY_DB_URI`, maintaining complete isolation from the Business Database.

**Registration:** Accepts new users via `POST /api/v1/auth/register` (username, email, password). New accounts are created with the minimal `guest` role and email-based OTP enabled by default.

**Authentication flow:** Accepts credentials via `POST /api/v1/auth/login`, verifies against Argon2id hashed passwords using constant-time comparison, and issues RS256-signed JSON Web Tokens valid for 15 minutes. Each token contains the user identity, assigned role, MFA enrollment status, and the JA3 fingerprint of the authenticating TLS connection for subsequent device continuity verification.

**Rate limiting:** Tracks failed login attempts per client IP in the `rate_limits` collection: after 5 failures, the IP is blocked for 5 minutes. The counter is reset on successful login, and the IP is taken from the Envoy-validated `x-envoy-external-address` header rather than spoofable client-supplied headers.

**Multi-factor authentication:** Generates one-time passwords delivered by email (via the MailHog SMTP sink in development) and verifies them via `POST /api/v1/auth/verify-otp`.

**WebAuthn enrollment:** Implements FIDO2 credential registration and assertion via `/api/v1/auth/register/begin|finish` and `/api/v1/auth/login/begin|finish` endpoints, enabling passwordless authentication. Credential enrollment requires an authenticated, non-guest user.

**Session management:** Issues JWT tokens as HttpOnly, Secure, SameSite=Strict cookies. Default users are provisioned by the Seeder, not by the service itself. Logs authentication and registration events in structured JSON (including the validated client IP) to `/var/log/ztaleaks/identity/identity_events.json`. Implements graceful shutdown with a 10-second timeout.

**JWKS publication:** Exposes its public key set at `/.well-known/jwks.json` for JWT verification by downstream services.

### Security Orchestrator

Written in Go. Exposes authorization evaluation endpoints on port 8081 (configurable via `SECURITY_ORCHESTRATOR_PORT`). Acts as the Policy Decision Point, receiving authorization requests from Envoy via `POST /api/v1/evaluate` and returning allow/deny verdicts.

**Decision logic:** On each request, the orchestrator:
1. Verifies the JWT signature and extracts claims (user identity, role, MFA status)
2. Queries the Security Database to verify device fingerprints and TPM enrollment status
3. Computes a risk score via the embedded AI scorer module based on temporal, behavioral, and device-based signals
4. Assembles a comprehensive input document containing request metadata, user claims, device posture, and risk signals
5. Submits the input to OPA for policy evaluation
6. Returns the policy engine's verdict to Envoy

**Cache layer:** Maintains an in-memory cache of Snort IDS alerts with a 3-minute TTL, enabling rapid correlation of detected threats with authorization decisions.

**Fail-safe behavior:** On OPA unavailability, returns HTTP 503 with a policy-engine-unavailable error, ensuring fail-closed access denial.

---

## Infrastructure

### Envoy Configuration

Envoy listens on port 8443 with the TLS Inspector listener filter enabled and JA3 fingerprinting activated. The filter chain accepts client certificates as optional for flexibility in device tier admission. The HTTP connection manager inserts the JA3 fingerprint and original URI into request headers (`x-ja3-fingerprint`, `x-original-uri`) before forwarding all requests to the external authorization service.

**Authorization integration:** The `ext_authz` HTTP filter calls the Security Orchestrator at `http://security-orchestrator:8081/api/v1/evaluate` with a 500-millisecond timeout. Configuration enforces fail-closed semantics: `failure_mode_allow: false` ensures that orchestrator unavailability results in access denial.

**Routing:** 
- `POST /api/v1/auth/*` → Identity Service cluster (port 8082)
- `GET /.well-known/jwks.json` → Identity Service cluster
- `GET|POST|PUT|DELETE /api/v1/*` → Business Logic cluster (port 8080)
- `/`, `/login`, `/register`, `/static/*` → Business Logic cluster

**Access logging:** Generates structured JSON access logs to both stdout and `/var/log/ztaleaks/envoy/access.jsonl`, including the TLS JA3 fingerprint, request ID, response code, and authenticated user for Splunk correlation.

### OPA Policy Engine

Deploys the Open Policy Agent with a multi-dimensional authorization model defined in `infra/opa/policy.rego`. The policy operates under package `envoy.authz` and evaluates authorization decisions across four independent dimensions:

**1. Path classification:** Distinguishes public, authentication, and protected business paths. Public paths (login, registration, health checks, static assets) require no authentication.

**2. Device tier admission:** Classifies devices into three tiers based on trust indicators:
- Tier 0: No client certificate, password + OTP required
- Tier 1: Client certificate validated by internal CA
- Tier 2: Certificate + TPM enrollment verified via Security Database

**3. Role-based access control:** Maps (path, HTTP method) pairs to permitted role sets. Each endpoint declares the roles authorized to execute its operations.

**4. Resource clearance:** Enforces a five-level classification hierarchy (PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET). The authenticated user's clearance level must equal or exceed the resource's minimum clearance for access.

**Default deny:** The policy defaults to `allow = false`, requiring explicit matching rules for every authorization decision. Policy evaluation failure or timeout results in automatic denial.

**Decision logging:** OPA logs all decisions to `/var/log/ztaleaks/orchestrator/opa_decision.jsonl` for audit and forensic analysis.

### Intrusion Detection System (Snort)

Three independent Snort instances provide defense-in-depth at different network boundaries:

**External IDS (`snort`):** Listens on the external-facing network interface co-located with Envoy. Detects inbound attack signatures, with primary emphasis on port scanning detection via SYN threshold analysis. Parses alerts into JSON format and writes to `/var/log/ztaleaks/snort/alerts.jsonl`.

**Internal IDS (`snort-internal`):** Monitors the traffic between the Firewall and Envoy. Detects:
- mTLS violations: Absence of valid client certificate in TLS 1.2 handshakes from internal sources
- Cipher anomalies: Deprecated or suspicious cipher suite usage inconsistent with known device fingerprints
- Obsolete TLS versions: TLS 1.0 and SSLv3 record header patterns
- Volumetric threats: SYN flood conditions targeting the Envoy port with abnormal connection rates

Alerts are parsed and written to `/var/log/ztaleaks/snort-internal/alerts.jsonl`.

**Mid-tier IDS (`snort-mid`):** Provides additional inspection of inter-service traffic within the back-net and auth-net segments.

All Snort alert parsers implement rate limiting (one alert per source IP per 5 seconds) to prevent alert spam and maintain Splunk ingestion bandwidth efficiency. Alerts are formatted as JSON and sent to the orchestrator's alert cache for real-time correlation with authorization decisions.

### Firewall (nftables)

Implements stateful packet filtering with default-drop ingress policy. Configured in `infra/nftables/nftables.conf`, the firewall:
- Maintains connection state tracking for TCP and UDP flows
- Permits inbound connections only on the Envoy-configured port
- Enforces egress filtering to constrain outbound traffic to authorized services and ports
- Logs all accept/reject decisions via ulogd in LOGEMU format
- Parses logs to JSON via embedded Go parser for Splunk forwarding

Runs with elevated Linux capabilities (`NET_ADMIN`, `NET_RAW`, `SYSLOG`, `SYS_ADMIN`) required for kernel-level packet manipulation.

### Certificate Management

The `certs/gen-certs.sh` script (excluded from version control per `.gitignore`) generates:
- **Root CA:** 4096-bit RSA certificate valid for 10 years, used to sign all service certificates
- **Envoy server certificate:** 2048-bit RSA with Subject Alternative Names for `ztaleaks_envoy`, `localhost`, `127.0.0.1`, valid for 10 years
- **Client certificate:** 2048-bit RSA for test clients, valid for 10 years

All certificates use OpenSSL extension files to enforce strict key usage and extended key usage constraints, preventing certificate misuse attacks.

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

The Seeder container (`tools/seeder/`) initializes all seven MongoDB collections with realistic seed data. The seeder is idempotent: each operation checks whether the target collection is already populated before inserting data. Seed data is inserted in dependency order: zones, then personnel, access badges, reactor parameters, maintenance orders, documents, and nuclear materials. The seeder runs as a non-root user (`seeduser`, UID 1001) and exits with code 0 after successful completion. If the Seeder container exits before completion due to missing dependencies, it will retry automatically when those dependencies become available.

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

The project includes comprehensive test suites across multiple layers:

### End-to-End Security Policy Tests

Located in `tests/e2e/`, these shell-based tests validate the complete Zero Trust policy enforcement chain:

- **abac.sh:** Attribute-based access control evaluation, verifying that authorization decisions respect user attributes (role, clearance, device tier) and resource attributes (classification level, required MFA).
- **auth.sh:** Authentication flow validation, including password-based login, OTP verification, WebAuthn enrollment and assertion, JWT token issuance, and token refresh.
- **rbac.sh:** Role-based access control matrix testing, ensuring that each role can access only the permitted operations and resources.
- **tier.sh:** Device tier admission testing, verifying correct classification of passwordless, certificate-only, and TPM-enrolled devices.
- **nftables.sh:** Firewall rule validation, confirming that packet filtering operates correctly at the network boundary.
- **pep.sh:** Policy Enforcement Point behavior testing, validating Envoy's authorization delegation, request routing, and fail-closed behavior on orchestrator unavailability.
- **run_all.sh:** Master test orchestrator executing all test suites in dependency order and generating `REPORT.md` with pass/fail results.

### Automated Test Clients

Two language implementations provide programmatic scenario simulation:

**Go client (`tests/clients/main.go`):** Executes six threat scenarios:
1. Valid TLS 1.2 without client certificate (mTLS violation detection)
2. Deprecated cipher suite usage (JA3 anomaly detection)
3. TLS 1.0 protocol downgrade attempt (obsolete TLS version detection)
4. SYN flood with 40 concurrent connections (volumetric attack detection)
5. Valid client certificate authentication (legitimate flow)
6. Port scanning simulation against ports 8000–8014 (port scan detection)

**Python client (`tests/clients/main.py`):** Equivalent scenarios using the Python `ssl` and `socket` modules.

Both clients require mounted certificates at `/app/certs/` and connect through the Envoy listener to validate the complete PEP-to-PDP pipeline.

**Execution:**
```bash
docker compose -f deployments/docker/docker-compose.test.yaml up
```

### Snort Alert Generation Tests

Located in `tests/alerts/`, pytest-based tests validate Snort rule detection:

- **test_snort_base.py:** Port scanning and external attack detection
- **test_snort_internal.py:** mTLS violations, cipher anomalies, TLS version downgrades
- **test_snort_mid.py:** Mid-tier traffic inspection rules

Tests generate synthetic malicious traffic patterns and verify that Snort produces alerts matching expected classifications and priorities.

### Internal Dashboard

`tests/dashboard-app/` provides a Go web application that demonstrates authorized API consumption. The dashboard fetches personnel, reactor, and zone data from the Business Logic API using a client certificate and renders results in an HTML table. Access denial by the Zero Trust PEP produces a clear denial message. The application listens on port 8080 and requires certificates at `/certs/`.

---

## Configuration

### Environment Variables

| Variable | Service | Default | Description |
|---|---|---|---|
| `BUSINESS_LOGIC_PORT` | business-logic | `8080` | HTTP port for the Business Logic API |
| `MONGO_URI` | business-logic | `mongodb://seed_service:...@business-db:27017/...` | MongoDB connection string for Business DB |
| `MONGO_DB` | business-logic | `nuclear_plant_db` | MongoDB database name |
| `SECURITY_DB_URI` | iam-service | `mongodb://ztadmin:ztpassword@security-db:27017/...` | MongoDB connection string for Security DB |
| `PORT` | iam-service | `8082` | HTTP port for the Identity Service |
| `LOG_DIR` | iam-service | `/var/log/ztaleaks/identity` | Directory for JSON log output |
| `SECURITY_ORCHESTRATOR_PORT` | security-orchestrator | `8081` | HTTP port for the Security Orchestrator |
| `OPA_URL` | security-orchestrator | `http://opa:8181/v1/data/envoy/authz/allow` | OPA policy evaluation endpoint |
| `ENVOY_PORT` | firewall | `8443` | Port for Envoy listener (injected into nftables and Snort rules) |
| `SPLUNK_PASSWORD` | splunk | `AdminPass2026!` | Splunk admin password |
| `SPLUNK_HEC_TOKEN` | splunk | — | HTTP Event Collector token |
| `MONGO_URI` | seeder | `mongodb://seed_service:...@localhost:27017/...` | MongoDB connection string for seeding |
| `MONGO_DB` | seeder | `nuclear_plant_db` | Target database for seed data |

---

## Observability

### Centralized Logging

Splunk acts as the centralized log aggregation and indexing platform. The Splunk Universal Forwarder monitors log volumes written by all infrastructure and application services, forwarding their contents to the Splunk indexer over TCP port 9997 (configurable via `outputs.conf`).

### Log Sources

| Service | Volume | Location | Forwarded to |
|---|---|---|---|
| Firewall | firewall-logs | `/var/log/ztaleaks/nftables` | Splunk |
| Envoy | envoy-logs | `/var/log/ztaleaks/envoy/access.jsonl` | Splunk |
| Snort (external) | snort-logs | `/var/log/ztaleaks/snort/alerts.jsonl` | Splunk |
| Snort (internal) | snort-internal-logs | `/var/log/ztaleaks/snort-internal/alerts.jsonl` | Splunk |
| Snort (mid-tier) | snort-mid-logs | `/var/log/ztaleaks/snort-mid/alerts.jsonl` | Splunk |
| Business Logic | business-logs | `/var/log/ztaleaks/business-logic/app.jsonl` | Splunk |
| Identity Service | identity-logs | `/var/log/ztaleaks/identity/identity_events.json` | Splunk |
| Security Orchestrator | orchestrator-logs | `/var/log/ztaleaks/orchestrator/app.jsonl` | Splunk |
| OPA Decisions | opa-logs | `/var/log/ztaleaks/orchestrator/opa_decision.jsonl` | Splunk |
| Business Database | business-db-logs | MongoDB diagnostic logs | Splunk |
| Security Database | security-db-logs | MongoDB diagnostic logs | Splunk |

### Request Traceability

All components propagate the `X-Request-ID` header injected by Envoy. This header enables end-to-end correlation of events across the firewall, proxy, orchestrator, databases, and application services. Each log entry includes the request ID as a standard field, allowing Splunk to reconstruct the complete request flow:

```
firewall → envoy → orchestrator → opa → business-logic
```

Example Splunk query for end-to-end tracing:
```
index=ztaleaks x_request_id=12345-67890 | table service,timestamp,action
```

### Log Format Standardization

All services emit structured JSON logs with consistent field naming:
- `service`: Source service identifier
- `timestamp`: RFC3339 formatted timestamp
- `x_request_id`: Request correlation identifier
- `level`: Log severity (debug, info, warn, error)
- Additional context-specific fields (user, resource, action, result)

### Audit Logging

OPA decision logs record every authorization decision with full context, enabling forensic analysis and compliance auditing. MongoDB operation logs capture all data modifications with user attribution. The combination provides a complete audit trail for regulatory compliance (applicable to nuclear facility operations).

---

## License

This project is released under the MIT License.

Copyright (c) 2026 DDoS-Fury
