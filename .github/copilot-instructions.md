# ZTALeaks Workspace Guidelines

## Architecture & Component Boundaries
ZTALeaks is a microservices-based Zero Trust Architecture (ZTA) simulating a nuclear power plant, strictly adhering to NIST 800-207 principles by separating the Policy Enforcement Point (PEP) from the Policy Decision Point (PDP).

- **Envoy Proxy (PEP)**: Terminates TLS and extracts handshake metadata via TLS Inspector. Delegates authorization to the Security Orchestrator.
- **Security Orchestrator (`services/security-orchestrator/`)**: Go service acting as the central brain. Receives metadata, computes the JA3 MD5 hash, queries the Security DB, and calls OPA for trust decisions.
- **OPA Policy Engine (`infra/opa/policy.rego`)**: Evaluates Rego policies based on resource sensitivity, role, JA3 trust, and exact ZTNA metadata.
- **Databases (`infra/databases/`)**: 
  - *Security DB*: Stores device fingerprints (JA3) and certificate metadata.
  - *Business DB*: Stores application data (personnel, access badges, reactor parameters) augmented with continuous monitoring parameters (trust scores, risk flags).
- **Splunk**: Centralized logging via HTTP Event Collector (HEC).

*Security Constraint*: Strict network segmentation applies. The **Business DB must NEVER be reachable** from the outside world or directly from the Security Orchestrator. It can only be accessed by the Business Logic service over the isolated `Back-Net`.

## Build & Test
- **Start/Build Services**: 
  ```bash
  docker-compose up -d --build
  ```
  *(Note: Requires `.env` configuration with Splunk HEC tokens and DB passwords before starting).*
- **Testing**: Involves generating valid traffic baselines and simulating attack scenarios (e.g., port scanning) logged centrally to verify Intrusion Detection systems.

## Conventions & Best Practices
- **Traceability**: Every microservice **must** propagate and log the `X-Request-ID` to Splunk in JSON format to ensure end-to-end traceability for event correlation.
- **Data Integrity**: Operational records (like `reactor_parameters`) utilize embedded SHA-256 hashes (`data_integrity_hash`) checked by the system to ensure data in transit is not tampered with.
- **Plan First (Workflow)**: For non-trivial tasks (3+ steps or architectural decisions), write a detailed spec/plan in `tasks/todo.md` to track progress and reduce ambiguity. 
- **Subagents**: Use subagents liberally for parallel analysis, research, and exploration.
- **Verification**: Never mark a task complete without proving it works. Point at logs, errors, or failing tests and fix them autonomously without temporary hacks.
- **Simplicity & Minimum Impact**: Follow standard SWE principles. Make every change as simple as possible, impacting minimal code, but implementing design patterns when needed.

## Reference Documentation
For in-depth details, refer to the existing project documentation instead of duplicating:
- [Project Notes](docs/project-notes.md)
- [Business DB Documentation](infra/databases/business/BUSINESS_DB_DOCUMENTATION.md)
- [Envoy Config](infra/envoy/envoy.yaml)
- [OPA Policy](infra/opa/policy.rego)
- [Security Orchestrator Main](services/security-orchestrator/cmd/orchestrator/main.go)