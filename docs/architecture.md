# ZTALeaks Architecture

## Overview
ZTALeaks is a microservices-based Zero Trust Architecture (ZTA) simulating a nuclear power plant, strictly adhering to NIST 800-207 principles. It implements adaptive, risk-based access control by separating the Policy Enforcement Point (PEP) from the Policy Decision Point (PDP). The system uses JA3 TLS fingerprinting, mTLS, and behavioral analysis for context-aware integrity checks beyond simple credential validation.

## Components
The system is distributed across multiple containerized components:

1. **Envoy Proxy (PEP)**: 
   - Terminates TLS connections and acts as an application-layer firewall.
   - Runs the TLS Inspector to extract handshake metadata (such as cipher suites and extensions).
   - Delegates authorization decisions to the Security Orchestrator via the `ext_authz` protocol.
2. **Security Orchestrator (Go)**:
   - Serves as the core logic component (PDP coordinator).
   - Receives connection metadata from Envoy, computes the JA3 MD5 hash, and queries the Security DB for device trust levels.
   - Queries the OPA Policy Engine to finalize trust decisions.
3. **OPA Policy Engine (PDP)**:
   - Evaluates Rego policies deterministically based on resource sensitivity, user role, JA3 device trust, and certificate presence/metadata.
4. **Dual MongoDB (Databases)**:
   - **Security DB**: Stores device hardware fingerprints (JA3) and certificate metadata to build hardware trust.
   - **Business DB**: Stores core application data (personnel records, access badges, reactor parameters embedded with SHA-256 `data_integrity_hash` tags) augmented with continuous monitoring parameters like trust scores and risk flags. 
5. **Splunk**:
   - Centralized logging platform via HTTP Event Collector (HEC).
   - Every microservice propagates and logs the `X-Request-ID` in JSON format to guarantee end-to-end event correlation and traceability.
6. **Network & Intrusion Detection (snoRT & Firewall)**:
   - **Network Firewall (NFTables)**: Interposed between the client and the main system to control inbound traffic. Logs are sent to Splunk.
   - **snoRT (NIDS)**: A Network Intrusion Detection and Prevention System that uses strategically positioned probes to analyze captured packets (e.g., detecting port scanning).

## Network Segmentation
To uphold the zero-trust strict networking model, the system leverages isolated Docker networks to enforce strict boundaries:

- **Front-Net**: Contains Envoy and the Security Orchestrator. This is the external-facing network that processes incoming requests.
- **Auth-Net**: A private network exclusively facilitating communication between the Security Orchestrator and the OPA Policy Engine.
- **Back-Net**: An isolated network connecting the **Business Logic** service and the **Business DB**.
  - *Constraint*: The Business DB must **NEVER** be reachable from the outside world or directly from the Security Orchestrator. 

## Request Flow
1. **Network Entry**: Client initiates an HTTPS HTTP handshake. The traffic passes the Network Firewall edge and is monitored by snoRT probes.
2. **Envoy Processing**: Envoy terminates TLS; the TLS Inspector extracts cipher suites and extensions.
3. **Authorization Delegation**: Envoy pauses the request and forwards the connection metadata to the Security Orchestrator.
4. **Context Building**: The Security Orchestrator computes the JA3 MD5 fingerprint and checks the Security DB to establish device trust context.
5. **Policy Evaluation**: The Security Orchestrator delegates the payload to the OPA Policy Engine, which evaluates the exact Rego policies to output an Allow/Deny decision.
6. **Execution**: 
   - If *Deny*, Envoy terminates the request.
   - If *Allow*, Envoy routes the request to the Business Logic service over the Back-Net.
7. **Business Processing**: The Business Logic service processes the request, communicating solely with the isolated Business DB.
8. **Logging**: Every step of this execution emits JSON logs to Splunk carrying the correlation identifier `X-Request-ID`.