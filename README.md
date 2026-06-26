# ZTALeaks

![Copertina](docs/images/rdm1.png)

<div align="center">
  <img src="https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python" />
  <img src="https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white" alt="PyTorch" />
  <img src="https://img.shields.io/badge/scikit--learn-%23F7931E.svg?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB" />
  <img src="https://img.shields.io/badge/envoy-%23242424.svg?style=for-the-badge&logo=envoyproxy&logoColor=white" alt="Envoy" />
  <img src="https://img.shields.io/badge/OPA-%23323D47.svg?style=for-the-badge&logo=open-policy-agent&logoColor=white" alt="Open Policy Agent" />
  <img src="https://img.shields.io/badge/splunk-%23000000.svg?style=for-the-badge&logo=splunk&logoColor=white" alt="Splunk" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT" />
</div>

<br/>

**ZTALeaks** is a microservices-based reference implementation of a **Zero Trust Architecture (ZTA)** compliant with NIST SP 800-207. It simulates the management system of a nuclear power plant, focusing on strict network segmentation, risk-based access control, and continuous policy evaluation.

## 🏗️ Architecture

The system enforces strict separation between the **Policy Enforcement Point (PEP)** and the **Policy Decision Point (PDP)** across isolated network segments.

### Policy Enforcement Point (PEP)
- **Firewall (nftables)**: Outermost layer. Default-drop, stateful packet filtering.
- **Envoy Proxy**: Terminates TLS/mTLS, extracts JA3 fingerprints, and delegates authorization to the PDP (`ext_authz`).
- **Snort IDS**: Three instances (external, internal, mid-tier) detecting port scans, mTLS violations, cipher anomalies, and SYN floods.

### Policy Decision Point (PDP)
- **Security Orchestrator (Go)**: Central policy coordinator. Aggregates metadata, fetches AI anomaly scores, and queries OPA.
- **AI Inference (Graphagate / Python)**: Temporal Graph Network (TGN) scoring user access streams in real-time.
- **Open Policy Agent (OPA)**: Evaluates Rego policies based on RBAC, resource clearance, and the real-time AI risk score.

### Core Services & Data (Business Layer)
- **Business Logic (Go)**: REST API serving operational plant data (personnel, docs, nuclear materials, reactor telemetry) with role-scoped DB connections.
- **IAM Service (Go)**: User registration, JWT (RS256) issuance, Argon2id password hashing, and WebAuthn.
- **Databases (MongoDB 7)**:
  - *Business DB*: Stores operational data.
  - *Security DB*: Stores identity and rate-limiting data, fully isolated from business logic.
- **Observability**: Splunk Universal Forwarder centralizing structured JSON logs with `X-Request-ID` end-to-end tracing.

## 🚀 Getting Started

Please refer to the detailed [Getting Started Guide](docs/getting-started.md) to learn how to:
- Configure prerequisites (Docker, CUDA) and the `.env` file.
- Initialize and train the AI Model (Graphagate).
- Deploy the environment using Docker Compose.
- Seed and manage the databases.
- Simulate traffic and attacks for testing.

## 📂 Project Structure

- `api/` - Protobuf definitions (`ext_authz`).
- `deployments/` - Manifests for Docker Compose (`docker/`).
- `infra/` - Configurations for databases, Envoy, nftables, OPA, Snort, Splunk, and the AI Inference module.
- `services/` - Go microservices source code (`business-logic`, `iam-service`, `security-orchestrator`).
- `tests/` - Comprehensive E2E security tests, clients, and Snort alert generators.
- `tools/seeder/` - Go utility for initializing MongoDB collections with seed data.

## 🔒 Security Model Highlights

- **Risk-Based Authorization**: Access granted only if `role ∈ admitted_roles AND (ai_score - impact) < accepted_risk`.
- **Data Integrity**: SHA-256 hashes computed for critical DB records to prevent tampering.
- **Strict Network Segmentation**: Isolated `front-net`, `auth-net`, and `back-net` boundaries.
- **Clearance Levels**: Strict data hierarchy (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `SECRET` < `TOP_SECRET`).
- **Device Continuity**: Enforced via JA3 TLS fingerprinting locked to the JWT session.

## 🧪 Testing

The project includes test clients and alert generation suites to validate the Zero Trust Architecture:

1. **Simulate Traffic & Behavior**:
   Run the test client container to generate traffic and validate policies:
   ```bash
   docker compose -f deployments/docker/docker-compose.test.yml up --build
   ```

2. **Snort Alert Generation Tests**:
   The `tests/alerts/` directory contains a pytest suite that validates the Snort IDS detection rules (e.g. port scanning, mTLS violations).
   ```bash
   cd tests/alerts/
   pip install -r requirements.txt
   pytest
   ```

---
*MIT License - Copyright (c) 2026 DDoS-Fury*
