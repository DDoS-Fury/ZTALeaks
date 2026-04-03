# ZTALeaks Base Infrastructure Testing

## 1. Test Client Implementation (Go)
- [x] Initialize Go module for the test client inside `tests/clients/`
- [x] Create HTTP client logic with custom TLS Config (e.g., specific cipher suites) to manipulate the JA3 fingerprint
- [x] Implement requests simulating valid access (e.g., getting the home page)
- [x] Implement requests simulating malicious/anomalous access (e.g., bad JA3)

## 2. Containerization
- [x] Write `tests/clients/Dockerfile` based on Golang alpine image
- [x] Ensure the container runs as a one-off execution for testing scenarios

## 3. Orchestration & Configuration
- [x] Create `deployments/docker-compose/docker-compose.test.yaml` (or update main compose)
- [x] Define the test clients, attaching them to the `front-net` network to reach Envoy
- [x] Pass necessary configuration (certificates, target Envoy URL) as environment variables

## 4. Verification
- [ ] Verify test containers build and execute successfully
- [ ] Verify logs in Splunk and Security Orchestrator for correctly logged ZTA evaluations
- [ ] Prove OPA correctly denies/allows the fabricated JA3 requests

## 5. Implement ZTA `ext_authz` Pipeline (PEP & PDP)
- [ ] **Envoy (`envoy.yaml`)**: Add `tls_inspector` listener filter, configure `ext_authz` HTTP filter to call Orchestrator, route to `business-logic` cluster.
- [ ] **Security Orchestrator**: Refactor `main.go` from a static stub to implement an `ext_authz` server (gRPC/HTTP) to process TLS contexts and JA3 hashes.
- [ ] **Business Logic**: Verify upstream reception and proxying.
