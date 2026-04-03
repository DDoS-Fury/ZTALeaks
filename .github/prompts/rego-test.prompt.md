---
description: "Generate rigorous OPA unit tests covering edge cases for Rego policies."
---
# Generate Rego Unit Tests

Generate rigorous unit tests for the associated Open Policy Agent (OPA) Rego policies. 

## Requirements
- Write the tests in Rego (e.g., `policy_test.rego`).
- Ensure tests cover standard allowing paths (e.g., correct role, correct JA3 fingerprint, valid certificate).
        
## Specific Edge Cases to Cover
When evaluating the `policy.rego` logic, make sure the generated tests assert `deny` for the following scenarios:
1. **Missing JA3 Hashes**: Scenarios where the TLS telemetry/metadata is incomplete.
2. **Expired/Invalid Device Certs**: Scenarios testing the negative path for mTLS or certificate validation.
3. **Incorrect Roles & Clearance**: Scenarios where a valid user attempts to access a resource above their clearance level or outside their assigned zone.
4. **Insufficient Trust Scores**: Testing the threshold boundaries for dynamic ZTNA trust scores (e.g., trust score falling below the required minimum).

## Output Expectations
Output the complete Rego test code block. Briefly explain the synthetic input (`input` object) used to simulate the metadata payload normally forwarded by the Security Orchestrator and Envoy.