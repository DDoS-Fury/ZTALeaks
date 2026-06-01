# ZTALeaks — E2E Validation Report (auto-generated)

**Generated**: 2026-05-24T16:43:09Z
**Stack endpoint**: `https://127.0.0.1:8443`
**Source**: `tests/e2e/run_all.sh` su 6 pillar.

Questo file viene rigenerato a ogni esecuzione.

---

## Summary

| # | Pillar | Status |
|---|---|---|
| 1 | Authentication Flow (login + 2FA) | ❌ FAIL |
| 2 | Policy Enforcement Point (Envoy + ext_authz) | ❌ FAIL |
| 3 | Role-Based Access Control (OPA) | ❌ FAIL |
| 4 | Attribute-Based Access (clearance hierarchy) | ❌ FAIL |
| 5 | 3-Tier Admission (cert × TPM) | ❌ FAIL |
| 6 | Firewall (nftables rate-limiting + egress) | ✅ PASS |

**Outcome**: almeno un pillar è FAIL.

---

## Per-pillar output

### Authentication Flow

- **Script**: `tests/e2e/auth.sh`
- **Status**: FAIL

```
[18:42:57] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:00] Auth pillar — admin login flow + claims

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  admin login → JWT issued                                   yes        no         FAIL
[18:43:03] Negative scenario: OTP errato
  verify-otp con OTP errato → 401                            401        400        FAIL
  login con password errata → 401                            401        403        FAIL

  Total: 3  PASS: 0  FAIL: 3
```

### PEP

- **Script**: `tests/e2e/pep.sh`
- **Status**: FAIL

```
[18:43:03] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:03] PEP pillar — public bypass + protect by default

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  /api/v1/auth/login (public) → non 403                      ok         ok         PASS
  /.well-known/jwks.json (public) → 200                      200        200        PASS
  GET /personnel senza JWT → 403                             403        403        PASS
  GET /nuclear-materials no-JWT (con cert) → 403             403        000        FAIL
  GET /personnel con JWT garbage → 401                       401        401        PASS

  Total: 5  PASS: 4  FAIL: 1
```

### RBAC

- **Script**: `tests/e2e/rbac.sh`
- **Status**: FAIL

```
[18:43:04] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:05] RBAC pillar — role × resource matrix (OPA)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT operator1
```

### ABAC

- **Script**: `tests/e2e/abac.sh`
- **Status**: FAIL

```
[18:43:05] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:05] ABAC pillar — clearance vs resource

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT insp_e2e_low
```

### Tier admission

- **Script**: `tests/e2e/tier.sh`
- **Status**: FAIL

```
[18:43:05] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:05] Tier admission pillar — cert × tpm (utente fresh per isolare TPM)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT tier_pm_gi0u_q
```

### Firewall (nftables)

- **Script**: `tests/e2e/nftables.sh`
- **Status**: PASS

```
[18:43:06] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[18:43:06] Firewall pillar — nftables rate-limiting + egress filtering

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
[18:43:06] TEST 1: Normal traffic to Envoy (chain input accept)
  Normal traffic to Envoy                                      allowed    allowed    PASS
[18:43:06] TEST 2: blocked_ips set is loaded with expected elements
  blocked_ips contains 10.99.99.99                             present    present    PASS
  blocked_ips contains 172.18.0.10                             present    present    PASS
[18:43:07] TEST 3: output chain has policy drop and allow-list configured
  output policy is drop                                        drop       drop       PASS
  output allow-list contains upstream ports                    present    present    PASS
  output logs unauthorized egress                              present    present    PASS
[18:43:07] TEST 4: nftables JSON parser writes to /var/log/ztaleaks/nftables/firewall.jsonl
  nftables JSON log file exists                                present    present    PASS
  log lines contain action field                               valid      valid      PASS
[18:43:08] TEST 5: SYN flood rate-limit rule is present in chain input
  SYN flood rule present                                       present    present    PASS
[18:43:09] TEST 6: Established connections pass (ct state established,related)
  Established connection rule                                  pass       pass       PASS

  Total: 10  PASS: 10  FAIL: 0
```
