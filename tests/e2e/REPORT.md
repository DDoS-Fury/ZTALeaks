# ZTALeaks — E2E Validation Report (auto-generated)

**Generated**: 2026-06-25T10:37:31Z
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
| 6 | Firewall (nftables rate-limiting + egress) | ❌ FAIL |

**Outcome**: almeno un pillar è FAIL.

---

## Per-pillar output

### Authentication Flow

- **Script**: `tests/e2e/auth.sh`
- **Status**: FAIL

```
[12:37:29] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:29] Auth pillar — admin login flow + claims

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  admin login → JWT issued                                   yes        no         FAIL
[12:37:29] Negative scenario: OTP errato
  verify-otp con OTP errato → 401                            401        400        FAIL
  login con password errata → 401                            401        403        FAIL

  Total: 3  PASS: 0  FAIL: 3
```

### PEP

- **Script**: `tests/e2e/pep.sh`
- **Status**: FAIL

```
[12:37:29] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:30] PEP pillar — public bypass + protect by default

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
[12:37:30] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:30] RBAC pillar — role × resource matrix (OPA)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT operator1
```

### ABAC

- **Script**: `tests/e2e/abac.sh`
- **Status**: FAIL

```
[12:37:30] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:31] ABAC pillar — clearance vs resource

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT insp_e2e_low
```

### Tier admission

- **Script**: `tests/e2e/tier.sh`
- **Status**: FAIL

```
[12:37:31] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:31] Tier admission pillar — cert × tpm (utente fresh per isolare TPM)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✗ impossibile ottenere JWT tier_pm_8hue1q
```

### Firewall (nftables)

- **Script**: `tests/e2e/nftables.sh`
- **Status**: FAIL

```
[12:37:31] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[12:37:31] Firewall pillar — nftables rate-limiting + egress filtering

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
[12:37:31] TEST 1: Normal traffic to Envoy (chain input accept)
  Normal traffic to Envoy                                      allowed    allowed    PASS
[12:37:31] TEST 2: blocked_ips set is loaded with expected elements
  blocked_ips contains 10.99.99.99                             present    missing    FAIL
  blocked_ips contains 172.18.0.10                             present    missing    FAIL
[12:37:31] TEST 3: output chain has policy drop and allow-list configured
  output policy is drop                                        drop       drop       PASS
  output allow-list contains upstream ports                    present    present    PASS
  output logs unauthorized egress                              present    present    PASS
[12:37:31] TEST 4: nftables JSON parser writes to /var/log/ztaleaks/nftables/firewall.jsonl
  nftables JSON log file exists                                present    present    PASS
  log lines contain action field                               valid      valid      PASS
[12:37:31] TEST 5: SYN flood rate-limit rule is present in chain input
  SYN flood rule present                                       present    present    PASS
[12:37:31] TEST 6: Established connections pass (ct state established,related)
  Established connection rule                                  pass       pass       PASS

  Total: 10  PASS: 8  FAIL: 2
```
