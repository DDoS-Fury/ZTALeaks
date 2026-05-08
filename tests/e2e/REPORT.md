# ZTALeaks — E2E Validation Report (auto-generated)

**Generated**: 2026-05-08T23:30:53Z
**Stack endpoint**: `https://127.0.0.1:8443`
**Source**: `tests/e2e/run_all.sh` su 5 pillar.

Questo file viene rigenerato a ogni esecuzione.

---

## Summary

| # | Pillar | Status |
|---|---|---|
| 1 | Authentication Flow (login + 2FA) | ✅ PASS |
| 2 | Policy Enforcement Point (Envoy + ext_authz) | ✅ PASS |
| 3 | Role-Based Access Control (OPA) | ✅ PASS |
| 4 | Attribute-Based Access (clearance hierarchy) | ✅ PASS |
| 5 | 3-Tier Admission (cert × TPM) | ✅ PASS |

**Outcome**: tutti i 5 pillar PASS.

---

## Per-pillar output

### Authentication Flow

- **Script**: `tests/e2e/auth.sh`
- **Status**: PASS

```
[01:30:34] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[01:30:35] Auth pillar — admin login flow + claims

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  admin login → JWT issued                                   yes        yes        PASS
  JWT.sub non vuoto                                            yes        yes        PASS
  JWT.role == plant_manager                                    plant_manager plant_manager PASS
  JWT.clearance == TOP_SECRET                                  TOP_SECRET TOP_SECRET PASS
  JWT.mfa_verified == True                                     True       True       PASS
  JWT.iss == identity service                                  identity-service.ztaleaks.local identity-service.ztaleaks.local PASS
[01:30:37] Negative scenario: OTP errato
  verify-otp con OTP errato → 401                            401        401        PASS
  login con password errata → 401                            401        401        PASS

  Total: 8  PASS: 8  FAIL: 0
```

### PEP

- **Script**: `tests/e2e/pep.sh`
- **Status**: PASS

```
[01:30:37] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[01:30:37] PEP pillar — public bypass + protect by default

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  /api/v1/auth/login (public) → non 403                      ok         ok         PASS
  /.well-known/jwks.json (public) → 200                      200        200        PASS
  GET /personnel senza JWT → 403                             403        403        PASS
  GET /nuclear-materials no-JWT (con cert) → 403             403        403        PASS
  GET /personnel con JWT garbage → 401                       401        401        PASS

  Total: 5  PASS: 5  FAIL: 0
```

### RBAC

- **Script**: `tests/e2e/rbac.sh`
- **Status**: PASS

```
[01:30:37] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[01:30:37] RBAC pillar — role × resource matrix (OPA)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✓ operator1 JWT obtained
  ✓ maint_tech1 JWT obtained
  operator + cert → /reactor-parameters GET                  200        200        PASS
  operator → /nuclear-materials GET (role denied)            403        403        PASS
  operator → /maintenance-orders POST (role denied)          403        403        PASS
  maint_tech1 + cert → /maintenance-orders POST (PDP allow)  yes        yes        PASS

  Total: 4  PASS: 4  FAIL: 0
```

### ABAC

- **Script**: `tests/e2e/abac.sh`
- **Status**: PASS

```
[01:30:40] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[01:30:40] ABAC pillar — clearance vs resource

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  ✓ insp_e2e_low (CONFIDENTIAL) JWT obtained
  ✓ inspector1 (SECRET) JWT obtained
  ✓ pm_e2e_low (plant_manager, INTERNAL) JWT obtained
  plant_manager INTERNAL → /nuclear-materials POST (clearance underflow) 403        403        PASS
  admin TOP_SECRET cert+tpm → /nuclear-materials POST (PDP allow) yes        yes        PASS
  inspector CONFIDENTIAL → /personnel GET (clearance ≥ INTERNAL) 200        200        PASS
  inspector → /personnel POST (role only plant_manager)      403        403        PASS

  Total: 4  PASS: 4  FAIL: 0
```

### Tier admission

- **Script**: `tests/e2e/tier.sh`
- **Status**: PASS

```
[01:30:49] Waiting for stack readiness
  ✓ Envoy reachable (https://127.0.0.1:8443)
  ✓ MailHog reachable (http://127.0.0.1:8025)
[01:30:49] Tier admission pillar — cert × tpm (utente fresh per isolare TPM)

  Scenario                                                     Expected   Actual     Result
  ------------------------------------------------------------------------------------------
  tier_pm no-cert → /personnel GET (tier 0 < 1)              403        403        PASS
  tier_pm cert → /personnel GET (tier 1 ≥ 1)               200        200        PASS
  tier_pm cert no-TPM → /nuclear POST (tier 1 < 2)           403        403        PASS
  tier_pm cert+TPM → /nuclear POST (tier 2 ≥ 2)            yes        yes        PASS
  tier_pm TPM ma no-cert → /nuclear POST (tier 0 < 2)        403        403        PASS

  Total: 5  PASS: 5  FAIL: 0
```
