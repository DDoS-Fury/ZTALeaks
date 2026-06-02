# =============================================================================
# OPA Policy Test Suite - ZTALeaks
# Package: envoy.authz_test
#
# Covers the following test categories:
#   1. Public paths (no authentication required)
#   2. Tier admission (cert/TPM combinations)
#   3. Clearance enforcement
#   4. Role enforcement
#   5. Path matching (exact and sub-resource prefix)
#   6. Maintenance technician tier rules
#   7. Tier-0 accessible routes
#   8. Negative / anomaly cases
#   9. AI risk scoring (high-confidence score bands)
#  10. AI low-confidence deterministic fallback
#  11. Backward compatibility (no "ai" or "context" fields in input)
#
# Run with:
#   docker run --rm -v $PWD:/workspace openpolicyagent/opa \
#       test /workspace/infra/opa -v
# =============================================================================

package envoy.authz_test

import rego.v1
import data.envoy.authz

# =============================================================================
# Test fixtures - reusable identity claim sets
# =============================================================================

plant_manager_top_secret := {
    "sub":             "EMP-001",
    "role":            "plant_manager",
    "clearance_level": "TOP_SECRET",
    "mfa_verified":    true,
    "device_id":       "dev-1",
}

plant_manager_internal := {
    "sub":             "EMP-001",
    "role":            "plant_manager",
    "clearance_level": "INTERNAL",
    "mfa_verified":    true,
}

operator_confidential := {
    "sub":             "EMP-002",
    "role":            "operator",
    "clearance_level": "CONFIDENTIAL",
    "mfa_verified":    true,
}

inspector_secret := {
    "sub":             "EMP-006",
    "role":            "inspector",
    "clearance_level": "SECRET",
    "mfa_verified":    true,
}

maint_internal := {
    "sub":             "EMP-003",
    "role":            "maintenance_technician",
    "clearance_level": "INTERNAL",
    "mfa_verified":    true,
}

# =============================================================================
# Section 1: Public path tests
# =============================================================================

# The login endpoint must be accessible without any credentials.
test_public_login_no_auth if {
    authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/auth/login"},
        "claims":       null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# The JWKS discovery endpoint must be publicly accessible.
test_public_jwks_no_auth if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/.well-known/jwks.json"},
        "claims":       null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# Static assets must be accessible without authentication.
test_public_static_asset if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/static/css/styles.css"},
        "claims":       null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# =============================================================================
# Section 2: Tier admission tests
# =============================================================================

# Tier 2 (cert + TPM): plant_manager with TOP_SECRET clearance may create
# nuclear material records.
test_allow_tier2_plant_manager_nuclear_create if {
    authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims":       plant_manager_top_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# Same user without a certificate -> tier 0 < min_tier 2 -> DENY.
test_deny_no_cert_blocks_nuclear_write if {
    not authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims":       plant_manager_top_secret,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# Certificate present but no TPM -> tier 1 < min_tier 2 -> DENY.
test_deny_cert_only_blocks_nuclear_write if {
    not authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims":       plant_manager_top_secret,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# =============================================================================
# Section 3: Clearance tests
# =============================================================================

# plant_manager with INTERNAL clearance attempts to create a nuclear material
# record that requires TOP_SECRET -> DENY.
test_deny_insufficient_clearance if {
    not authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims":       plant_manager_internal,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# =============================================================================
# Section 4: Role tests
# =============================================================================

# operator with CONFIDENTIAL clearance reading reactor parameters -> ALLOW.
# Route requires tier 1 (cert only) and CONFIDENTIAL clearance.
test_allow_operator_reactor_get if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims":       operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# operator role is not in the allowed set for nuclear-materials -> DENY.
test_deny_operator_nuclear_get if {
    not authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims":       operator_confidential,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# =============================================================================
# Section 5: Path matching tests
# =============================================================================

# inspector with SECRET clearance reads /api/v1/personnel/EMP-001
# (sub-resource path with a suffix) -> ALLOW via prefix matching.
test_allow_path_with_subresource if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel/EMP-001"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# =============================================================================
# Section 6: Maintenance technician tier-1 tests
# =============================================================================

# maintenance_technician creates a work order with a certificate -> ALLOW
# (route requires tier 1).
test_allow_maint_creates_order_with_cert if {
    authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/maintenance-orders"},
        "claims":       maint_internal,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# Same operation without a certificate -> DENY (tier 0 < min_tier 1).
test_deny_maint_creates_order_without_cert if {
    not authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/maintenance-orders"},
        "claims":       maint_internal,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# DELETE on maintenance-orders requires tier 2 even for maintenance_technician.
test_deny_maint_delete_without_tpm if {
    not authz.allow with input as {
        "request":      {"method": "DELETE", "path": "/api/v1/maintenance-orders/MO-123"},
        "claims":       maint_internal,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# =============================================================================
# Section 7: Tier-0 accessible route tests
# =============================================================================

# GET /api/v1/zones requires tier 0; any authenticated user may access it
# without a certificate.
test_allow_zones_get_tier0 if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/zones"},
        "claims":       operator_confidential,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# GET /api/v1/documents is open to all roles at tier 0.
test_allow_documents_get_no_cert if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/documents"},
        "claims":       maint_internal,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# =============================================================================
# Section 8: Negative / anomaly tests
# =============================================================================

# No JWT claims on a protected route -> DENY.
test_deny_no_claims_protected_path if {
    not authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       null,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# operator role is not authorized for nuclear-materials -> DENY.
test_deny_unauthorized_role_nuclear_materials if {
    not authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims":       operator_confidential,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# plant_manager with CONFIDENTIAL clearance attempts to read nuclear-materials
# (requires SECRET) -> DENY.
test_deny_insufficient_clearance_nuclear if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims": {
            "sub":             "EMP-999",
            "role":            "plant_manager",
            "clearance_level": "CONFIDENTIAL",
            "mfa_verified":    true,
        },
        "cert_present": true,
        "tpm_verified": true,
    }
}

# Insufficient tier (no cert/TPM) on a route that requires tier 2 -> DENY.
test_deny_low_tier_on_tier2_route if {
    not authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims":       plant_manager_top_secret,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# =============================================================================
# Section 9: AI risk scoring tests (high-confidence score bands)
# =============================================================================

# Low score (< 0.3) -> bucket "low"; otherwise authorized request -> ALLOW.
test_allow_low_ai_score if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.1, "confidence": "high"},
    }
    authz.risk_bucket == "low" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.1, "confidence": "high"},
    }
}

# Medium score (0.3 <= score < 0.7) -> bucket "medium"; request is allowed
# but flagged for audit logging.
test_allow_medium_ai_score_with_audit if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.5, "confidence": "high"},
    }
    authz.risk_bucket == "medium" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.5, "confidence": "high"},
    }
}

# High score (>= 0.7) -> bucket "high" -> DENY override even if role/tier/
# clearance would otherwise permit the request.
test_deny_high_ai_score_override if {
    not authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.85, "confidence": "high"},
    }
    authz.risk_bucket == "high" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0.85, "confidence": "high"},
    }
}

# Public paths must remain open even when the AI score is very high.
test_public_path_not_blocked_by_high_ai if {
    authz.allow with input as {
        "request":      {"method": "POST", "path": "/api/v1/auth/login"},
        "claims":       null,
        "cert_present": false,
        "tpm_verified": false,
        "ai":           {"score": 0.95, "confidence": "high"},
    }
}

# =============================================================================
# Section 10: AI low-confidence deterministic fallback tests
# =============================================================================

# Off-hours (02:00) + no certificate + stale session (>8h) -> combined score
# exceeds 50 -> bucket "high" -> DENY.
# Score breakdown: off_hours(25) + missing_cert(20) + stale_session(15) = 60.
test_deny_fallback_offhours_no_cert_stale if {
    not authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": false,
        "tpm_verified": false,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         2,
            "day_of_week":         3,
            "session_age_seconds": 30000,
            "client_ip":           "10.0.0.1",
        },
    }
}

# Off-hours alone (score = 25) -> bucket "medium" -> ALLOW (cert present,
# request is otherwise legitimate).
test_allow_fallback_offhours_only_medium_bucket if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         23,
            "day_of_week":         5,
            "session_age_seconds": 100,
            "client_ip":           "10.0.0.1",
        },
    }
    authz.risk_bucket == "medium" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         23,
            "day_of_week":         5,
            "session_age_seconds": 100,
            "client_ip":           "10.0.0.1",
        },
    }
}

# Benign context (business hours, fresh session, cert present) -> score 0
# -> bucket "low" -> ALLOW.
test_allow_fallback_benign_context if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         10,
            "day_of_week":         2,
            "session_age_seconds": 600,
            "client_ip":           "10.0.0.1",
        },
    }
    authz.risk_bucket == "low" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         10,
            "day_of_week":         2,
            "session_age_seconds": 600,
            "client_ip":           "10.0.0.1",
        },
    }
}

# Operator role at off-hours is exempt from the off_hours_score penalty
# (operators work rotating shifts). Score = 0 -> bucket "low" -> ALLOW.
test_allow_fallback_operator_offhours_exempt if {
    authz.allow with input as {
        "request":      {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims":       operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         3,
            "day_of_week":         1,
            "session_age_seconds": 200,
            "client_ip":           "10.0.0.5",
        },
    }
    authz.risk_bucket == "low" with input as {
        "request":      {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims":       operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
        "ai":           {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day":         3,
            "day_of_week":         1,
            "session_age_seconds": 200,
            "client_ip":           "10.0.0.5",
        },
    }
}

# =============================================================================
# Section 11: Backward compatibility
# =============================================================================

# Input without "ai" or "context" fields (legacy test format) must produce
# the default risk bucket "low" and not cause evaluation errors.
test_backward_compat_no_ai_no_context if {
    authz.risk_bucket == "low" with input as {
        "request":      {"method": "GET", "path": "/api/v1/personnel"},
        "claims":       inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}
