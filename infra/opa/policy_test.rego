package envoy.authz_test

import rego.v1
import data.envoy.authz

# =============================================================================
# OPA Policy Tests — copertura tier × clearance × role × route
# =============================================================================
# Esecuzione:
#   docker run --rm -v $PWD:/workspace openpolicyagent/opa test /workspace/infra/opa -v
# =============================================================================

# --- Helpers ----------------------------------------------------------------

plant_manager_top_secret := {
    "sub": "EMP-001",
    "role": "plant_manager",
    "clearance_level": "TOP_SECRET",
    "mfa_verified": true,
    "device_id": "dev-1",
}

plant_manager_internal := {
    "sub": "EMP-001",
    "role": "plant_manager",
    "clearance_level": "INTERNAL",
    "mfa_verified": true,
}

operator_confidential := {
    "sub": "EMP-002",
    "role": "operator",
    "clearance_level": "CONFIDENTIAL",
    "mfa_verified": true,
}

inspector_secret := {
    "sub": "EMP-006",
    "role": "inspector",
    "clearance_level": "SECRET",
    "mfa_verified": true,
}

maint_internal := {
    "sub": "EMP-003",
    "role": "maintenance_technician",
    "clearance_level": "INTERNAL",
    "mfa_verified": true,
}

# --- Public path tests ------------------------------------------------------

test_public_login_no_auth if {
    authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/auth/login"},
        "claims": null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

test_public_jwks_no_auth if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/.well-known/jwks.json"},
        "claims": null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

test_public_static_asset if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/static/css/styles.css"},
        "claims": null,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# --- Tier admission tests ---------------------------------------------------

# Tier 2 (cert+TPM): plant_manager TOP_SECRET può scrivere nuclear-materials
test_allow_tier2_plant_manager_nuclear_create if {
    authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims": plant_manager_top_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# Stesso utente senza cert → DENY (tier=0 < min_tier=2)
test_deny_no_cert_blocks_nuclear_write if {
    not authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims": plant_manager_top_secret,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# Cert ma niente TPM → tier=1 < 2 → DENY
test_deny_cert_only_blocks_nuclear_write if {
    not authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims": plant_manager_top_secret,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# --- Clearance tests --------------------------------------------------------

# plant_manager INTERNAL prova a creare nuclear-material (richiede TOP_SECRET)
test_deny_insufficient_clearance if {
    not authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims": plant_manager_internal,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# --- Role tests -------------------------------------------------------------

# operator CONFIDENTIAL legge reactor-parameters → ALLOW (role+tier1+CONFIDENTIAL)
test_allow_operator_reactor_get if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims": operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# operator non è nella lista nuclear-materials → DENY
test_deny_operator_nuclear_get if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims": operator_confidential,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# --- Path matching tests ----------------------------------------------------

# inspector SECRET legge personnel/EMP-001 (path con suffisso)
test_allow_path_with_subresource if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel/EMP-001"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# --- Maintenance tier-1 tests -----------------------------------------------

test_allow_maint_creates_order_with_cert if {
    authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/maintenance-orders"},
        "claims": maint_internal,
        "cert_present": true,
        "tpm_verified": false,
    }
}

test_deny_maint_creates_order_without_cert if {
    not authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/maintenance-orders"},
        "claims": maint_internal,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# DELETE su maintenance-orders richiede tier 2 anche per maintenance_technician
test_deny_maint_delete_without_tpm if {
    not authz.allow with input as {
        "request": {"method": "DELETE", "path": "/api/v1/maintenance-orders/MO-123"},
        "claims": maint_internal,
        "cert_present": true,
        "tpm_verified": false,
    }
}

# --- Tier-0 tests -----------------------------------------------------------

# zones GET è tier 0 → utente "senza niente" può accederlo
test_allow_zones_get_tier0 if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/zones"},
        "claims": operator_confidential,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# documents GET è aperto a tutti i ruoli a tier 0
test_allow_documents_get_no_cert if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/documents"},
        "claims": maint_internal,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# --- Negative tests ---------------------------------------------------------

# Nessun claim (no JWT) su rotta protetta → DENY
test_deny_no_claims_protected_path if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": null,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# --- Anomalie e attributi non conformi -----------------------------------

# Ruolo non valido / non autorizzato (operator su nuclear-materials)
test_deny_unauthorized_role_nuclear_materials if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims": operator_confidential,
        "cert_present": true,
        "tpm_verified": true,
    }
}

# Clearance insufficiente (CONFIDENTIAL vs SECRET richiesto)
test_deny_insufficient_clearance_nuclear if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/nuclear-materials"},
        "claims": {
            "sub": "EMP-999",
            "role": "plant_manager",
            "clearance_level": "CONFIDENTIAL",
            "mfa_verified": true,
        },
        "cert_present": true,
        "tpm_verified": true,
    }
}

# Tier insufficiente (no cert/tpm su rotta che richiede tier 2)
test_deny_low_tier_on_tier2_route if {
    not authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/nuclear-materials"},
        "claims": plant_manager_top_secret,
        "cert_present": false,
        "tpm_verified": false,
    }
}

# =============================================================================
# AI RISK SCORING TESTS — sezione 6 di policy.rego
# =============================================================================

# --- AI ad alta confidenza: fasce ------------------------------------------

# Score basso (<0.3) → bucket "low", utente normalmente autorizzato → allow.
test_allow_low_ai_score if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.1, "confidence": "high"},
    }
    authz.risk_bucket == "low" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.1, "confidence": "high"},
    }
}

# Score medio (0.3..0.7) → bucket "medium", allow ma audit.
test_allow_medium_ai_score_with_audit if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.5, "confidence": "high"},
    }
    authz.risk_bucket == "medium" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.5, "confidence": "high"},
    }
}

# Score alto (≥0.7) → bucket "high" → deny anche se role/tier/clearance OK.
test_deny_high_ai_score_override if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.85, "confidence": "high"},
    }
    authz.risk_bucket == "high" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0.85, "confidence": "high"},
    }
}

# Public path: anche con AI score alto deve restare aperta.
test_public_path_not_blocked_by_high_ai if {
    authz.allow with input as {
        "request": {"method": "POST", "path": "/api/v1/auth/login"},
        "claims": null,
        "cert_present": false,
        "tpm_verified": false,
        "ai": {"score": 0.95, "confidence": "high"},
    }
}

# --- AI low confidence: fallback deterministico ----------------------------

# Off-hours (ora 02:00) + niente cert su rotta tier>=1 → fallback bucket "high" → deny.
# Punteggio: off_hours(25) + missing_cert(20) = 45 → "medium"? Hmm rivedere.
# Aggiungo session vecchia per arrivare a 60 → "high".
test_deny_fallback_offhours_no_cert_stale if {
    not authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": false,
        "tpm_verified": false,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 2,
            "day_of_week": 3,
            "session_age_seconds": 30000,
            "client_ip": "10.0.0.1",
        },
    }
}

# Off-hours da solo (25) → bucket "medium" → allow (se richiesta altrimenti OK).
test_allow_fallback_offhours_only_medium_bucket if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 23,
            "day_of_week": 5,
            "session_age_seconds": 100,
            "client_ip": "10.0.0.1",
        },
    }
    authz.risk_bucket == "medium" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 23,
            "day_of_week": 5,
            "session_age_seconds": 100,
            "client_ip": "10.0.0.1",
        },
    }
}

# Contesto benigno (ora 10, sessione fresca, cert ok) → bucket "low" → allow.
test_allow_fallback_benign_context if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 10,
            "day_of_week": 2,
            "session_age_seconds": 600,
            "client_ip": "10.0.0.1",
        },
    }
    authz.risk_bucket == "low" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 10,
            "day_of_week": 2,
            "session_age_seconds": 600,
            "client_ip": "10.0.0.1",
        },
    }
}

# Operator off-hours: turnista, off_hours non si applica → score 0 → "low" → allow.
test_allow_fallback_operator_offhours_exempt if {
    authz.allow with input as {
        "request": {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims": operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 3,
            "day_of_week": 1,
            "session_age_seconds": 200,
            "client_ip": "10.0.0.5",
        },
    }
    authz.risk_bucket == "low" with input as {
        "request": {"method": "GET", "path": "/api/v1/reactor-parameters"},
        "claims": operator_confidential,
        "cert_present": true,
        "tpm_verified": false,
        "ai": {"score": 0, "confidence": "low"},
        "context": {
            "hour_of_day": 3,
            "day_of_week": 1,
            "session_age_seconds": 200,
            "client_ip": "10.0.0.5",
        },
    }
}

# --- Retrocompatibilità ----------------------------------------------------

# Input senza `ai` né `context` (i 22 test storici) → bucket default "low" → allow.
test_backward_compat_no_ai_no_context if {
    authz.risk_bucket == "low" with input as {
        "request": {"method": "GET", "path": "/api/v1/personnel"},
        "claims": inspector_secret,
        "cert_present": true,
        "tpm_verified": true,
    }
}
