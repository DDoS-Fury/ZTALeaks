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
