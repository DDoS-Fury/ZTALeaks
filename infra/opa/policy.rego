package envoy.authz

import rego.v1

# =============================================================================
# OPA Policy — Zero Trust Authorization for ZTALeaks Nuclear Plant
# =============================================================================
# Decisione di accesso basata su 4 dimensioni indipendenti, tutte richieste:
#
#   1. Public path     — alcune rotte sono aperte (login, register, JWKS, etc.)
#   2. Tier admission  — certificato e/o TPM determinano il tier (0/1/2);
#                        ogni rotta dichiara il `min_tier` richiesto
#   3. Role            — ogni (path, method) ha la sua lista `roles` ammessi
#   4. Clearance       — gerarchia PUBLIC<INTERNAL<CONFIDENTIAL<SECRET<TOP_SECRET;
#                        l'utente deve ≥ `min_clearance` della rotta
#
# Input atteso (popolato da security-orchestrator):
#   {
#     "request": {"method", "path", "headers"},
#     "claims":  {"sub", "role", "clearance_level", "mfa_verified", "device_id"} | null,
#     "cert_present": bool,
#     "cert_subject": str (opt),
#     "tpm_verified": bool,
#     "zone_id": str (opt)
#   }
# =============================================================================

default allow := false

# -----------------------------------------------------------------------------
# 1. PUBLIC PATHS — accesso libero, niente JWT richiesto
# -----------------------------------------------------------------------------
public_paths := {
    "/",
    "/health",
    "/login",
    "/register",
    "/materials",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/verify-otp",
    "/api/v1/auth/register/begin",
    "/api/v1/auth/register/finish",
    "/api/v1/auth/login/begin",
    "/api/v1/auth/login/finish",
    "/.well-known/jwks.json",
}

allow if {
    input.request.path in public_paths
}

allow if {
    startswith(input.request.path, "/static/")
}

# -----------------------------------------------------------------------------
# 2. TIER ADMISSION
#    0 = né cert né TPM (login con sola password+OTP)
#    1 = solo certificato client (mTLS riconosciuto)
#    2 = certificato + TPM/WebAuthn enrollato
# -----------------------------------------------------------------------------
user_tier := 2 if {
    input.cert_present
    input.tpm_verified
}

user_tier := 1 if {
    input.cert_present
    not input.tpm_verified
}

user_tier := 0 if {
    not input.cert_present
}

# -----------------------------------------------------------------------------
# 3. CLEARANCE HIERARCHY
# -----------------------------------------------------------------------------
clearance_order := {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP_SECRET": 4,
}

# -----------------------------------------------------------------------------
# 4. ROLE × ROUTE MATRIX
#    Per ogni (path, method): {roles, min_tier, min_clearance}.
#    Path matching: esatto, oppure prefisso "{path}/" (es. /personnel/EMP-001).
# -----------------------------------------------------------------------------
route_rules := {
    "/api/v1/personnel": {
        "GET":    {"roles": {"security_officer", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "INTERNAL"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
    },
    "/api/v1/zones": {
        "GET":    {"roles": {"operator", "plant_manager", "inspector", "maintenance_technician", "radiation_protection_officer", "security_officer"}, "min_tier": 0, "min_clearance": "PUBLIC"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
    },
    "/api/v1/badges": {
        "GET":    {"roles": {"security_officer", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "INTERNAL"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
    },
    "/api/v1/reactor-parameters": {
        "GET":    {"roles": {"operator", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "CONFIDENTIAL"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET"},
    },
    "/api/v1/maintenance-orders": {
        "GET":    {"roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"},
        "POST":   {"roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"},
        "PUT":    {"roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"},
        "DELETE": {"roles": {"maintenance_technician", "plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
    },
    "/api/v1/documents": {
        "GET":    {"roles": {"operator", "plant_manager", "inspector", "maintenance_technician", "radiation_protection_officer", "security_officer"}, "min_tier": 0, "min_clearance": "PUBLIC"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL"},
    },
    "/api/v1/nuclear-materials": {
        "GET":    {"roles": {"plant_manager", "inspector", "radiation_protection_officer"}, "min_tier": 2, "min_clearance": "SECRET"},
        "POST":   {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET"},
        "PUT":    {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET"},
        "DELETE": {"roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET"},
    },
}

# matched_route trova la voce di route_rules che matcha input.request.path:
# match esatto OPPURE prefisso "{key}/" (consente subpath /{id}).
matched_route := key if {
    some key, _ in route_rules
    input.request.path == key
}

matched_route := key if {
    some key, _ in route_rules
    startswith(input.request.path, concat("", [key, "/"]))
}

# -----------------------------------------------------------------------------
# 5. ALLOW principale: richiede claims, tier, role e clearance sufficienti.
# -----------------------------------------------------------------------------
allow if {
    # Claims presenti (utente autenticato)
    input.claims.sub

    # Match della rotta nella matrix
    rule := route_rules[matched_route][input.request.method]

    # Tier admission
    user_tier >= rule.min_tier

    # Role
    input.claims.role in rule.roles

    # Clearance
    clearance_order[input.claims.clearance_level] >= clearance_order[rule.min_clearance]
}
