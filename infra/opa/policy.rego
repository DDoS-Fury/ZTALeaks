# =============================================================================
# OPA Authorization Policy - ZTALeaks Zero Trust Nuclear Plant
# Package: envoy.authz
#
# Access decisions are based on four independent dimensions, all of which must
# be satisfied simultaneously:
#
#   1. Public paths    - certain routes are open without authentication
#                        (login, register, JWKS endpoint, static assets).
#
#   2. Tier admission  - the client's authentication strength determines a
#                        numeric tier (0, 1, or 2); each route declares the
#                        minimum tier required:
#                          0 = password + OTP only (no certificate)
#                          1 = mTLS client certificate present
#                          2 = mTLS certificate + TPM/WebAuthn enrolled device
#
#   3. Role            - each (path, HTTP method) pair has an allowed set of
#                        roles; the authenticated user's role must be in the set.
#
#   4. Clearance       - five-level hierarchy:
#                          PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET
#                        The user's clearance level must be >= the route's
#                        minimum clearance level.
#
# Additionally, an AI risk scoring layer (section 6) can override an otherwise
# valid decision when the risk bucket is "high".
#
# Expected input document (populated by the security-orchestrator):
# {
#   "request": {
#     "method": string,
#     "path":   string,
#     "headers": object
#   },
#   "claims": {
#     "sub":             string,
#     "role":            string,
#     "clearance_level": string,
#     "mfa_verified":    bool,
#     "device_id":       string   # optional
#   } | null,
#   "cert_present":  bool,
#   "cert_subject":  string,      # optional
#   "tpm_verified":  bool,
#   "zone_id":       string,      # optional
#   "ai": {                       # optional
#     "score":      number,       # 0.0 .. 0.99
#     "confidence": "high" | "low"
#   },
#   "context": {                  # optional
#     "hour_of_day":        number,   # 0 .. 23
#     "day_of_week":        number,   # 0 .. 6
#     "session_age_seconds": number,
#     "client_ip":          string
#   }
# }
#
# Outputs:
#   allow      : bool   - final access decision consumed by the PEP (Envoy)
#   risk_bucket: string - "low" | "medium" | "high"; used by the orchestrator
#                         for audit logging and adaptive response
#   risk_score : number - deterministic fallback score (only when confidence=low)
# =============================================================================

package envoy.authz

import rego.v1

# Default decision: deny everything unless a rule explicitly allows it.
default allow := false

# =============================================================================
# Section 1: Public Paths
# These routes are accessible without any JWT or certificate.
# =============================================================================

public_paths := {
    "/",
    "/health",
    "/login",
    "/register",
    "/materials",
    "/reserved",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/verify-otp",
    # WebAuthn login flow (begin/finish) does not require a pre-existing token.
    "/api/v1/auth/login/begin",
    "/api/v1/auth/login/finish",
    # JWKS endpoint must be public so clients can fetch the signing key.
    "/.well-known/jwks.json",
}

# Allow any path listed in public_paths
allow if {
    input.request.path in public_paths
}

# Allow all static assets (CSS, JS, images, etc.)
allow if {
    startswith(input.request.path, "/static/")
}

# =============================================================================
# Section 2: Tier Admission
#
# Tier 2: client certificate present AND TPM/WebAuthn verified
# Tier 1: client certificate present, no TPM/WebAuthn
# Tier 0: no client certificate (password + OTP authentication only)
# =============================================================================

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

# =============================================================================
# Section 3: Clearance Hierarchy
#
# Numeric mapping allows >= comparisons between clearance levels.
# =============================================================================

clearance_order := {
    "PUBLIC":     0,
    "INTERNAL":   1,
    "CONFIDENTIAL": 2,
    "SECRET":     3,
    "TOP_SECRET": 4,
}

# =============================================================================
# Section 4: Role x Route Access Matrix
#
# Structure: route_rules[path][method] = {roles, min_tier, min_clearance}
#
# Path matching supports:
#   - Exact match: input.request.path == key
#   - Prefix match: input.request.path starts with key + "/"
#     (allows sub-resources such as /api/v1/personnel/EMP-001)
# =============================================================================

route_rules := {

    # WebAuthn device enrollment - requires an authenticated session (tier 1)
    # because device binding must happen after password+OTP verification.
    "/api/v1/auth/register/begin": {
        "POST": {
            "roles": {
                "plant_manager", "operator", "maintenance_technician",
                "radiation_protection_officer", "security_officer", "inspector"
            },
            "min_tier":      1,
            "min_clearance": "PUBLIC",
        },
    },
    "/api/v1/auth/register/finish": {
        "POST": {
            "roles": {
                "plant_manager", "operator", "maintenance_technician",
                "radiation_protection_officer", "security_officer", "inspector"
            },
            "min_tier":      1,
            "min_clearance": "PUBLIC",
        },
    },

    # Personnel records
    "/api/v1/personnel": {
        "GET":    { "roles": {"security_officer", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "INTERNAL" },
        "POST":   { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "SECRET"   },
        "PUT":    { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "SECRET"   },
        "DELETE": { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "SECRET"   },
    },

    # Facility zones
    "/api/v1/zones": {
        "GET": {
            "roles": {
                "operator", "plant_manager", "inspector",
                "maintenance_technician", "radiation_protection_officer", "security_officer"
            },
            "min_tier":      0,
            "min_clearance": "PUBLIC",
        },
        "POST":   { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET" },
        "PUT":    { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET" },
        "DELETE": { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "SECRET" },
    },

    # Access badges
    "/api/v1/badges": {
        "GET":    { "roles": {"security_officer", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "INTERNAL"     },
        "POST":   { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
        "PUT":    { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
        "DELETE": { "roles": {"plant_manager"},                                  "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
    },

    # Reactor parameters
    "/api/v1/reactor-parameters": {
        "GET":    { "roles": {"operator", "plant_manager", "inspector"}, "min_tier": 1, "min_clearance": "CONFIDENTIAL" },
        "POST":   { "roles": {"plant_manager"},                          "min_tier": 2, "min_clearance": "SECRET"       },
        "PUT":    { "roles": {"plant_manager"},                          "min_tier": 2, "min_clearance": "SECRET"       },
        "DELETE": { "roles": {"plant_manager"},                          "min_tier": 2, "min_clearance": "SECRET"       },
    },

    # Maintenance work orders
    "/api/v1/maintenance-orders": {
        "GET":    { "roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"     },
        "POST":   { "roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"     },
        "PUT":    { "roles": {"maintenance_technician", "plant_manager"}, "min_tier": 1, "min_clearance": "INTERNAL"     },
        # DELETE requires a higher tier to prevent accidental or malicious removal
        "DELETE": { "roles": {"maintenance_technician", "plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
    },

    # Document repository (open to all authenticated roles at tier 0 for read)
    "/api/v1/documents": {
        "GET": {
            "roles": {
                "operator", "plant_manager", "inspector", "maintenance_technician",
                "radiation_protection_officer", "security_officer"
            },
            "min_tier":      0,
            "min_clearance": "PUBLIC",
        },
        "POST":   { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
        "PUT":    { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
        "DELETE": { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "CONFIDENTIAL" },
    },

    # Nuclear materials inventory - highest protection level
    "/api/v1/nuclear-materials": {
        "GET": {
            "roles": {"plant_manager", "inspector", "radiation_protection_officer"},
            "min_tier":      2,
            "min_clearance": "SECRET",
        },
        "POST":   { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET" },
        "PUT":    { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET" },
        "DELETE": { "roles": {"plant_manager"}, "min_tier": 2, "min_clearance": "TOP_SECRET" },
    },
}

# Resolve the route_rules key that matches the current request path.
# Exact match takes precedence; prefix match (key + "/") covers sub-resources.
matched_route := key if {
    some key, _ in route_rules
    input.request.path == key
}

matched_route := key if {
    some key, _ in route_rules
    startswith(input.request.path, concat("", [key, "/"]))
}

# =============================================================================
# Section 5: Main Allow Rule
#
# A request is allowed when:
#   a) Authentication and authorisation checks pass (authn_authz_ok), AND
#   b) The AI risk bucket is not "high".
#
# The risk_bucket guard enables the anomaly detection layer (section 6) to
# override an otherwise valid decision, implementing adaptive access control.
# =============================================================================

allow if {
    authn_authz_ok
    risk_bucket != "high"
}

# Helper: all four dimensions must pass.
authn_authz_ok if {
    # The user must be authenticated (JWT claims present)
    input.claims.sub

    # The requested route and method must exist in the matrix
    rule := route_rules[matched_route][input.request.method]

    # The user's tier must meet the route's minimum tier requirement
    user_tier >= rule.min_tier

    # The user's role must be in the route's allowed role set
    input.claims.role in rule.roles

    # The user's clearance level must meet the route's minimum clearance
    clearance_order[input.claims.clearance_level] >= clearance_order[rule.min_clearance]
}

# =============================================================================
# Section 6: AI Risk Scoring
#
# When the AI microservice is available (confidence = "high"), the risk bucket
# is determined directly from the score:
#   "low"    : score < 0.3   - no additional action
#   "medium" : 0.3 <= score < 0.7 - allow but flag for audit logging
#   "high"   : score >= 0.7  - deny override regardless of role/tier/clearance
#
# When the AI microservice is unavailable (confidence = "low"), a deterministic
# fallback score is computed from contextual signals and mapped to a bucket.
#
# When the "ai" field is absent entirely (backward compatibility with older
# tests), the default bucket "low" applies.
# =============================================================================

default risk_bucket := "low"

# High-confidence AI score ranges
risk_bucket := "low" if {
    input.ai.confidence == "high"
    input.ai.score < 0.3
}

risk_bucket := "medium" if {
    input.ai.confidence == "high"
    input.ai.score >= 0.3
    input.ai.score < 0.7
}

risk_bucket := "high" if {
    input.ai.confidence == "high"
    input.ai.score >= 0.7
}

# Low-confidence fallback: delegate to the deterministic fallback bucket
risk_bucket := bucket if {
    input.ai.confidence == "low"
    bucket := fallback_bucket
}

# =============================================================================
# Deterministic Fallback Scoring (used when AI confidence = "low")
#
# Each signal contributes a numeric penalty (0..100 total):
#   off_hours_score    : 25 pts - access outside 06:00-22:00 (non-operators)
#   missing_cert_score : 20 pts - missing certificate on a tier >= 1 route
#   stale_session_score: 15 pts - session older than 8 hours
#
# Score thresholds:
#   >= 50 -> "high"   (deny)
#   >= 25 -> "medium" (allow + audit)
#   <  25 -> "low"    (allow)
# =============================================================================

risk_score := s if {
    s := off_hours_score + missing_cert_score + stale_session_score
}

# Off-hours penalty: applies outside 06:00-22:00 for non-operator roles.
# Operators work rotating shifts and are exempt from this penalty.
default off_hours_score := 0

off_hours_score := 25 if {
    input.context.hour_of_day < 6
    input.claims.role != "operator"
}

off_hours_score := 25 if {
    input.context.hour_of_day >= 22
    input.claims.role != "operator"
}

# Missing certificate penalty: applies when a route requires tier >= 1 but
# the client has not presented a certificate.
default missing_cert_score := 0

missing_cert_score := 20 if {
    not input.cert_present
    rule := route_rules[matched_route][input.request.method]
    rule.min_tier >= 1
}

# Stale session penalty: applies when the session is older than 8 hours
# (28800 seconds), suggesting the token was not refreshed after a long absence.
default stale_session_score := 0

stale_session_score := 15 if {
    input.context.session_age_seconds > 28800
}

# Map the numeric fallback score to a risk bucket.
fallback_bucket := "high"   if { risk_score >= 50 }
fallback_bucket := "medium" if { risk_score >= 25; risk_score < 50 }
fallback_bucket := "low"    if { risk_score < 25 }

# =============================================================================
# Exported Variables for Logging
# =============================================================================
ai_score := input.ai.score
