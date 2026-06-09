# =============================================================================
# OPA Policy Test Suite - ZTALeaks (modello ruoli: guest/operator/manager/admin)
#
# Copre:
#   1. Rotte tecniche e public paths (con gate sull'AI score)
#   2. Asset statici
#   3. Matrice RBAC per rotta/metodo
#   4. Risoluzione sottorotte (longest-prefix)
#   5. Rischio vs impatto (soglie AI per rotta)
#   6. Enrollment WebAuthn (register/begin|finish)
#
# Run:
#   docker run --rm -v $PWD/infra/opa:/policy openpolicyagent/opa test /policy -v
# =============================================================================

package envoy.authz_test

import rego.v1
import data.envoy.authz

# Helper: input minimo con score AI
req(path, method, role, score) := {
    "request": {"path": path, "method": method},
    "role": role,
    "ai": {"score": score},
}

# -----------------------------------------------------------------------------
# 1. Rotte tecniche e public paths
# -----------------------------------------------------------------------------

test_allow_health_always if {
    authz.allow with input as {"request": {"path": "/health", "method": "GET"}}
}

test_allow_jwks_always if {
    authz.allow with input as {"request": {"path": "/.well-known/jwks.json", "method": "GET"}}
}

test_allow_public_root_low_score if {
    authz.allow with input as req("/", "GET", "guest", 0.1)
}

test_allow_public_login_no_role if {
    authz.allow with input as {
        "request": {"path": "/api/v1/auth/login", "method": "POST"},
        "ai": {"score": 0.1},
    }
}

test_deny_public_path_extreme_score if {
    not authz.allow with input as req("/materials", "GET", "guest", 0.9)
}

# -----------------------------------------------------------------------------
# 2. Asset statici
# -----------------------------------------------------------------------------

test_allow_static_assets if {
    authz.allow with input as {"request": {"path": "/static/css/styles.css", "method": "GET"}}
}

# -----------------------------------------------------------------------------
# 3. Matrice RBAC
# -----------------------------------------------------------------------------

test_allow_operator_get_personnel if {
    authz.allow with input as req("/api/v1/personnel", "GET", "operator", 0.0)
}

test_deny_guest_get_personnel if {
    not authz.allow with input as req("/api/v1/personnel", "GET", "guest", 0.0)
}

test_deny_operator_get_documents if {
    not authz.allow with input as req("/api/v1/documents", "GET", "operator", 0.0)
}

test_allow_manager_delete_documents if {
    authz.allow with input as req("/api/v1/documents/DOC-1", "DELETE", "manager", 0.0)
}

test_deny_manager_get_reactor_parameters if {
    not authz.allow with input as req("/api/v1/reactor-parameters", "GET", "manager", 0.0)
}

test_allow_admin_get_reactor_parameters if {
    authz.allow with input as req("/api/v1/reactor-parameters", "GET", "admin", 0.0)
}

test_allow_manager_get_nuclear_materials if {
    authz.allow with input as req("/api/v1/nuclear-materials", "GET", "manager", 0.0)
}

test_deny_operator_post_nuclear_materials if {
    not authz.allow with input as req("/api/v1/nuclear-materials", "POST", "operator", 0.0)
}

test_allow_admin_trusted_guard if {
    authz.allow with input as req("/api/v1/trusted-guard/sanitized-delete-personnel/EMP-7", "POST", "admin", 0.0)
}

test_deny_manager_trusted_guard if {
    not authz.allow with input as req("/api/v1/trusted-guard/sanitized-delete-personnel/EMP-7", "POST", "manager", 0.0)
}

# -----------------------------------------------------------------------------
# 4. Risoluzione sottorotte (longest-prefix)
# -----------------------------------------------------------------------------

test_allow_subroute_personnel_id if {
    authz.allow with input as req("/api/v1/personnel/EMP-001", "GET", "operator", 0.0)
}

test_trusted_guard_wins_longest_prefix if {
    # /api/v1/trusted-guard/... NON deve risolversi su una rotta più corta
    not authz.allow with input as req("/api/v1/trusted-guard/sanitized-delete-personnel/EMP-7", "POST", "operator", 0.0)
}

# -----------------------------------------------------------------------------
# 5. Rischio vs impatto
# -----------------------------------------------------------------------------

# personnel GET: impatto 0.4, rischio 0.5 → allow se score < 0.9
test_allow_personnel_score_under_band if {
    authz.allow with input as req("/api/v1/personnel", "GET", "operator", 0.89)
}

test_deny_personnel_score_over_band if {
    not authz.allow with input as req("/api/v1/personnel", "GET", "operator", 0.91)
}

# reactor-parameters GET: impatto 0.15, rischio 0.2 → allow se score < 0.35
test_deny_reactor_parameters_moderate_score if {
    not authz.allow with input as req("/api/v1/reactor-parameters", "GET", "admin", 0.4)
}

test_allow_reactor_parameters_low_score if {
    authz.allow with input as req("/api/v1/reactor-parameters", "GET", "admin", 0.3)
}

# -----------------------------------------------------------------------------
# 6. Enrollment WebAuthn
# -----------------------------------------------------------------------------

test_allow_operator_webauthn_begin if {
    authz.allow with input as req("/api/v1/auth/register/begin", "POST", "operator", 0.0)
}

test_allow_admin_webauthn_finish if {
    authz.allow with input as req("/api/v1/auth/register/finish", "POST", "admin", 0.0)
}

test_deny_guest_webauthn_begin if {
    not authz.allow with input as req("/api/v1/auth/register/begin", "POST", "guest", 0.0)
}

# Default deny: rotta sconosciuta
test_deny_unknown_route if {
    not authz.allow with input as req("/api/v1/unknown", "GET", "admin", 0.0)
}
