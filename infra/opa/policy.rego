package envoy.authz

import rego.v1

# Default decision: deny everything unless a rule explicitly allows it.
default allow := false

# ==================================================
# Section 1 : Public Routes
# ==================================================

# Rotte tecniche: passano SEMPRE e a prescindere dall'AI
allow if {
    input.request.path in {"/health", "/.well-known/jwks.json", "/api/v1/evaluate/favicon.ico", "/favicon.ico"}
}

public_paths := {
    "/",
    "/login",
    "/register",
    "/materials",
    "/reserved",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/verify-otp",
    "/api/v1/auth/login/begin",
    "/api/v1/auth/login/finish",
}

public_paths_impact := 0.2

allow if {
    input.request.path in public_paths
    ai_score := object.get(input, ["ai", "score"], 0.0)
    (input.ai.score - public_paths_impact) < 0.6
}

# Allow all static assets (CSS, JS, images, etc.)
allow if {
    startswith(input.request.path, "/static/")
}

# ==================================================
# Section 2 : Roles-Gain Nested Matrix [rotta][metodo]
# ==================================================

matrice_sicurezza := {
    "/api/v1/personnel": {
        "POST": {
            "impatto": 0.3,
            "ruoli_ammessi": ["operator", "manager","admin"],
            "rischio_accettato": 0.5
        },
        "GET": {
            "impatto": 0.4,
            "ruoli_ammessi": ["operator", "manager","admin"],
            "rischio_accettato": 0.5
        }
    },
    "/api/v1/documents": {
        "GET": {
            "impatto": 0.4,
            "ruoli_ammessi": [ "manager","admin"],
            "rischio_accettato": 0.5
        },
        "POST": {
            "impatto": 0.3,
            "ruoli_ammessi": [ "manager","admin"],
            "rischio_accettato": 0.5
        },
        "DELETE": {
            "impatto": 0.3,
            "ruoli_ammessi": [ "manager","admin"],
            "rischio_accettato": 0.5
        }
    },
     "/api/v1/nuclear-materials": {
        "GET": {
            "impatto": 0.2,
            "ruoli_ammessi": ["manager","admin"],
            "rischio_accettato": 0.4
        },
        "POST": {
            "impatto": 0.2,  
            "ruoli_ammessi": ["manager","admin"],
            "rischio_accettato": 0.4
        },
        "DELETE": {
            "impatto": 0.2,
            "ruoli_ammessi": ["manager","admin"],
            "rischio_accettato": 0.4
        }
    },
    "/api/v1/reactor-parameters": {
        "GET": {
            "impatto": 0.15,
            "ruoli_ammessi": ["admin"],
            "rischio_accettato": 0.2
        },
        "POST": {
            "impatto": 0.15,
            "ruoli_ammessi": ["admin"],
            "rischio_accettato": 0.2
        },
        "DELETE": {
            "impatto": 0.15,
            "ruoli_ammessi": ["admin"],
            "rischio_accettato": 0.2
        }
    },
    "/api/v1/trusted-guard/sanitized-delete-personnel": {
        "POST": {
            "impatto": 0.4,
            "ruoli_ammessi": ["admin"],
            "rischio_accettato": 0.2
        }
    },
    # Enrollment WebAuthn: richiede utente autenticato (qualsiasi ruolo non-guest)
    "/api/v1/auth/register/begin": {
        "POST": {
            "impatto": 0.2,
            "ruoli_ammessi": ["operator", "manager", "admin"],
            "rischio_accettato": 0.5
        }
    },
    "/api/v1/auth/register/finish": {
        "POST": {
            "impatto": 0.2,
            "ruoli_ammessi": ["operator", "manager", "admin"],
            "rischio_accettato": 0.5
        }
    }

}

# =======================================================
# Section 3 : Risoluzione Dinamica della Rotta (Sottorotte)
# =======================================================

rotte_compatibili[p] if {
    matrice_sicurezza[p]
    p == input.request.path
}

rotte_compatibili[p] if {
    matrice_sicurezza[p]
    # Verifica se il path in input inizia con la rotta base seguita da un "/"
    # Es: /api/v1/transazioni/123 inizia con /api/v1/transazioni/
    startswith(input.request.path, sprintf("%s/", [p]))
}

rotta_base := p if {
    rotte_compatibili[p]
    not ha_match_piu_lungo(p)
}

ha_match_piu_lungo(p) if {
    rotte_compatibili[altro_p]
    count(altro_p) > count(p)
}

# =======================================================
# Section 4 : Rules
# =======================================================

allow if {
    # Usiamo 'rotta_base' (risolta dinamicamente) invece di 'input.request.path'
    config_rotta := matrice_sicurezza[rotta_base][input.request.method]
    
    # --- CONTROLLO 1: RUOLO (RBAC) ---
    input.role == config_rotta.ruoli_ammessi[_]
    
    # --- CONTROLLO 2: RISCHIO VS IMPATTO ---
    (input.ai.score - config_rotta.impatto) < config_rotta.rischio_accettato
}