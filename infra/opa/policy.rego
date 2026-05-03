package envoy.authz

import rego.v1

default allow = false

allow if {
    true
}

# 1. LOGICA PER PAGINE PUBBLICHE (Login/Register)
# Permetti l'accesso se il rischio è basso, anche senza JWT
allow if {
    is_public_path
    input.risk_score < 0.3
}

# 2. LOGICA PER BUSINESS LOGIC (Richiede Identità + Rischio Basso)
allow if {
    is_business_path
    input.risk_score < 0.5    # Soglia di rischio per utenti loggati
}




is_public_path if {
    public_paths := ["/", "/login", "/register", "/api/v1/auth/login"]
    input.attributes.request.http.path == public_paths[_]
}

is_business_path if {
    startswith(input.attributes.request.http.path, "/api/v1")
}