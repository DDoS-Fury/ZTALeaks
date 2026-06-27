package envoy.authz

import rego.v1

# Default decision: deny everything unless a rule explicitly allows it.
default allow := false

# Mappatura gerarchica dei livelli di sicurezza (corrispondenza esatta maiuscola)
livelli := {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP_SECRET": 4
}

# Definiamo cosa significa ogni ruolo aziendale nel mondo Bell-LaPadula
ruoli_to_blp := {
    "guest": {
        "clearance": 0, # Mappato a PUBLIC
        "categorie": []
    },
    "operator": {
        "clearance": 1, # Mappato a INTERNAL
        "categorie": ["hr", "ops"]
    },
    "manager": {
        "clearance": 2, # Mappato a CONFIDENTIAL
        "categorie": ["hr", "ops", "finance"]
    },
    "admin": {
        "clearance": 4, # Mappato a TOP_SECRET
        "categorie": ["hr", "ops", "finance", "nuclear", "security"]
    }
}

# Estrazione dei dati utente basati sul JWT
ruolo_utente := input.claims.role
user_clearance_val := ruoli_to_blp[ruolo_utente].clearance
user_categories := ruoli_to_blp[ruolo_utente].categorie

# ==================================================
# Section 1 : Public Routes
# ==================================================

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
    "/api/v1/auth/register/finish",
    "/api/v1/auth/register/begin",
}

beneficio := 0.8

allow if {
    input.request.path in public_paths
    ai_score := object.get(input, ["ai", "score"], 0.99)
    (beneficio - ai_score) >= 0.4
}

allow if {
    startswith(input.request.path, "/static/")
}

# ==================================================
# Section 2 : BLP Populated Security Matrix
# ==================================================

matrice_sicurezza := {
    "/api/v1/personnel": {
        "classificazione": "INTERNAL",
        "categorie": ["hr"],
        "GET": {"benefici": 0.6, "beneficio_netto_minimo": 0.3},
        "POST": {"benefici": 0.6, "beneficio_netto_minimo": 0.3}        
    },
    "/api/v1/documents": {
        "classificazione": "CONFIDENTIAL",
        "categorie": ["finance"],
        "GET": {"benefici": 0.7, "beneficio_netto_minimo": 0.5},
        "POST": {"benefici": 0.7, "beneficio_netto_minimo": 0.5},
        "DELETE": {"benefici": 0.7, "beneficio_netto_minimo": 0.5}
    },
    "/api/v1/nuclear-materials": {
        "classificazione": "TOP_SECRET",
        "categorie": ["nuclear"],
        "GET": {"benefici": 0.8, "beneficio_netto_minimo": 0.6},
        "POST": {"benefici": 0.8, "beneficio_netto_minimo": 0.6},
        "DELETE": {"benefici": 0.8, "beneficio_netto_minimo": 0.6}
    },
    "/api/v1/reactor-parameters": {
        "classificazione": "TOP_SECRET",
        "categorie": ["nuclear", "security"],
        "GET": {"benefici": 0.9, "beneficio_netto_minimo": 0.8},
        "POST": {"benefici": 0.9, "beneficio_netto_minimo": 0.8},
        "DELETE": {"benefici": 0.9, "beneficio_netto_minimo": 0.8}
    },
    # Questo endpoint è SECRET. Un admin (TOP_SECRET) che fa una POST violerebbe la *-Property.
    # Lo classifichiamo come SECRET richiedendo la categoria "security".
    "/api/v1/trusted-guard/sanitized-delete-personnel": {
        "classificazione": "SECRET",
        "categorie": ["security"],
        "POST": {"benefici": 0.9, "beneficio_netto_minimo": 0.7}
    }
}

# =======================================================
# Section 3 : Dynamic Route Resolution
# =======================================================

rotte_compatibili[p] if {
    matrice_sicurezza[p]
    p == input.request.path
}

rotte_compatibili[p] if {
    matrice_sicurezza[p]
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
# Section 4 : BLP Logic Core (Funzioni helper con scope corretto)
# =======================================================

# Simple Security Property (No Read-Up):
blp_elabora_regola("GET", u_clearance, o_classification, _, _) if {
    u_clearance >= o_classification
}

# *-Property (No Write-Down standard):
metodi_scrittura := {"POST", "PUT", "DELETE", "PATCH"}
blp_elabora_regola(method, u_clearance, o_classification, path, _) if {
    method in metodi_scrittura
    # Escludiamo la rotta di bypass dal controllo standard no-write-down
    path != "/api/v1/trusted-guard/sanitized-delete-personnel"
    u_clearance <= o_classification
}

# eccezione: SANITIZED WRITE-DOWN (Concept di Soggetto Fidato / Trusted Subject)
# Permette specificamente all'admin (clearance 4) di scrivere sulla rotta del Trusted Guard (clearance 3)
blp_elabora_regola("POST", 4, 3, "/api/v1/trusted-guard/sanitized-delete-personnel", "admin")


# =======================================================
# Section 5 : Final Authorization Rule
# =======================================================

cert_ou := lower(trim_space(split(trim_space(part), "=")[1])) if {
    input.cert_present
    some part in split(input.cert_subject, ",")
    startswith(trim_space(part), "OU=")
}

cert_mismatch if {
    input.cert_present
    input.claims.role
    cert_ou != lower(input.claims.role)
}

cert_required_missing if {
    lower(input.claims.role) in {"admin", "manager"}
    not input.cert_present
}

allow if {
    # 0. Anti-Privilege Escalation: Controllo coerenza JWT vs Certificato
    not cert_mismatch
    not cert_required_missing

    # 1. Estrazione configurazione metodo (Senza il finto sotto-blocco .metodi)
    config_metodo := matrice_sicurezza[rotta_base][input.request.method]
    
    # 2. Risoluzione dinamica dei dati dell'oggetto per questa specifica rotta
    obj_classification_val := livelli[matrice_sicurezza[rotta_base].classificazione]
    obj_categories := matrice_sicurezza[rotta_base].categorie
    
    # 3. Controllo Matematico Compartimenti (Categorie)
    categorie_mancanti := {c | c := obj_categories[_]; not c in user_categories}
    count(categorie_mancanti) == 0
    
    # 4. Controllo Gerarchico BLP (Inclusa eccezione Trusted Guard)
    blp_elabora_regola(input.request.method, user_clearance_val, obj_classification_val, rotta_base, ruolo_utente)
    
    # 5. Controllo Rischio AI (Formula corretta per il calcolo del rischio netto)
    ai_score := object.get(input, ["ai", "score"], 0.99)
    (config_metodo.benefici - ai_score) >= config_metodo.beneficio_netto_minimo
}