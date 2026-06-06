// =============================================================================
// ZTALeaks - Modulo frontend condiviso (auth + RBAC mirror + API client)
//
// Usato da reserved.html (dashboard) e materials.html.
//
// NOTA SICUREZZA: la matrice RBAC qui sotto e' un MIRROR della policy OPA
// (infra/opa/policy.rego) usato SOLO per la UX (mostrare/nascondere voci e
// pulsanti). L'enforcement reale e' SEMPRE server-side e attraversa la catena
// Zero Trust: Envoy (PEP) -> Security Orchestrator (PDP) -> OPA + AI scorer.
// Tier mTLS, clearance e risk-score sono decisi dal server: la UI mostra
// fedelmente status e corpo di ogni risposta, inclusi i deny.
// =============================================================================

(function (global) {
    "use strict";

    const TOKEN_KEY = "access_token";

    // -------------------------------------------------------------------------
    // Token / JWT
    // -------------------------------------------------------------------------

    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }

    // Decodifica il payload del JWT senza verificarne la firma (solo lettura UI).
    function decodeJWT(token) {
        const t = token || getToken();
        if (!t) return null;
        try {
            const payload = t.split(".")[1];
            const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
            return JSON.parse(atob(base64));
        } catch (e) {
            return null;
        }
    }

    // true se assente o scaduto (claim exp in secondi epoch).
    function isExpired(token) {
        const claims = decodeJWT(token);
        if (!claims) return true;
        if (!claims.exp) return false; // nessuna scadenza dichiarata
        return Date.now() >= claims.exp * 1000;
    }

    // Guardia di pagina: redirige a /login se non autenticati o token scaduto.
    function requireAuth() {
        const token = getToken();
        if (!token || isExpired(token)) {
            logout();
            return null;
        }
        return decodeJWT(token);
    }

    function logout() {
        localStorage.removeItem(TOKEN_KEY);
        window.location.href = "/login";
    }

    // -------------------------------------------------------------------------
    // API client: aggiunge sempre Authorization: Bearer <jwt>
    // Ritorna { status, statusText, ok, text } per un render fedele.
    // -------------------------------------------------------------------------

    async function apiFetch(method, path, body) {
        const token = getToken();
        const opts = {
            method: method,
            headers: { "Authorization": "Bearer " + token },
        };
        if (body !== undefined && body !== null) {
            opts.headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(path, opts);
        const text = await res.text();
        return {
            status: res.status,
            statusText: res.statusText,
            ok: res.ok,
            text: text,
        };
    }

    // -------------------------------------------------------------------------
    // Mirror RBAC (da infra/opa/policy.rego) - SOLO rotte implementate nel
    // backend (services/business-logic/internal/handler/routes.go).
    // zones/badges/maintenance-orders sono nella policy ma non nel backend
    // (404) quindi sono volutamente esclusi.
    // -------------------------------------------------------------------------

    const CLEARANCE_ORDER = {
        "PUBLIC": 0,
        "INTERNAL": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4,
    };

    const ALL_ROLES = [
        "plant_manager", "operator", "inspector",
        "maintenance_technician", "radiation_protection_officer", "security_officer",
    ];

    const ROUTE_RULES = {
        "/api/v1/personnel": {
            "GET": { roles: ["security_officer", "plant_manager", "inspector"], min_tier: 1, min_clearance: "INTERNAL" },
            "POST": { roles: ["plant_manager"], min_tier: 2, min_clearance: "SECRET" },
        },
        "/api/v1/documents": {
            "GET": { roles: ALL_ROLES, min_tier: 0, min_clearance: "PUBLIC" },
            "POST": { roles: ["plant_manager"], min_tier: 2, min_clearance: "CONFIDENTIAL" },
            "DELETE": { roles: ["plant_manager"], min_tier: 2, min_clearance: "CONFIDENTIAL" },
        },
        "/api/v1/reactor-parameters": {
            "GET": { roles: ["operator", "plant_manager", "inspector"], min_tier: 1, min_clearance: "CONFIDENTIAL" },
            "POST": { roles: ["plant_manager"], min_tier: 2, min_clearance: "SECRET" },
            "DELETE": { roles: ["plant_manager"], min_tier: 2, min_clearance: "SECRET" },
        },
        "/api/v1/nuclear-materials": {
            "GET": { roles: ["plant_manager", "inspector", "radiation_protection_officer"], min_tier: 2, min_clearance: "SECRET" },
            "POST": { roles: ["plant_manager"], min_tier: 2, min_clearance: "TOP_SECRET" },
            "DELETE": { roles: ["plant_manager"], min_tier: 2, min_clearance: "TOP_SECRET" },
        },
        // Gateway di sanitizzazione (admin): cancellazione controllata e
        // tracciata di personale. Richiede tier 2 + clearance SECRET.
        "/api/v1/trusted-guard/sanitized-delete-personnel": {
            "POST": { roles: ["plant_manager"], min_tier: 2, min_clearance: "SECRET" },
        },
    };

    function ruleFor(path, method) {
        const r = ROUTE_RULES[path];
        return r ? r[method] : undefined;
    }

    // Il ruolo e' tra quelli ammessi per (path, method)?
    function roleCan(role, path, method) {
        const rule = ruleFor(path, method);
        if (!rule) return false;
        return rule.roles.indexOf(role) !== -1;
    }

    // La clearance soddisfa il minimo richiesto da (path, method)?
    function clearanceMeets(level, path, method) {
        const rule = ruleFor(path, method);
        if (!rule) return false;
        const have = CLEARANCE_ORDER[level];
        const need = CLEARANCE_ORDER[rule.min_clearance];
        if (have === undefined || need === undefined) return false;
        return have >= need;
    }

    // -------------------------------------------------------------------------
    // UI helper: badge identita' dal JWT
    // -------------------------------------------------------------------------

    function renderIdentity(el) {
        const claims = decodeJWT();
        if (!el) return;
        if (!claims) {
            el.textContent = "Token non valido o illeggibile.";
            return;
        }
        const auth = claims.mfa_verified ? "2FA" : "1FA";
        el.textContent = "Utente: " + claims.sub +
            " | Ruolo: " + claims.role +
            " | Clearance: " + claims.clearance_level +
            " | Auth: " + auth;
    }

    // -------------------------------------------------------------------------
    // Export
    // -------------------------------------------------------------------------

    global.ZTA = {
        getToken: getToken,
        decodeJWT: decodeJWT,
        isExpired: isExpired,
        requireAuth: requireAuth,
        logout: logout,
        apiFetch: apiFetch,
        roleCan: roleCan,
        clearanceMeets: clearanceMeets,
        ruleFor: ruleFor,
        renderIdentity: renderIdentity,
        ROUTE_RULES: ROUTE_RULES,
        CLEARANCE_ORDER: CLEARANCE_ORDER,
    };
})(window);
