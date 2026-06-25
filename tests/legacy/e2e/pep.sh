#!/usr/bin/env bash
# Pillar 2 — PEP (Envoy + ext_authz orchestrator):
#   - rotte pubbliche bypassano (login, jwks)
#   - rotte protette senza JWT vengono rifiutate
#   - JWT invalido → rifiutato
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_stack
log "PEP pillar — public bypass + protect by default"
print_header

# Public endpoints
code=$(http_envoy POST /api/v1/auth/login "" 0 '{"username":"x","password":"y"}')
# 401 (cred sbagliate ma routing ok) o 200 (con seed admin). Accettiamo qualunque
# 4xx/2xx perché la chiave è "non 403 di ext_authz".
allowed_code="ok"; [[ "$code" == "403" ]] && allowed_code="denied"
assert_eq "/api/v1/auth/login (public) → non 403" "ok" "$allowed_code"

code=$(curl -sk -o /dev/null -w "%{http_code}" "$ENVOY_URL/.well-known/jwks.json")
assert_eq "/.well-known/jwks.json (public) → 200" "200" "$code"

# Protected senza JWT
code=$(http_envoy GET /api/v1/personnel "" 0)
assert_eq "GET /personnel senza JWT → 403" "403" "$code"

code=$(http_envoy GET /api/v1/nuclear-materials "" 1)
assert_eq "GET /nuclear-materials no-JWT (con cert) → 403" "403" "$code"

# JWT invalido → 401
code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer not.a.jwt" "$ENVOY_URL/api/v1/personnel")
assert_eq "GET /personnel con JWT garbage → 401" "401" "$code"

print_summary
