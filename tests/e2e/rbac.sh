#!/usr/bin/env bash
# Pillar 3 — RBAC: ruoli ammessi vs ruoli negati su rotte specifiche.
# La matrice è in OPA (policy.rego). Verifichiamo i diritti chiave:
#   operator può GET reactor-parameters (cert)
#   operator NON può GET nuclear-materials (role non in lista)
#   operator NON può POST maintenance-orders (role non in lista)
#   maintenance_technician può POST maintenance-orders (con cert)
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_stack
log "RBAC pillar — role × resource matrix (OPA)"
print_header

JWT_OP=$(get_jwt operator1 admin123)
[[ -z "$JWT_OP" ]] && die "impossibile ottenere JWT operator1"
ok "operator1 JWT obtained"

JWT_MAINT=$(get_jwt maint_tech1 admin123)
[[ -z "$JWT_MAINT" ]] && die "impossibile ottenere JWT maint_tech1"
ok "maint_tech1 JWT obtained"

# operator: ALLOWED su reactor-parameters GET (con cert per superare tier 1)
code=$(http_envoy GET /api/v1/reactor-parameters "$JWT_OP" 1)
assert_eq "operator + cert → /reactor-parameters GET" "200" "$code"

# operator: DENIED su nuclear-materials GET (role non in lista)
code=$(http_envoy GET /api/v1/nuclear-materials "$JWT_OP" 1)
assert_eq "operator → /nuclear-materials GET (role denied)" "403" "$code"

# operator: DENIED su maintenance-orders POST (role non in lista)
code=$(http_envoy POST /api/v1/maintenance-orders "$JWT_OP" 1 '{}')
assert_eq "operator → /maintenance-orders POST (role denied)" "403" "$code"

# maintenance_technician: ALLOWED su maintenance-orders POST con cert (tier 1)
code=$(http_envoy POST /api/v1/maintenance-orders "$JWT_MAINT" 1 '{"order_id":"MO-E2E-1","title":"e2e","status":"OPEN"}')
# 201/200 ok; 5xx tollerato come passaggio del PDP (validazione lato BL out-of-scope)
allowed="yes"; [[ "$code" == "403" || "$code" == "401" ]] && allowed="no"
assert_eq "maint_tech1 + cert → /maintenance-orders POST (PDP allow)" "yes" "$allowed"

print_summary
