#!/usr/bin/env bash
# Pillar 4 — ABAC (clearance hierarchy):
# Registriamo inline un inspector con clearance bassa (CONFIDENTIAL) e
# verifichiamo che, pur essendo nella lista dei role di /personnel POST
# (no — POST è solo plant_manager) prendiamo nuclear-materials GET che
# richiede clearance >= SECRET ed è ammesso a inspector.
#
# Test concreto:
#   inspector_low (role inspector, clearance CONFIDENTIAL) → /nuclear-materials GET
#   con cert+JWT → DENY per clearance underflow (CONFIDENTIAL < SECRET)
#   inspector1 (role inspector, clearance SECRET) → stessa rotta → ALLOW
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_stack
log "ABAC pillar — clearance vs resource"
print_header

# Registra inline un inspector con clearance bassa (idempotente: 409 se esiste)
INSP_LOW_USER="insp_e2e_low"
INSP_LOW_PASS="LowPass2026!"
curl -sk -X POST "$ENVOY_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$INSP_LOW_USER\",\"email\":\"${INSP_LOW_USER}@ztaleaks.local\",\"password\":\"$INSP_LOW_PASS\",\"role\":\"inspector\",\"clearance_level\":\"CONFIDENTIAL\"}" \
    > /dev/null

JWT_LOW=$(get_jwt "$INSP_LOW_USER" "$INSP_LOW_PASS")
[[ -z "$JWT_LOW" ]] && die "impossibile ottenere JWT $INSP_LOW_USER"
ok "$INSP_LOW_USER (CONFIDENTIAL) JWT obtained"

JWT_HIGH=$(get_jwt inspector1 admin123)
[[ -z "$JWT_HIGH" ]] && die "impossibile ottenere JWT inspector1"
ok "inspector1 (SECRET) JWT obtained"

# Per nuclear-materials GET il min_tier è 2 (cert+TPM). Per testare il SOLO
# clearance, usiamo /personnel GET (min_tier 1, min_clearance INTERNAL):
# entrambi gli ispettori passano clearance, quindi serve un confronto su una
# rotta dove la clearance è discriminante. Usiamo /reactor-parameters GET
# (min_tier 1, min_clearance CONFIDENTIAL) — entrambi a CONFIDENTIAL+ passano.
# Per dimostrare il blocco da clearance prendiamo /nuclear-materials POST
# (min_clearance TOP_SECRET, role-only plant_manager): il role bocca prima.
#
# Soluzione: registriamo anche un plant_manager con clearance bassa.
PM_LOW_USER="pm_e2e_low"
PM_LOW_PASS="LowPass2026!"
curl -sk -X POST "$ENVOY_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$PM_LOW_USER\",\"email\":\"${PM_LOW_USER}@ztaleaks.local\",\"password\":\"$PM_LOW_PASS\",\"role\":\"plant_manager\",\"clearance_level\":\"INTERNAL\"}" \
    > /dev/null

JWT_PM_LOW=$(get_jwt "$PM_LOW_USER" "$PM_LOW_PASS")
[[ -z "$JWT_PM_LOW" ]] && die "impossibile ottenere JWT $PM_LOW_USER"
ok "$PM_LOW_USER (plant_manager, INTERNAL) JWT obtained"

# enroll TPM così tier=2 e il blocco sarà solo da clearance
enroll_webauthn "$JWT_PM_LOW" || warn "enroll WebAuthn pm_low failed"
# rilascia un nuovo JWT per avere device_id nel token
JWT_PM_LOW=$(get_jwt "$PM_LOW_USER" "$PM_LOW_PASS")

# Ora plant_manager INTERNAL+TPM → POST /nuclear-materials → DENY per clearance
code=$(http_envoy POST /api/v1/nuclear-materials "$JWT_PM_LOW" 1 '{}')
assert_eq "plant_manager INTERNAL → /nuclear-materials POST (clearance underflow)" "403" "$code"

# Confronto: admin (TOP_SECRET) con cert+TPM → stessa rotta → PDP allow
JWT_ADMIN=$(get_jwt admin admin123)
[[ -z "$JWT_ADMIN" ]] && die "impossibile ottenere JWT admin"
enroll_webauthn "$JWT_ADMIN" || true
JWT_ADMIN=$(get_jwt admin admin123)
code=$(http_envoy POST /api/v1/nuclear-materials "$JWT_ADMIN" 1 '{}')
allowed="yes"; [[ "$code" == "403" || "$code" == "401" ]] && allowed="no"
assert_eq "admin TOP_SECRET cert+tpm → /nuclear-materials POST (PDP allow)" "yes" "$allowed"

# inspector low CONFIDENTIAL su personnel GET (richiede INTERNAL: passa)
code=$(http_envoy GET /api/v1/personnel "$JWT_LOW" 1)
assert_eq "inspector CONFIDENTIAL → /personnel GET (clearance ≥ INTERNAL)" "200" "$code"

# inspector1 SECRET su personnel POST → DENY per role (solo plant_manager)
code=$(http_envoy POST /api/v1/personnel "$JWT_HIGH" 1 '{}')
assert_eq "inspector → /personnel POST (role only plant_manager)" "403" "$code"

print_summary
