#!/usr/bin/env bash
# Pillar 5 — 3-tier admission (DIRETTIVA: cert+TPM / solo cert / niente).
# Per isolare l'effetto di cert × TPM neutralizzando role e clearance, registriamo
# un utente fresh "tier_pm" plant_manager TOP_SECRET — vergine di enrollment WebAuthn.
# Sequenza di test:
#   - tier 0: tier_pm no-cert     → /personnel GET (min_tier 1)        → DENY
#   - tier 1: tier_pm cert        → /personnel GET                     → ALLOW
#   - tier 1: tier_pm cert no-TPM → /nuclear-materials POST (min 2)    → DENY
#   - enroll TPM, nuovo JWT
#   - tier 2: tier_pm cert+TPM    → /nuclear-materials POST (min 2)    → ALLOW
#   - tier 0: tier_pm no-cert     → /nuclear-materials POST            → DENY
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_stack
log "Tier admission pillar — cert × tpm (utente fresh per isolare TPM)"
print_header

# Username randomizzato per essere sicuri di partire senza enrollment WebAuthn
# anche su rerun ravvicinati (il TPM una volta enrollato resta in security-db).
USER="tier_pm_$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(4)).decode().rstrip('=').lower())")"
PASS="TierPass2026!"

# Idempotente: 409 se già esiste (utente persiste tra run, ma nessun TPM se mai
# enrollato in questo run)
curl -sk -X POST "$ENVOY_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"email\":\"${USER}@ztaleaks.local\",\"password\":\"$PASS\",\"role\":\"plant_manager\",\"clearance_level\":\"TOP_SECRET\"}" \
    > /dev/null

JWT=$(get_jwt "$USER" "$PASS")
[[ -z "$JWT" ]] && die "impossibile ottenere JWT $USER"

# tier 0 (no cert) su /personnel GET (min_tier 1) → DENY
code=$(http_envoy GET /api/v1/personnel "$JWT" 0)
assert_eq "tier_pm no-cert → /personnel GET (tier 0 < 1)" "403" "$code"

# tier 1 (cert) su /personnel GET → ALLOW
code=$(http_envoy GET /api/v1/personnel "$JWT" 1)
assert_eq "tier_pm cert → /personnel GET (tier 1 ≥ 1)"   "200" "$code"

# tier 1 (cert, NO TPM ancora) su /nuclear-materials POST (min 2) → DENY
code=$(http_envoy POST /api/v1/nuclear-materials "$JWT" 1 '{}')
# Se per qualche motivo l'utente avesse già un device (run precedente), il PDP
# allow → BL 500 (payload vuoto). In quel caso il fix è cancellare i device.
assert_eq "tier_pm cert no-TPM → /nuclear POST (tier 1 < 2)" "403" "$code"

# Enroll WebAuthn → nuovo JWT con device_id
enroll_webauthn "$JWT" || die "enroll WebAuthn $USER failed"
JWT=$(get_jwt "$USER" "$PASS")

# tier 2 → ALLOW (PDP); BL può rispondere 5xx per payload vuoto, ma quello che
# conta è "non 401/403"
code=$(http_envoy POST /api/v1/nuclear-materials "$JWT" 1 '{}')
allowed="yes"; [[ "$code" == "403" || "$code" == "401" ]] && allowed="no"
assert_eq "tier_pm cert+TPM → /nuclear POST (tier 2 ≥ 2)" "yes" "$allowed"

# tier 0 (no cert) anche con TPM enrollato → DENY (cert manca)
code=$(http_envoy POST /api/v1/nuclear-materials "$JWT" 0 '{}')
assert_eq "tier_pm TPM ma no-cert → /nuclear POST (tier 0 < 2)" "403" "$code"

print_summary
