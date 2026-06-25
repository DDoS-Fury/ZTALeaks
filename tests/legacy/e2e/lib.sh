#!/usr/bin/env bash
# tests/e2e/lib.sh — helpers per la suite E2E ZTALeaks (mix-master-zta-core)
#
# Uso:
#   SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/lib.sh"
#
# Dipendenze: bash, curl, python3 (no jq).

if [[ "${ZTA_E2E_LIB_SOURCED:-}" == "1" ]]; then return 0; fi
ZTA_E2E_LIB_SOURCED=1

# ----- Config (overridable via env) ------------------------------------------
ENVOY_URL="${ENVOY_URL:-https://127.0.0.1:8443}"
MAILHOG_URL="${MAILHOG_URL:-http://127.0.0.1:8025}"
CERTS_DIR="${CERTS_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../certs" && pwd)}"
CLIENT_CERT="$CERTS_DIR/admin.crt"
CLIENT_KEY="$CERTS_DIR/admin.key"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-90}"

# ----- Pretty output ---------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'
    C_CYA=$'\033[36m'; C_BLD=$'\033[1m';  C_OFF=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YLW=""; C_CYA=""; C_BLD=""; C_OFF=""
fi
log()  { printf "%s[%s]%s %s\n" "$C_CYA" "$(date +%H:%M:%S)" "$C_OFF" "$*"; }
ok()   { printf "%s  ✓ %s%s\n" "$C_GRN" "$*" "$C_OFF"; }
warn() { printf "%s  ! %s%s\n" "$C_YLW" "$*" "$C_OFF"; }
err()  { printf "%s  ✗ %s%s\n" "$C_RED" "$*" "$C_OFF" >&2; }
die()  { err "$*"; exit 1; }

# ----- Counters per assert_eq ------------------------------------------------
ZTA_TESTS_RUN=0
ZTA_TESTS_PASS=0
ZTA_TESTS_FAIL=0

print_header() {
    printf "\n  %-60s %-10s %-10s %s\n" "Scenario" "Expected" "Actual" "Result"
    printf "  %s\n" "------------------------------------------------------------------------------------------"
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    ZTA_TESTS_RUN=$((ZTA_TESTS_RUN + 1))
    local mark res
    if [[ "$expected" == "$actual" ]]; then
        ZTA_TESTS_PASS=$((ZTA_TESTS_PASS + 1)); mark="$C_GRN"; res="PASS"
    else
        ZTA_TESTS_FAIL=$((ZTA_TESTS_FAIL + 1)); mark="$C_RED"; res="FAIL"
    fi
    printf "  %-60s %-10s %-10s %s%s%s\n" "$desc" "$expected" "$actual" "$mark" "$res" "$C_OFF"
}

print_summary() {
    printf "\n  Total: %d  PASS: %d  FAIL: %d\n" "$ZTA_TESTS_RUN" "$ZTA_TESTS_PASS" "$ZTA_TESTS_FAIL"
    if (( ZTA_TESTS_FAIL > 0 )); then return 1; fi
    return 0
}

# ----- Stack readiness --------------------------------------------------------
wait_for() {
    local name="$1" url="$2" deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
    while (( $(date +%s) < deadline )); do
        if curl -ks -o /dev/null -w '%{http_code}' --max-time 3 "$url" \
             | grep -qE '^[1-5][0-9][0-9]$'; then
            return 0
        fi
        sleep 1
    done
    die "$name not reachable after ${WAIT_TIMEOUT}s ($url)"
}

wait_for_stack() {
    log "Waiting for stack readiness"
    wait_for "Envoy"   "$ENVOY_URL/.well-known/jwks.json" && ok "Envoy reachable ($ENVOY_URL)"
    wait_for "MailHog" "$MAILHOG_URL/api/v2/messages" && ok "MailHog reachable ($MAILHOG_URL)"
}

# ----- MailHog --------------------------------------------------------------
mailhog_clear() {
    curl -s -X DELETE "$MAILHOG_URL/api/v1/messages" -o /dev/null
}

# extract OTP da MailHog: usa il messaggio più recente per il destinatario `to`.
# Restituisce stringa vuota se non trovato.
mailhog_latest_otp_for() {
    local to="$1"
    curl -s "$MAILHOG_URL/api/v2/messages" | python3 -c "
import sys, json, re
to = '$to'
try:
    d = json.loads(sys.stdin.read(), strict=False)
except Exception:
    print(''); raise SystemExit
items = d.get('items', [])
items.sort(key=lambda x: x.get('Created', ''), reverse=True)
for it in items:
    addrs = it.get('To', [])
    if any((a.get('Mailbox','')+'@'+a.get('Domain','')) == to for a in addrs):
        m = re.search(r'>(\d{6})<', it.get('Content',{}).get('Body',''))
        print(m.group(1) if m else '')
        break
else:
    print('')
"
}

# ----- Auth helpers ----------------------------------------------------------
# get_jwt <username> <password> → stampa il JWT ottenuto via login + OTP, o
# vuoto se qualcosa va storto.
get_jwt() {
    local user="$1" pass="$2"
    local email="${user}@ztaleaks.local"
    mailhog_clear
    local resp st
    resp=$(curl -sk -X POST "$ENVOY_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$user\",\"password\":\"$pass\"}")
    st=$(printf '%s' "$resp" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('session_token',''))
except: print('')")
    if [[ -z "$st" ]]; then return 1; fi
    sleep 1
    local otp
    otp=$(mailhog_latest_otp_for "$email")
    if [[ -z "$otp" ]]; then return 1; fi
    curl -sk -X POST "$ENVOY_URL/api/v1/auth/verify-otp" \
        -H "Content-Type: application/json" \
        -d "{\"session_token\":\"$st\",\"otp\":\"$otp\"}" \
        | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('access_token',''))
except: print('')"
}

# decode_jwt_payload <jwt> → stampa il payload JSON
decode_jwt_payload() {
    local tok="$1"
    printf '%s' "$tok" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
def pad(s): return s + '=' * (-len(s) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(pad(parts[1])))))
"
}

# ----- HTTP assertion via Envoy ---------------------------------------------
# http_envoy <method> <path> [jwt] [use_cert: 0|1] [body]
# Stampa solo lo status code.
http_envoy() {
    local method="$1" path="$2" jwt="${3:-}" use_cert="${4:-0}" body="${5:-}"
    local args=(-sk -o /dev/null -w "%{http_code}" -X "$method" "$ENVOY_URL$path")
    if [[ "$use_cert" == "1" ]]; then
        args+=(--cert "$CLIENT_CERT" --key "$CLIENT_KEY")
    fi
    if [[ -n "$jwt" ]]; then
        args+=(-H "Authorization: Bearer $jwt")
    fi
    if [[ -n "$body" ]]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi
    curl "${args[@]}"
}

# enroll_webauthn <jwt> <user_id> → registra una credenziale fake; segue
# /register/begin → /register/finish (lab pattern).
enroll_webauthn() {
    # register/begin e register/finish richiedono min_tier 1 (mTLS) lato OPA,
    # quindi entrambe le chiamate devono presentare il certificato client.
    local jwt="$1"
    local begin
    begin=$(curl -sk --cert "$CLIENT_CERT" --key "$CLIENT_KEY" -X POST "$ENVOY_URL/api/v1/auth/register/begin" \
        -H "Authorization: Bearer $jwt" \
        -H "Content-Type: application/json" \
        -d "{\"device_name\":\"lab-tpm\"}")
    local sid
    sid=$(printf '%s' "$begin" | python3 -c "import sys,json;print(json.load(sys.stdin).get('session_id',''))")
    if [[ -z "$sid" ]]; then return 1; fi
    local cred pkey
    cred=$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('='))")
    pkey=$(python3 -c "import os, base64; print(base64.b64encode(os.urandom(64)).decode())")
    curl -sk --cert "$CLIENT_CERT" --key "$CLIENT_KEY" -X POST "$ENVOY_URL/api/v1/auth/register/finish" \
        -H "Authorization: Bearer $jwt" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\":\"$sid\",\"credential_id\":\"$cred\",\"public_key\":\"$pkey\",\"attestation_type\":\"platform\"}" \
        > /dev/null
}
