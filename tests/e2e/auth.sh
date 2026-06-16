#!/usr/bin/env bash
# Pillar 1 — Authentication: login flow + claim JWT corretti.
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_stack
log "Auth pillar — admin login flow + claims"
print_header

JWT=$(get_jwt admin admin123)
issued="no"; [[ -n "$JWT" ]] && issued="yes"
assert_eq "admin login → JWT issued" "yes" "$issued"

if [[ "$issued" == "yes" ]]; then
    payload=$(decode_jwt_payload "$JWT")
    sub=$(printf '%s' "$payload" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sub',''))")
    role=$(printf '%s' "$payload" | python3 -c "import sys,json;print(json.load(sys.stdin).get('role',''))")
    clr=$(printf '%s' "$payload" | python3 -c "import sys,json;print(json.load(sys.stdin).get('clearance_level',''))")
    mfa=$(printf '%s' "$payload" | python3 -c "import sys,json;print(json.load(sys.stdin).get('mfa_verified',False))")
    iss=$(printf '%s' "$payload" | python3 -c "import sys,json;print(json.load(sys.stdin).get('iss',''))")

    assert_eq "JWT.sub non vuoto"           "yes"          "$([[ -n "$sub" ]] && echo yes || echo no)"
    assert_eq "JWT.role == plant_manager"   "plant_manager" "$role"
    assert_eq "JWT.clearance == TOP_SECRET" "TOP_SECRET"   "$clr"
    assert_eq "JWT.mfa_verified == True"    "True"         "$mfa"
    assert_eq "JWT.iss == identity service" "iam-service.ztaleaks.local" "$iss"
fi

# Negative: OTP errato → 401
log "Negative scenario: OTP errato"
mailhog_clear
LOGIN=$(curl -sk -X POST "$ENVOY_URL/api/v1/auth/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}')
ST=$(printf '%s' "$LOGIN" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('session_token',''))
except: print('')")
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$ENVOY_URL/api/v1/auth/verify-otp" \
    -H "Content-Type: application/json" -d "{\"session_token\":\"$ST\",\"otp\":\"000000\"}")
assert_eq "verify-otp con OTP errato → 401" "401" "$code"

# Negative: password errata → 401
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$ENVOY_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" -d '{"username":"admin","password":"WRONG"}')
assert_eq "login con password errata → 401" "401" "$code"

print_summary
