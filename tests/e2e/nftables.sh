#!/usr/bin/env bash
# Pillar — Firewall (nftables):
#   - Traffico legittimo verso Envoy accettato
#   - Set blocked_ips caricato correttamente
#   - Chain output con policy DROP e allow-list configurata
#   - Parser JSON che scrive su disco
#   - Connessioni stabilite passano la chain input
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

FIREWALL_CTR="${FIREWALL_CTR:-ztaleaks_firewall}"

wait_for_stack
log "Firewall pillar — nftables rate-limiting + egress filtering"
print_header

# Test 1: Traffico legittimo verso Envoy deve essere accettato (chain input)
log "TEST 1: Normal traffic to Envoy (chain input accept)"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$ENVOY_URL/.well-known/jwks.json")
if [[ "$code" == "200" ]] || [[ "$code" == "404" ]]; then
    assert_eq "Normal traffic to Envoy" "allowed" "allowed"
else
    assert_eq "Normal traffic to Envoy" "allowed" "blocked(HTTP=$code)"
fi

# Test 2: Il set blocked_ips deve essere caricato con gli elementi attesi
log "TEST 2: blocked_ips set is loaded with expected elements"
if docker exec "$FIREWALL_CTR" nft list set inet filter blocked_ips 2>/dev/null \
     | grep -qE '10\.99\.99\.99'; then
    assert_eq "blocked_ips contains 10.99.99.99" "present" "present"
else
    assert_eq "blocked_ips contains 10.99.99.99" "present" "missing"
fi
if docker exec "$FIREWALL_CTR" nft list set inet filter blocked_ips 2>/dev/null \
     | grep -qE '172\.18\.0\.10'; then
    assert_eq "blocked_ips contains 172.18.0.10" "present" "present"
else
    assert_eq "blocked_ips contains 172.18.0.10" "present" "missing"
fi

# Test 3: Chain output deve avere policy DROP e la allow-list applicata
log "TEST 3: output chain has policy drop and allow-list configured"
output_chain=$(docker exec "$FIREWALL_CTR" nft list chain inet filter output 2>/dev/null || echo "")
if echo "$output_chain" | grep -qE 'policy[[:space:]]+drop'; then
    assert_eq "output policy is drop" "drop" "drop"
else
    assert_eq "output policy is drop" "drop" "accept_or_missing"
fi
if echo "$output_chain" | grep -qE 'tcp[[:space:]]+dport.*8080.*8081.*8082'; then
    assert_eq "output allow-list contains upstream ports" "present" "present"
else
    assert_eq "output allow-list contains upstream ports" "present" "missing_or_mismatch"
fi
if echo "$output_chain" | grep -qE 'fw-egress-drop'; then
    assert_eq "output logs unauthorized egress" "present" "present"
else
    assert_eq "output logs unauthorized egress" "present" "missing"
fi

# Test 4: Il parser nftables deve aver creato il file JSONL nel volume
log "TEST 4: nftables JSON parser writes to /var/log/ztaleaks/nftables/firewall.jsonl"
if docker exec "$FIREWALL_CTR" test -f /var/log/ztaleaks/nftables/firewall.jsonl; then
    assert_eq "nftables JSON log file exists" "present" "present"
    # Se ci sono già righe, verifica che siano JSON con campo action
    last_line=$(docker exec "$FIREWALL_CTR" sh -c 'tail -1 /var/log/ztaleaks/nftables/firewall.jsonl 2>/dev/null' || echo "")
    if [[ -n "$last_line" ]]; then
        if echo "$last_line" | grep -qE '"action"[[:space:]]*:[[:space:]]*"(accept|drop)"'; then
            assert_eq "log lines contain action field" "valid" "valid"
        else
            assert_eq "log lines contain action field" "valid" "malformed"
        fi
    else
        # File vuoto è ammissibile a stack appena avviato (no eventi loggati ancora)
        warn "log file is empty — no firewall events yet (acceptable on fresh start)"
    fi
else
    assert_eq "nftables JSON log file exists" "present" "missing"
fi

# Test 5: Rate-limit anti SYN flood deve essere caricato nella chain input
log "TEST 5: SYN flood rate-limit rule is present in chain input"
input_chain=$(docker exec "$FIREWALL_CTR" nft list chain inet filter input 2>/dev/null || echo "")
if echo "$input_chain" | grep -qE 'fw-syn-flood-drop'; then
    assert_eq "SYN flood rule present" "present" "present"
else
    assert_eq "SYN flood rule present" "present" "missing"
fi

# Test 6: Connessioni stabilite (replay del test 1) — verifica indiretta della ct established rule
log "TEST 6: Established connections pass (ct state established,related)"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$ENVOY_URL/.well-known/jwks.json")
if [[ "$code" == "200" ]] || [[ "$code" == "404" ]]; then
    assert_eq "Established connection rule" "pass" "pass"
else
    assert_eq "Established connection rule" "pass" "fail(HTTP=$code)"
fi

print_summary
