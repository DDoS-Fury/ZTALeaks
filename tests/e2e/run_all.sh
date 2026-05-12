#!/usr/bin/env bash
# tests/e2e/run_all.sh — orchestratore della suite E2E.
# Esegue i 6 pillar e rigenera tests/e2e/REPORT.md.
# Compatibile con bash 3 (macOS default), niente associative array.
set -u
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PILLARS=(auth pep rbac abac tier nftables)

# Parallel arrays: STATUS[i] e OUTFILE[i] indicizzati come PILLARS[i]
STATUS=()
OUTFILES=()
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

overall=0
for p in "${PILLARS[@]}"; do
    script="$SCRIPT_DIR/${p}.sh"
    [[ -x "$script" ]] || chmod +x "$script"
    outfile="$TMPDIR/${p}.out"
    bash "$script" > "$outfile" 2>&1
    rc=$?
    OUTFILES+=("$outfile")
    if (( rc == 0 )); then
        STATUS+=("PASS")
    else
        STATUS+=("FAIL")
        overall=1
    fi
    printf "==== %-15s [%s] ====\n" "$p" "${STATUS[${#STATUS[@]}-1]}"
    cat "$outfile"
    echo
done

REPORT="$SCRIPT_DIR/REPORT.md"
{
    echo "# ZTALeaks — E2E Validation Report (auto-generated)"
    echo
    echo "**Generated**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "**Stack endpoint**: \`${ENVOY_URL:-https://127.0.0.1:8443}\`"
    echo "**Source**: \`tests/e2e/run_all.sh\` su 5 pillar."
    echo
    echo "Questo file viene rigenerato a ogni esecuzione."
    echo
    echo "---"
    echo
    echo "## Summary"
    echo
    echo "| # | Pillar | Status |"
    echo "|---|---|---|"
    for i in "${!PILLARS[@]}"; do
        p="${PILLARS[$i]}"
        case "$p" in
            auth) name="Authentication Flow (login + 2FA)" ;;
            pep)  name="Policy Enforcement Point (Envoy + ext_authz)" ;;
            rbac) name="Role-Based Access Control (OPA)" ;;
            abac) name="Attribute-Based Access (clearance hierarchy)" ;;
            tier) name="3-Tier Admission (cert × TPM)" ;;
            *)    name="$p" ;;
        esac
        emoji="✅"; [[ "${STATUS[$i]}" == "FAIL" ]] && emoji="❌"
        echo "| $((i+1)) | $name | $emoji ${STATUS[$i]} |"
    done
    echo
    if (( overall == 0 )); then
        echo "**Outcome**: tutti i 5 pillar PASS."
    else
        echo "**Outcome**: almeno un pillar è FAIL."
    fi
    echo
    echo "---"
    echo
    echo "## Per-pillar output"
    for i in "${!PILLARS[@]}"; do
        p="${PILLARS[$i]}"
        case "$p" in
            auth) name="Authentication Flow" ;;
            pep)  name="PEP" ;;
            rbac) name="RBAC" ;;
            abac) name="ABAC" ;;
            tier) name="Tier admission" ;;
            *)    name="$p" ;;
        esac
        echo
        echo "### ${name}"
        echo
        echo "- **Script**: \`tests/e2e/${p}.sh\`"
        echo "- **Status**: ${STATUS[$i]}"
        echo
        echo '```'
        sed -E 's/\x1b\[[0-9;]*m//g' "${OUTFILES[$i]}"
        echo '```'
    done
} > "$REPORT"

echo
echo "Report written to: $REPORT"
exit "$overall"
