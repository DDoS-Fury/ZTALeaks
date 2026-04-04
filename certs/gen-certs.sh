#!/usr/bin/env bash
set -euo pipefail

# Compatibilità Git Bash
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

OUT="$(cd "$(dirname "$0")" && pwd)"
if command -v cygpath &>/dev/null; then
  OUT="$(cygpath -w "$OUT")"
fi

DAYS=3650
EXT="${OUT}/openssl-ext-tmp.cnf"
trap 'rm -f "$EXT"' EXIT

echo "==> Pulizia certificati precedenti..."
rm -f "$OUT"/*.crt "$OUT"/*.key "$OUT"/*.csr "$OUT"/*.srl

# ---------------------------------------------------------
# 1. ROOT CA (La tua Autorità di Certificazione)
# ---------------------------------------------------------
echo "==> Generazione Root CA..."
openssl genrsa -out "$OUT/ca.key" 4096

# NOTA: Il CN della CA deve essere diverso da quello del server
openssl req -x509 -new -nodes \
  -key "$OUT/ca.key" \
  -sha256 -days "$DAYS" \
  -out "$OUT/ca.crt" \
  -subj "/C=IT/O=ZTA-Leaks/CN=ZTA-Internal-Root-CA"

# ---------------------------------------------------------
# 2. CERTIFICATO SERVER (Per Envoy)
# ---------------------------------------------------------
echo "==> Generazione Certificato Server per Envoy..."
openssl genrsa -out "$OUT/server.key" 2048

# Il CN qui può essere ztaleaks_envoy
openssl req -new \
  -key "$OUT/server.key" \
  -out "$OUT/server.csr" \
  -subj "/C=IT/O=ZTA-Leaks/CN=ztaleaks_envoy"

# IMPORTANTE: Il SAN deve contenere il nome host usato nell'URL di Go
printf "subjectAltName=DNS:ztaleaks_envoy,DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > "$EXT"

openssl x509 -req \
  -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" \
  -CAcreateserial \
  -out "$OUT/server.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

# ---------------------------------------------------------
# 3. CERTIFICATO CLIENT (Se Envoy richiede mTLS)
# ---------------------------------------------------------
echo "==> Generazione Certificato Client..."
openssl genrsa -out "$OUT/client.key" 2048

openssl req -new \
  -key "$OUT/client.key" \
  -out "$OUT/client.csr" \
  -subj "/C=IT/O=ZTA-Leaks/CN=client-test"

printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > "$EXT"

openssl x509 -req \
  -in "$OUT/client.csr" \
  -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" \
  -CAcreateserial \
  -out "$OUT/client.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

echo "==> Fatto! I file generati sono nella cartella $OUT"

: <<'EOF'
# ─────────────────────────────────────────────────────────
# 2. CA ESTERNA (simulata localmente)
# ─────────────────────────────────────────────────────────
echo "==> Generazione CA esterna (simulata)..."
openssl genrsa -out "$OUT/ca-external.key" 4096

openssl req -x509 -new -nodes \
  -key "$OUT/ca-external.key" \
  -sha256 -days "$DAYS" \
  -out "$OUT/ca-external.crt" \
  -subj "/C=IT/O=ExternalOrg/CN=External Root CA"

# Certificato SERVER per external.example.local
echo "==> Certificato server esterno (external.example.local)..."
openssl genrsa -out "$OUT/server-external.key" 2048

openssl req -new \
  -key "$OUT/server-external.key" \
  -out "$OUT/server-external.csr" \
  -subj "/C=IT/O=ExternalOrg/CN=external.example.local"

printf "subjectAltName=DNS:external.example.local\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > "$EXT"
openssl x509 -req \
  -in "$OUT/server-external.csr" \
  -CA "$OUT/ca-external.crt" \
  -CAkey "$OUT/ca-external.key" \
  -CAcreateserial \
  -out "$OUT/server-external.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

# Certificato CLIENT firmato dalla CA esterna
echo "==> Certificato client esterno..."
openssl genrsa -out "$OUT/client-external.key" 2048

openssl req -new \
  -key "$OUT/client-external.key" \
  -out "$OUT/client-external.csr" \
  -subj "/C=IT/O=ExternalOrg/CN=external-client"

printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > "$EXT"
openssl x509 -req \
  -in "$OUT/client-external.csr" \
  -CA "$OUT/ca-external.crt" \
  -CAkey "$OUT/ca-external.key" \
  -CAcreateserial \
  -out "$OUT/client-external.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

echo ""
echo "Certificati generati in: $OUT"
echo ""
echo "File creati:"
ls -1 "$OUT"/*.crt "$OUT"/*.key | xargs -I{} basename {}

EOF