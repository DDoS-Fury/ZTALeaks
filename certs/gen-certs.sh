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
# 3. CERTIFICATO CLIENT ADMIN (Se Envoy richiede mTLS)
# ---------------------------------------------------------
echo "==> Generazione Certificato Client..."
openssl genrsa -out "$OUT/admin.key" 2048

openssl req -new \
  -key "$OUT/admin.key" \
  -out "$OUT/admin.csr" \
  -subj "/C=IT/O=ZTA-Leaks/CN=admin/OU=plant_manager"

printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > "$EXT"

openssl x509 -req \
  -in "$OUT/admin.csr" \
  -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" \
  -CAcreateserial \
  -out "$OUT/admin.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

echo "==> Fatto! I file generati sono nella cartella $OUT"

# ---------------------------------------------------------
# 4. CERTIFICATO CLIENT USER (Se Envoy richiede mTLS)
# ---------------------------------------------------------
echo "==> Generazione Certificato Client..."
openssl genrsa -out "$OUT/operator1.key" 2048

openssl req -new \
  -key "$OUT/operator1.key" \
  -out "$OUT/operator1.csr" \
  -subj "/C=IT/O=ZTA-Leaks/CN=operator1/OU=operator"

printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > "$EXT"

openssl x509 -req \
  -in "$OUT/operator1.csr" \
  -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" \
  -CAcreateserial \
  -out "$OUT/operator1.crt" \
  -days "$DAYS" -sha256 \
  -extfile "$EXT"

echo "==> Fatto! I file generati sono nella cartella $OUT"