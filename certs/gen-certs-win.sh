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
rm -f "$OUT"/*.crt "$OUT"/*.key "$OUT"/*.csr "$OUT"/*.srl "$OUT"/*.p12 "$OUT"/*.pfx

# ---------------------------------------------------------
# 1. ROOT CA (Autorità di Certificazione)
# ---------------------------------------------------------
echo "==> Generazione Root CA..."
openssl genrsa -out "$OUT/ca.key" 4096

# Il CN della CA deve essere diverso da quello del server
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

openssl req -new \
  -key "$OUT/server.key" \
  -out "$OUT/server.csr" \
  -subj "/C=IT/O=ZTA-Leaks/CN=ztaleaks_envoy"

# Il SAN deve contenere il nome host usato nell'URL
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
# 3. CERTIFICATI CLIENT mTLS (CN=username, OU=ruolo)
# ---------------------------------------------------------
gen_client_cert() {
  local username="$1" role="$2"
  echo "==> Generazione Certificati Client per ${username} (OU=${role})..."
  openssl genrsa -out "$OUT/${username}.key" 2048

  openssl req -new \
    -key "$OUT/${username}.key" \
    -out "$OUT/${username}.csr" \
    -subj "/C=IT/O=ZTA-Leaks/CN=${username}/OU=${role}"

  printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > "$EXT"

  openssl x509 -req \
    -in "$OUT/${username}.csr" \
    -CA "$OUT/ca.crt" \
    -CAkey "$OUT/ca.key" \
    -CAcreateserial \
    -out "$OUT/${username}.crt" \
    -days "$DAYS" -sha256 \
    -extfile "$EXT"

  echo "==> Generazione file .p12 (Windows) e .pfx (Mac) per ${username}..."
  # Impostiamo la password ztaleaks per l'importazione
  openssl pkcs12 -export \
    -out "$OUT/${username}.p12" \
    -inkey "$OUT/${username}.key" \
    -in "$OUT/${username}.crt" \
    -certfile "$OUT/ca.crt" \
    -passout pass:ztaleaks \
    -name "ZTALeaks ${username}"

  cp "$OUT/${username}.p12" "$OUT/${username}-apple.pfx"
}

# Generiamo i certificati per i vari utenti
gen_client_cert "admin" "admin"
gen_client_cert "manager1" "manager"
gen_client_cert "operator1" "operator"

# ---------------------------------------------------------
# 4. RICOSTRUZIONE ENVOY
# ---------------------------------------------------------
echo "==> Ricostruzione e riavvio di Envoy con i nuovi certificati..."
if [ -d "$OUT/../deployments/docker" ]; then
  cd "$OUT/../deployments/docker"
  # In base all'installazione di docker, si tenta di usare il comando corretto
  if command -v docker.exe &>/dev/null; then
    docker.exe compose up -d --build envoy
  elif docker compose version &>/dev/null; then
    docker compose up -d --build envoy
  elif command -v docker-compose &>/dev/null; then
    docker-compose up -d --build envoy
  else
    echo "ATTENZIONE: Nessun comando docker compose trovato. Impossibile riavviare Envoy automaticamente."
  fi
else
  echo "ATTENZIONE: Cartella deployments/docker non trovata in $OUT/.."
fi

echo "==> Fatto! I file generati sono nella cartella $OUT"