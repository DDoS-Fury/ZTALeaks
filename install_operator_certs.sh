#!/usr/bin/env bash
# Se lanciato con `sh script.sh` (dash non supporta gli array), rilancia in bash.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
set -euo pipefail

# Installer certificati ZTALeaks: rigenera CA + cert client, rimuove i vecchi
# dal trust store di sistema e dai browser, importa i nuovi.
CERTS_DIR="$(cd "$(dirname "$0")/certs" && pwd)"
CLIENT_USERS=("admin" "manager1" "operator1")
P12_PASSWORD="ztaleaks"

echo "=========================================================="
echo " Installer Certificati ZTALeaks (CA + ${CLIENT_USERS[*]})"
echo "=========================================================="
echo ""

# 1. Dipendenze
echo "[*] Controllo dipendenze..."
if ! command -v certutil &> /dev/null || ! command -v pk12util &> /dev/null; then
    echo "    -> libnss3-tools mancante. Procedo con l'installazione (richiede sudo)..."
    sudo apt-get update
    sudo apt-get install -y libnss3-tools
else
    echo "    -> libnss3-tools già installato."
fi
if ! python3 -c "import cryptography" &> /dev/null; then
    echo "ERRORE: la libreria Python 'cryptography' non è installata."
    echo "Installala con: pip install cryptography"
    exit 1
fi

# 2. Rigenerazione certificati (CA, server, client) + bundle .p12 per i browser
echo ""
echo "[*] Rigenerazione certificati con certs/gen-certs.sh..."
bash "$CERTS_DIR/gen-certs.sh"

echo ""
echo "[*] Generazione bundle PKCS#12 per i browser..."
rm -f "$CERTS_DIR"/*.p12 "$CERTS_DIR"/*.pfx
for user in "${CLIENT_USERS[@]}"; do
    python3 "$CERTS_DIR/create_browser_cert.py" "$user" > /dev/null
    echo "    -> ${user}.p12 creato."
done

# 3. Trust store di sistema: rimuovi la vecchia CA e installa la nuova
echo ""
echo "[*] Aggiornamento Root CA nel trust store di sistema (richiede sudo)..."
sudo rm -f /usr/local/share/ca-certificates/ztaleaks-ca.crt
sudo cp "$CERTS_DIR/ca.crt" /usr/local/share/ca-certificates/ztaleaks-ca.crt
sudo update-ca-certificates

# 4. Database NSS dei browser
DB_PATHS=()

# Chrome/Chromium/Brave/Edge (Linux)
if [ -d "$HOME/.pki/nssdb" ]; then
    DB_PATHS+=("$HOME/.pki/nssdb")
fi

# Firefox (Snap o Deb)
for dir in "$HOME/.mozilla/firefox/"* "$HOME/snap/firefox/common/.mozilla/firefox/"*; do
    if [ -d "$dir" ] && [ -f "$dir/cert9.db" ]; then
        DB_PATHS+=("$dir")
    fi
done

if [ ${#DB_PATHS[@]} -eq 0 ]; then
    echo ""
    echo "ATTENZIONE: nessun database browser NSS trovato. Importa i .p12 a mano."
fi

# Elimina dal database ogni certificato ZTALeaks precedente (CA e client),
# inclusi eventuali duplicati con lo stesso nickname.
remove_old_zta_certs() {
    local db="$1"
    certutil -d sql:"$db" -L 2>/dev/null \
        | sed -E 's/[[:space:]]+[A-Za-z]*,[A-Za-z]*,[A-Za-z]*[[:space:]]*$//' \
        | grep -i 'ZTA' \
        | while IFS= read -r nick; do
            while certutil -d sql:"$db" -D -n "$nick" 2>/dev/null; do
                echo "    -> Rimosso vecchio certificato: \"$nick\""
            done
        done || true
}

echo ""
echo "[*] Pulizia vecchi certificati e importazione dei nuovi nei browser..."
for db in "${DB_PATHS[@]}"; do
    echo "    -> Database browser: $db"

    remove_old_zta_certs "$db"

    # Importa la nuova Root CA
    certutil -d sql:"$db" -A -t "C,," -n "ZTALeaks Root CA" -i "$CERTS_DIR/ca.crt"

    # Importa i certificati client (nickname per-utente, vedi create_browser_cert.py)
    for user in "${CLIENT_USERS[@]}"; do
        pk12util -d sql:"$db" -i "$CERTS_DIR/${user}.p12" -W "$P12_PASSWORD" || true
    done
done

echo ""
echo "=========================================================="
echo " INSTALLAZIONE COMPLETATA!"
echo " Certificati client installati: ${CLIENT_USERS[*]}"
echo " Riavvia il browser se era aperto. Ricorda anche di"
echo " rilanciare il seeder/ricreare il volume del security-db"
echo " se gli utenti hanno ancora i ruoli vecchi."
echo "=========================================================="
