#!/usr/bin/env bash
set -e

# Spostiamoci nella cartella certs per usare percorsi relativi
cd "$(dirname "$0")/certs" || exit 1

echo "=========================================================="
echo " Installer Certificati per ZTALeaks (CA + operator1)"
echo "=========================================================="
echo ""

# 1. Installazione tool necessari
echo "[*] Controllo dipendenze libnss3-tools..."
if ! command -v certutil &> /dev/null || ! command -v pk12util &> /dev/null; then
    echo "    -> libnss3-tools mancante. Procedo con l'installazione (richiede sudo)..."
    sudo apt-get update
    sudo apt-get install -y libnss3-tools
else
    echo "    -> libnss3-tools già installato."
fi

# 2. Installazione CA a livello di sistema (per curl, wget, ecc.)
echo ""
echo "[*] Installazione della Root CA a livello di sistema (OS Trust Store)..."
sudo cp ca.crt /usr/local/share/ca-certificates/ztaleaks-ca.crt
sudo update-ca-certificates

# 3. Path dei database NSS dei browser
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

# 4. Importazione nei browser
echo ""
echo "[*] Importazione della CA e del certificato operator1 nei browser..."
for db in "${DB_PATHS[@]}"; do
    echo "    -> Trovato database browser in: $db"
    
    # Importa la Root CA
    certutil -d sql:"$db" -A -t "C,," -n "ZTALeaks Root CA" -i ca.crt || true
    
    # Importa il certificato client operator1
    # Nota: Assumiamo che la password del .p12 sia 'ztaleaks' come da script Python
    pk12util -d sql:"$db" -i operator1.p12 -W "ztaleaks" || true
done

echo ""
echo "=========================================================="
echo " INSTALLAZIONE COMPLETATA!"
echo " Se Firefox o Chrome sono aperti, ricordati di riavviarli."
echo "=========================================================="
