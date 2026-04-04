#!/bin/bash
set -e

# Crea il file di log per ulogd preventivamente
touch /var/log/ulogd-syslogemu.log

# Avvia ulogd in background
ulogd -d -c /etc/ulogd.conf

# Carica configurazione nftables
echo "Caricamento regole nftables..."
nft -f /etc/nftables.conf
echo "Regole nftables caricate con successo."

# Leggi in continuo il file di log per stampare sullo stdout del container (utile a Splunk/Docker logs)
exec tail -F /var/log/ulogd-syslogemu.log
