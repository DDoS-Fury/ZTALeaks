#!/bin/bash
set -e

# Crea il file di log per ulogd preventivamente
touch /var/log/ulogd-syslogemu.log

# Avvia ulogd in background
ulogd -d -c /etc/ulogd.conf

# Sostituisci la porta di Envoy nella configurazione nftables prelevandola dall'ambiente, o usa il fallback 8443
ENVOY_PORT=${ENVOY_PORT:-8443}
sed -i "s/ENV_ENVOY_PORT/$ENVOY_PORT/g" /etc/nftables.conf

# Carica configurazione nftables
echo "Caricamento regole nftables per la porta $ENVOY_PORT..."
nft -f /etc/nftables.conf
echo "Regole nftables caricate con successo."

# Leggi in continuo il file di log per stampare sullo stdout del container (utile a Splunk/Docker logs)
exec tail -F /var/log/ulogd-syslogemu.log
