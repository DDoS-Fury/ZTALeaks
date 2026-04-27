#!/bin/bash
set -e

# Crea la directory di log per il volume
mkdir -p /var/log/firewall
mkdir -p /var/log/ztaleaks/nftables

# Crea il file di log per ulogd preventivamente
touch /var/log/firewall/ulogd-syslogemu.log

# Ensure ownership so ulogd can write if needed
chown -R root:root /var/log/firewall

# Avvia ulogd in background
ulogd -d -c /etc/ulogd.conf

# Sostituisci la porta di Envoy nella configurazione nftables prelevandola dall'ambiente, o usa il fallback 8443
ENVOY_PORT=${ENVOY_PORT:-8443}
sed -i "s/ENV_ENVOY_PORT/$ENVOY_PORT/g" /etc/nftables.conf

# Carica configurazione nftables
# Nota: usiamo delete+add invece di "flush ruleset" per non cancellare
# le regole NAT di Docker (127.0.0.11 DNS) che usano il backend nftables.
echo "Caricamento regole nftables per la porta $ENVOY_PORT..."
nft delete table inet filter 2>/dev/null || true
nft -f /etc/nftables.conf
echo "Regole nftables caricate con successo."

# Leggi in continuo il file di log e avvia il parser json
/usr/local/bin/nftables-parser /var/log/firewall/ulogd-syslogemu.log /var/log/ztaleaks/nftables/firewall.jsonl &
exec tail -F /var/log/firewall/ulogd-syslogemu.log
