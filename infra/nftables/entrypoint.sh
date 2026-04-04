#!/bin/bash
set -e

# Avvia syslog per avere i log di nftables sul frontend Docker
syslogd -n -O /dev/stdout &

# Carica configurazione nftables
echo "Caricamento regole nftables..."
nft -f /etc/nftables.conf
echo "Regole nftables caricate con successo."

# Mantieni vivo il container
exec sleep infinity
