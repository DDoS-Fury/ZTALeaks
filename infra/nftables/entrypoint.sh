#!/bin/bash
# =============================================================================
# nftables Firewall - Container Entrypoint
#
# Responsibilities:
#   1. Create log directories and seed the ulogd log file.
#   2. Start ulogd in the background (kernel NFLOG -> syslogemu file).
#   3. Resolve the Envoy port and the front-net interface at runtime,
#      then substitute placeholders in nftables.conf.
#   4. Load the nftables ruleset (delete+add instead of flush to preserve
#      Docker's internal NAT rules for the embedded DNS resolver).
#   5. Launch the Go log parser in the background to convert the ulogd
#      syslogemu output to structured JSONL for Splunk.
#   6. Tail the raw ulogd log file as the foreground process.
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# 1. Prepare log directories and seed the ulogd log file
# -----------------------------------------------------------------------------
mkdir -p /var/log/firewall
mkdir -p /var/log/ztaleaks/nftables

# Create the file upfront so ulogd can open it even before the first packet
touch /var/log/firewall/ulogd-syslogemu.log

# Ensure root owns the firewall log directory
chown -R root:root /var/log/firewall

# -----------------------------------------------------------------------------
# 2. Start ulogd in the background
# -----------------------------------------------------------------------------
ulogd -d -c /etc/ulogd.conf

# -----------------------------------------------------------------------------
# 3. Substitute runtime placeholders in nftables.conf
# -----------------------------------------------------------------------------

# Resolve the Envoy listening port (default: 8443)
ENVOY_PORT=${ENVOY_PORT:-8443}
sed -i "s/ENV_ENVOY_PORT/$ENVOY_PORT/g" /etc/nftables.conf

# Resolve the network interface attached to the front-net segment.
# Docker assigns interface names (eth0, eth1, ...) alphabetically by network
# name, so the front-net interface is not necessarily eth0. We identify it by
# its subnet, which is pinned in the Compose file.
# Without a correct interface, the external Snort instance would inspect the
# wrong network segment.
FRONT_NET_SUBNET=${FRONT_NET_SUBNET:-172.30.0.0/24}
FRONT_IFACE=$(ip -o -4 addr show to "$FRONT_NET_SUBNET" | awk '{print $2; exit}')

if [ -z "$FRONT_IFACE" ]; then
    echo "ERROR: no interface found for subnet $FRONT_NET_SUBNET" >&2
    ip -o -4 addr show >&2
    exit 1
fi

echo "Front-net interface resolved: $FRONT_IFACE (subnet $FRONT_NET_SUBNET)"
sed -i "s/ENV_FRONT_IFACE/$FRONT_IFACE/g" /etc/nftables.conf

# -----------------------------------------------------------------------------
# 4. Load the nftables ruleset
#
# We use delete+add instead of "flush ruleset" to avoid wiping Docker's NAT
# rules for the internal DNS resolver (127.0.0.11), which also uses the
# nftables backend.
# -----------------------------------------------------------------------------
echo "Loading nftables rules for port $ENVOY_PORT ..."
nft delete table inet filter 2>/dev/null || true
nft -f /etc/nftables.conf
echo "nftables rules loaded successfully."

# -----------------------------------------------------------------------------
# 5. Start the Go log parser in the background
#    Reads the ulogd syslogemu file and writes structured JSONL for Splunk.
# -----------------------------------------------------------------------------
/usr/local/bin/nftables-parser \
    /var/log/firewall/ulogd-syslogemu.log \
    /var/log/ztaleaks/nftables/firewall.jsonl &

# -----------------------------------------------------------------------------
# 6. Tail the raw log file as the foreground process (keeps the container alive
#    and streams firewall events to Docker logs).
# -----------------------------------------------------------------------------
exec tail -F /var/log/firewall/ulogd-syslogemu.log