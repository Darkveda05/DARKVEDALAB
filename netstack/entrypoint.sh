#!/bin/bash
# DARKVEDA LAB netstack entrypoint: first-boot setup (idempotent), then FRR.
# Requires: privileged + host networking (manages the host netns).
set -e

WG_ADDR="${WG_ADDR:-10.99.0.1/24}"
WG_PORT="${WG_PORT:-51820}"
BR10_ADDR="${BR10_ADDR:-192.168.10.1/24}"
BGP_AS="${BGP_AS:-65001}"
BGP_PEER="${BGP_PEER:-10.99.0.2}"
BGP_PEER_AS="${BGP_PEER_AS:-65002}"
BGP_ROUTER_ID="${BGP_ROUTER_ID:-10.99.0.1}"
ORIGIN_NET="${ORIGIN_NET:-192.168.10.0/24}"
HOME_NETS="${HOME_NETS:-172.16.0.0/24,172.16.10.0/24,172.16.20.0/24,172.16.30.0/24,172.16.100.0/24}"

mkdir -p /etc/wireguard /etc/frr /var/run/frr /var/log/supervisor

# --- WireGuard server keys (persisted in wgconf volume) ---
if [ ! -f /etc/wireguard/server_private.key ]; then
    echo "[netstack] generating WireGuard server keys"
    umask 077
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
fi
export WG_PRIVATE_KEY="$(cat /etc/wireguard/server_private.key)"
export WG_ADDR WG_PORT

# --- Prefix-lists from env (comma-separated CIDRs) ---
HOME_IN_RULES=""
i=10
for net in $(echo "$HOME_NETS" | tr ',' ' '); do
    HOME_IN_RULES="${HOME_IN_RULES}ip prefix-list HOME-IN seq $i permit $net
"
    i=$((i + 1))
done
VPS_OUT_RULES="ip prefix-list VPS-OUT seq 10 permit ${ORIGIN_NET}"
export HOME_IN_RULES VPS_OUT_RULES

# --- Render configs only if missing (never clobber portal edits) ---
if [ ! -f /etc/wireguard/wg0.conf ]; then
    echo "[netstack] rendering wg0.conf (no peers yet — add them in the portal)"
    envsubst < /templates/wg0.conf.tmpl > /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/wg0.conf
fi
if [ ! -f /etc/frr/frr.conf ]; then
    echo "[netstack] rendering frr.conf"
    export BGP_AS BGP_PEER BGP_PEER_AS BGP_ROUTER_ID ORIGIN_NET HOME_NETS
    envsubst < /templates/frr.conf.tmpl > /etc/frr/frr.conf
fi
chown -R frr:frr /etc/frr /var/run/frr 2>/dev/null || chown -R root:root /etc/frr /var/run/frr

# --- Kernel + firewall + bridge (re-applied every boot) ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! ip link show br10 >/dev/null 2>&1; then
    echo "[netstack] creating br10 (${BR10_ADDR})"
    ip link add br10 type bridge
    ip addr add "${BR10_ADDR}" dev br10
fi
ip link set br10 up
if [ -f /templates/iptables-rules.v4 ]; then
    echo "[netstack] restoring iptables base rules"
    iptables-restore /templates/iptables-rules.v4 || echo "[netstack] WARNING: iptables-restore had errors"
fi
/usr/local/sbin/ns10-setup.sh || echo "[netstack] WARNING: ns10 setup failed (non-fatal)"

# --- WireGuard interface ---
if ! wg show wg0 >/dev/null 2>&1; then
    echo "[netstack] bringing up wg0"
    wg-quick up wg0 || echo "[netstack] WARNING: wg-quick up failed (check wg0.conf)"
fi

echo "[netstack] public key: $(cat /etc/wireguard/server_public.key)"
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
