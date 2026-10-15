#!/bin/bash
# DARKVEDA LAB netstack entrypoint: first-boot setup (idempotent).
# Requires: privileged + host networking (manages the host netns).
set -e

WG_ADDR="${WG_ADDR:-10.99.0.1/24}"
WG_PORT="${WG_PORT:-51820}"
BR10_ADDR="${BR10_ADDR:-192.168.10.1/24}"

mkdir -p /etc/wireguard /var/log/supervisor

# --- WireGuard server keys (persisted in wgconf volume) ---
if [ ! -f /etc/wireguard/server_private.key ]; then
    echo "[netstack] generating WireGuard server keys"
    umask 077
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
fi
export WG_PRIVATE_KEY="$(cat /etc/wireguard/server_private.key)"
export WG_ADDR WG_PORT

# --- Render wg0.conf only if missing (never clobber portal edits) ---
if [ ! -f /etc/wireguard/wg0.conf ]; then
    echo "[netstack] rendering wg0.conf (no peers yet — add them in the portal)"
    envsubst < /templates/wg0.conf.tmpl > /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/wg0.conf
fi

# --- Kernel + firewall + bridge (re-applied every boot) ---
# NOTE: NEVER use plain `iptables-restore file` here — it FLUSHES the
# `DOCKER`, `DOCKER-USER`, etc. chains and breaks any bridged container
# created afterwards (db/ipam fail with "Unable to enable DNAT rule ...
# No chain/target/match by that name"). Always append idempotently.
# Firewall is OPEN by design (user request: no blocking): INPUT/FORWARD/
# OUTPUT policies are ACCEPT and no DROP/REJECT rules are installed for
# Samba or forwarding. Docker's own chains are left untouched.
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! ip link show br10 >/dev/null 2>&1; then
    echo "[netstack] creating br10 (${BR10_ADDR})"
    ip link add br10 type bridge
    ip addr add "${BR10_ADDR}" dev br10
fi
ip link set br10 up
echo "[netstack] applying open firewall (no blocking, preserves Docker chains)"
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true
# Cleanup: remove any leftover restrictive rules from previous versions
# (Samba lockdown + lab FORWARD allowlist — redundant now that policies are ACCEPT).
for _spec in "-p tcp -m multiport --dports 445,139 -j DROP" \
             "-i lo -p tcp -m multiport --dports 445,139 -j ACCEPT" \
             "-i br10 -p tcp -m multiport --dports 445,139 -j ACCEPT" \
             "-i wg0 -p tcp -m multiport --dports 445,139 -j ACCEPT"; do
    # shellcheck disable=SC2086
    while iptables -C INPUT $_spec 2>/dev/null; do iptables -D INPUT $_spec 2>/dev/null || break; done
done
for _spec in "-s 192.168.10.0/24 -i br10 -o wg0 -j ACCEPT" \
             "-d 192.168.10.0/24 -i wg0 -o br10 -j ACCEPT" \
             "-i wg0 -o eth0 -j ACCEPT" \
             "-i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT" \
             "-i wg0 -o wg0 -j ACCEPT"; do
    # shellcheck disable=SC2086
    while iptables -C FORWARD $_spec 2>/dev/null; do iptables -D FORWARD $_spec 2>/dev/null || break; done
done
# Remove legacy lab netns (ns10/veth10) if left over from previous versions.
ip link del veth10-host 2>/dev/null || true
ip netns del ns10 2>/dev/null || true

# --- WireGuard interface ---
if ! wg show wg0 >/dev/null 2>&1; then
    echo "[netstack] bringing up wg0"
    wg-quick up wg0 || echo "[netstack] WARNING: wg-quick up failed (check wg0.conf)"
fi

echo "[netstack] public key: $(cat /etc/wireguard/server_public.key)"
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
