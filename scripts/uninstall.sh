#!/bin/bash
# DARKVEDA LAB — uninstall script (Docker stack + host-net artifacts it created).
# Usage:
#   ./scripts/uninstall.sh [--yes] [--purge-data] [--rm-images] [--keep-host-net] [--force-host-net]
#
# Defaults are SAFE:
#   - stops/removes the compose project in THIS repo (containers + networks),
#   - cleans host kernel artifacts ONLY if no native host unit owns them
#     (wg-quick@wg0, frr, smbd active => skip wg0/br10/iptables, warn instead),
#   - never touches volumes/images unless flagged,
#   - never touches the standalone /root/darkveda-ipam project.
#
# Flags:
#   --yes              skip confirmation prompt
#   --purge-data       also remove this project's named volumes (KEYS + DB + SHARES GONE)
#   --rm-images        also remove built images darkveda-{netstack,portal,ipam}:local
#   --keep-host-net    skip br10/wg0/ns10/iptables cleanup entirely
#   --force-host-net   clean br10/wg0/ns10/iptables even if host units are active (DROPS LIVE VPN/BGP)
set -euo pipefail

YES=0; PURGE=0; IMAGES=0; KEEP_NET=0; FORCE_NET=0
for a in "$@"; do
  case "$a" in
    -y|--yes) YES=1 ;;
    --purge-data) PURGE=1 ;;
    --rm-images) IMAGES=1 ;;
    --keep-host-net) KEEP_NET=1 ;;
    --force-host-net) FORCE_NET=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a (see --help)" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

say() { echo "[uninstall] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

if ! have docker; then echo "docker not found, nothing to do." >&2; exit 1; fi

echo "== DARKVEDA LAB uninstall =="
echo "   root: $ROOT"
echo "   purge-data: $PURGE | rm-images: $IMAGES | keep-host-net: $KEEP_NET | force-host-net: $FORCE_NET"
if [ "$PURGE" = 1 ]; then
  echo "   WARNING: --purge-data deletes WireGuard keys, FRR/Samba state, shares, portal data, DB."
fi
if [ "$FORCE_NET" = 1 ]; then
  echo "   WARNING: --force-host-net will bring down LIVE wg0/br10/iptables if present."
fi
if [ "$YES" != 1 ]; then
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
fi

# --- 1. Compose stack (this repo only) ---
say "stopping compose project (containers + networks)..."
docker compose -p darkvedalab down --remove-orphans 2>/dev/null \
  || docker compose down --remove-orphans || true

# Belt-and-braces: remove known container names if orphaned by another project name
for c in darkveda-netstack darkveda-portal darkveda-ipam darkveda-ipam-db; do
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$c"; then
    say "removing orphan container $c..."
    docker rm -f "$c" || true
  fi
done

# --- 2. Host kernel artifacts created by netstack entrypoint ---
if [ "$KEEP_NET" = 1 ]; then
  say "skipping host-net cleanup (--keep-host-net)."
else
  NATIVE=0
  for u in 'wg-quick@wg0' frr smbd darkveda-lab; do
    if unit_active "$u"; then say "host unit ACTIVE: $u"; NATIVE=1; fi
  done
  if [ "$NATIVE" = 1 ] && [ "$FORCE_NET" != 1 ]; then
    cat <<'EOF'
[uninstall] Native host units own wg0/br10/FRR/Samba (live VPN/BGP likely).
[uninstall] Skipping wg0/br10/ns10/iptables cleanup. Re-run with:
[uninstall]   --keep-host-net    (silence this, leave host net alone), or
[uninstall]   --force-host-net   (take it all down — DROPS live peers/BGP/Samba)
EOF
  else
    say "cleaning host netns artifacts..."
    # WireGuard interface (created via `wg-quick up wg0` in netstack/entrypoint.sh)
    if ip link show wg0 >/dev/null 2>&1; then
      say "bringing down wg0..."
      (wg-quick down wg0 2>/dev/null || ip link del wg0) || true
    fi
    # Lab netns (scripts/ns10-teardown.sh)
    if [ -x "$ROOT/scripts/ns10-teardown.sh" ]; then
      "$ROOT/scripts/ns10-teardown.sh" || true
    else
      ip link del veth10-host 2>/dev/null || true
      ip netns del ns10 2>/dev/null || true
    fi
    # Service bridge (created in netstack/entrypoint.sh with BR10_ADDR)
    if ip link show br10 >/dev/null 2>&1; then
      say "deleting br10..."
      ip link set br10 down 2>/dev/null || true
      ip link del br10 || true
    fi
    # iptables base rules (templates/iptables-rules.v4) — delete exact matches, keep Docker chains
    if have iptables; then
      say "removing lab iptables rules (best-effort, Docker chains kept)..."
      iptables -D INPUT -i lo -p tcp -m multiport --dports 445,139 -j ACCEPT 2>/dev/null || true
      iptables -D INPUT -i br10 -p tcp -m multiport --dports 445,139 -j ACCEPT 2>/dev/null || true
      iptables -D INPUT -i wg0 -p tcp -m multiport --dports 445,139 -j ACCEPT 2>/dev/null || true
      iptables -D INPUT -p tcp -m multiport --dports 445,139 -j DROP 2>/dev/null || true
      iptables -D FORWARD -s 192.168.10.0/24 -i br10 -o wg0 -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -d 192.168.10.0/24 -i wg0 -o br10 -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null || true
      # Per-client MASQUERADE examples some installs add (10.99.0.0/24 via wg0/eth0)
      for net in 10.99.0.0/24 192.168.10.0/24; do
        iptables -t nat -D POSTROUTING -s "$net" -o eth0 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "$net" -o wg0 -j MASQUERADE 2>/dev/null || true
      done
      for ip in 10.99.0.3/32 10.99.0.4/32; do
        iptables -t nat -D POSTROUTING -s "$ip" -o eth0 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s "$ip" -o wg0 -j MASQUERADE 2>/dev/null || true
      done
    fi
  fi
fi

# --- 3. Volumes (opt-in; project-scoped so other stacks are untouched) ---
if [ "$PURGE" = 1 ]; then
  say "removing named volumes (--purge-data)..."
  # Names as created by `docker compose -p darkvedalab` from docker-compose.yml
  for v in wgconf frrconf frrrun smbconf sambadb shares portaldata peers backups bot_inbox mvnbcdata dbdata ipuploads; do
    for name in "darkvedalab_$v" "darkvedalab-$v"; do
      if docker volume inspect "$name" >/dev/null 2>&1; then
        docker volume rm "$name" || true
      fi
    done
  done
else
  say "keeping volumes (re-run with --purge-data to delete keys/DB/shares)."
fi

# --- 4. Images (opt-in) ---
if [ "$IMAGES" = 1 ]; then
  say "removing built images..."
  for i in darkveda-netstack:local darkveda-portal:local darkveda-ipam:local; do
    docker rmi "$i" 2>/dev/null || true
  done
else
  say "keeping images (re-run with --rm-images to delete)."
fi

cat <<'EOF'
== verify ==
  docker ps -a | grep darkveda   # expect empty (this project's containers)
  ip link show br10; ip link show wg0; ip netns list   # expect "does not exist" unless native stack owns them
  iptables -S | grep -E 'br10|wg0|445,139'             # expect empty (unless native kept)
[uninstall] done. Repo files untouched; delete the directory to finish removal.
EOF
