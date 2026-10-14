#!/bin/bash
# DARKVEDA LAB portal entrypoint: first-boot state, then supervisord.
set -e

mkdir -p /opt/portal/data /opt/portal/peers /opt/portal/backups /opt/portal/bot_inbox \
         /opt/mvnbc /var/log/supervisor /var/run/frr /DATA/labshare

# Persisted portal state lives in the portaldata volume; link it in.
for f in users.json secret.key traffic.db portal_tabs.json bot_admins.json .bot_offset; do
    if [ ! -e "/opt/portal/$f" ]; then
        ln -sfn "/opt/portal/data/$f" "/opt/portal/$f"
    fi
done

# MVNBC seed (code + example configs) on first boot; user data persists in volume.
if [ ! -f /opt/mvnbc/MVNBC.sh ]; then
    echo "[portal] seeding /opt/mvnbc"
    cp -a /opt/mvnbc-seed/. /opt/mvnbc/
fi

# IPAM DB credentials for the portal's IPAM tab (read by app.py).
if [ -n "${DB_NAME:-}" ]; then
    cat > /opt/ipam.env <<EOF
DB_USER=${DB_USER:-darkveda}
DB_PASS=${DB_PASS:-}
DB_NAME=${DB_NAME:-darkveda_ipam}
EOF
    chmod 600 /opt/ipam.env
fi

# smb.conf from template on first boot (preserved in smbconf volume after).
if [ ! -f /etc/samba/smb.conf ]; then
    echo "[portal] installing default smb.conf"
    cp /opt/portal/smb.conf.tmpl /etc/samba/smb.conf
fi
testparm -s >/dev/null 2>&1 || { echo "[portal] smb.conf invalid, refusing to start"; exit 1; }

# Demo Samba account admin/admin (idempotent).
if ! id admin >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin admin || true
fi
if ! pdbedit -L 2>/dev/null | grep -q "^admin:"; then
    echo "[portal] creating samba user admin/admin (CHANGE AFTER FIRST LOGIN)"
    (echo "admin"; echo "admin") | smbpasswd -a -s admin || true
fi

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
