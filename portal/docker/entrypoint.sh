#!/bin/bash
# DARKVEDA LAB portal entrypoint: first-boot state, then supervisord.
set -e

mkdir -p /opt/portal/data /opt/portal/peers /opt/portal/backups /opt/portal/bot_inbox \
         /opt/mvnbc /var/log/supervisor /DATA/sharelab

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
# NOTE: the smbconf named volume is seeded by the Debian package default
# (Sample configuration ... only [global]/[printers]/[print$], no user
# shares), so a mere "-f" check never fires. If the file has NO user share
# at all (only reserved sections), install the template — otherwise a fresh
# install ends up with GUI "no shares". Custom configs with user shares are
# left untouched (migration below only ensures [sharelab]).
if [ ! -f /etc/samba/smb.conf ]; then
    echo "[portal] installing default smb.conf"
    cp /opt/portal/smb.conf.tmpl /etc/samba/smb.conf
else
    _sections=$(grep -oiE '^[[:space:]]*\[[^]]+\][[:space:]]*$' /etc/samba/smb.conf 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r' || true)
    _user_shares=$(echo "$_sections" | grep -v -E '^\[(global|printers|print\$)\]$' || true)
    if [ -z "$_user_shares" ]; then
        echo "[portal] smb.conf has no user shares (stock Debian default?) — installing template (backup kept)"
        cp -a /etc/samba/smb.conf "/etc/samba/smb.conf.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        cp /opt/portal/smb.conf.tmpl /etc/samba/smb.conf
    fi
fi
# Open access migration: strip any leftover `hosts allow` / `hosts deny` lines
# from previous locked-down versions so Samba is reachable from any IP.
if grep -qiE '^[[:space:]]*hosts[[:space:]]+(allow|deny)[[:space:]]*=' /etc/samba/smb.conf 2>/dev/null; then
    echo "[portal] removing legacy Samba host restrictions (open to any IP)"
    sed -i -E '/^[[:space:]]*hosts[[:space:]]+(allow|deny)[[:space:]]*=/Id' /etc/samba/smb.conf || true
fi
# Default share migration: ensure [sharelab] exists on old volumes that only
# have [lab] (template is only copied on first boot, never clobbered after).
# Legacy [lab] (/DATA/labshare) is removed — it was renamed to [sharelab]
# (/DATA/sharelab, bind-mounted from ./sharelab). Any files left in the old
# named-volume dir are moved over before the old dir is dropped, so the GUI
# "Current Shares" list is never empty after upgrade.
if grep -qiE '^[[:space:]]*\[lab\][[:space:]]*$' /etc/samba/smb.conf 2>/dev/null; then
    echo "[portal] removing legacy [lab] share (renamed to [sharelab])"
    python3 - <<'PY' || true
import re
p = "/etc/samba/smb.conf"
with open(p, encoding="utf-8", errors="replace") as f:
    txt = f.read()
# delete every [lab] section (case-insensitive, exact name only — not [labshare])
txt = re.sub(r"(?mi)^[ \t]*\[lab\][ \t]*\r?\n(?:(?!^[ \t]*\[).*\r?\n?)*", "", txt)
with open(p, "w", encoding="utf-8") as f:
    f.write(txt)
PY
fi
if [ -d /DATA/labshare ] && [ ! -L /DATA/labshare ]; then
    # Migrate stray files from the old named-volume dir into the bind mount,
    # but never overwrite newer files already in /DATA/sharelab.
    if [ -n "$(ls -A /DATA/labshare 2>/dev/null)" ]; then
        echo "[portal] migrating files /DATA/labshare -> /DATA/sharelab"
        mkdir -p /DATA/sharelab
        cp -an /DATA/labshare/. /DATA/sharelab/ 2>/dev/null || true
    fi
    # Drop the legacy dir so only /DATA/sharelab remains (avoids confusion
    # between "labshare" and "sharelab" in the GUI/storage card).
    if [ -z "$(ls -A /DATA/labshare 2>/dev/null)" ]; then
        rmdir /DATA/labshare 2>/dev/null || true
    else
        # Non-empty after copy (e.g. dotfiles) — move remainder then remove.
        cp -an /DATA/labshare/. /DATA/sharelab/ 2>/dev/null || true
        rm -rf /DATA/labshare 2>/dev/null || true
        mkdir -p /DATA/sharelab
    fi
fi
if ! grep -qiE '^[[:space:]]*\[sharelab\][[:space:]]*$' /etc/samba/smb.conf 2>/dev/null; then
    echo "[portal] adding default [sharelab] share (admin RW)"
    cat >> /etc/samba/smb.conf <<'EOF'

[sharelab]
   path = /DATA/sharelab
   comment = DARKVEDA LAB default share
   browseable = yes
   read only = yes
   valid users = admin
   write list = admin
   create mask = 0664
   directory mask = 0775
EOF
fi
testparm -s >/dev/null 2>&1 || { echo "[portal] smb.conf invalid, refusing to start"; exit 1; }

# Samba is reachable from any IP: no firewall sync needed.
# (Old samba-fw.sh lockdown removed; netstack cleans up stale 445/139 rules.)

# Demo Samba account admin/admin (idempotent).
if ! id admin >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin admin || true
fi
if ! pdbedit -L 2>/dev/null | grep -q "^admin:"; then
    echo "[portal] creating samba user admin/admin (CHANGE AFTER FIRST LOGIN)"
    (echo "admin"; echo "admin") | smbpasswd -a -s admin || true
fi

# Default share folder: root:root 2770 + admin RW via inheritable POSIX ACLs,
# so Samba `valid users/write list` AND kernel ACLs both grant admin RW.
mkdir -p /DATA/sharelab
chown 0:0 /DATA/sharelab 2>/dev/null || true
chmod 2770 /DATA/sharelab 2>/dev/null || true
if command -v setfacl >/dev/null 2>&1 && id admin >/dev/null 2>&1; then
    setfacl -m u:admin:rwx /DATA/sharelab 2>/dev/null || true
    setfacl -d -m u:admin:rwx /DATA/sharelab 2>/dev/null || true
fi

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
