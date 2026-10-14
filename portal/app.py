#!/usr/bin/env python3
"""
WireGuard Tunnel Monitor - Darkveda Lab
Secure login portal: http://<IP>:8090/

Security:
- scrypt password hashing (Werkzeug)
- Signed session cookies (HttpOnly, SameSite=Strict)
- Brute-force lockout: 5 fails = 15 min lockout
- CSRF token on password change
- All data routes require auth
"""

import subprocess
import time
import re
import json
import os
import secrets
import threading
import ipaddress
import shutil
import zipfile
import sqlite3
from datetime import datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo
    MYTZ = ZoneInfo("Asia/Kuala_Lumpur")
except Exception:
    MYTZ = timezone(timedelta(hours=8))
MYTZ_NAME = "Asia/Kuala_Lumpur"

def _myfmt(ts, fmt="%Y-%m-%d %H:%M:%S"):
    try:
        return datetime.fromtimestamp(ts, tz=MYTZ).strftime(fmt)
    except Exception:
        return datetime.fromtimestamp(ts).strftime(fmt)

def _myt_now(fmt="%Y-%m-%d %H:%M:%S"):
    try:
        return datetime.now(MYTZ).strftime(fmt)
    except Exception:
        return datetime.now().strftime(fmt)

from functools import wraps
from flask import (
    Flask, render_template_string, jsonify, session,
    request, redirect, url_for, abort, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")

# ---------------- WG traffic history (sqlite, 30s samples, 7d retention) ----------------
TRAFFIC_DB = os.path.join(BASE_DIR, "traffic.db")

# ---------------- IPAM (darkveda-ipam MariaDB, read + create subnets) ----------------
import pymysql as _pymysql
_IPAM_CACHE = {"t": 0, "data": None}
_IPAM_TTL = 10

def _ipam_env():
    env = {}
    # Container-friendly: IPAM_ENV_FILE (default keeps historic host path).
    env_file = os.environ.get("IPAM_ENV_FILE", "/root/darkveda-ipam/.env")
    try:
        with open(env_file, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                env[k.strip()] = v.strip()
    except Exception:
        pass
    return env

def _ipam_conn():
    env = _ipam_env()
    # Container-friendly: IPAM_DB_HOST (docker compose sets 127.0.0.1 via the
    # published db port). Otherwise historic host behaviour is unchanged.
    host = os.environ.get("IPAM_DB_HOST")
    if not host:
        host = "172.21.0.2"
        try:
            import subprocess as _sp
            out = _sp.run(["docker", "inspect", "darkveda-ipam-db", "--format",
                           "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                          capture_output=True, text=True, timeout=5)
            ip = (out.stdout or "").strip().split()[0] if out.stdout else ""
            if ip:
                host = ip
        except Exception:
            pass
    return _pymysql.connect(host=host, port=3306, user=env.get("DB_USER", "darkveda"),
                            password=env.get("DB_PASS", ""), database=env.get("DB_NAME", "darkveda_ipam"),
                            connect_timeout=5, autocommit=True)

def _ipam_subnet_stats():
    """Per-subnet used/total + utilization, computed from ip_addresses."""
    c = _ipam_conn()
    try:
        cur = c.cursor()
        cur.execute("""SELECT s.id, s.cidr, s.name, s.gateway, s.status, s.description,
                              st.name AS site, v.name AS vlan
                       FROM subnets s
                       LEFT JOIN sites st ON st.id=s.site_id
                       LEFT JOIN vlans v ON v.id=s.vlan_id
                       ORDER BY s.cidr""")
        rows = cur.fetchall()
        out = []
        for sid, cidr, name, gw, status, desc, site, vlan in rows:
            try:
                import ipaddress as _ip
                net = _ip.ip_network(cidr, strict=False)
                total = net.num_addresses
                if net.version == 4 and net.prefixlen <= 30:
                    total = max(total - 2, 1)
            except Exception:
                total = 0
            cur.execute("SELECT COUNT(*) FROM ip_addresses WHERE subnet_id=%s AND status NOT IN ('deprecated','decommissioned')", (sid,))
            used = cur.fetchone()[0] if cur.rowcount is not None else 0
            free = max((total or 0) - (used or 0), 0)
            pct = round(used * 100 / total, 1) if total else 0
            out.append({"id": sid, "cidr": cidr, "name": name, "gateway": gw, "status": status,
                        "description": desc, "site": site, "vlan": vlan,
                        "used": used, "total": total, "free": free, "pct": pct})
        return out
    finally:
        try:
            c.close()
        except Exception:
            pass

def _ipam_summary_cached():
    import time as _t
    now = _t.time()
    if _IPAM_CACHE["data"] is not None and (now - _IPAM_CACHE["t"]) < _IPAM_TTL:
        return _IPAM_CACHE["data"]
    subs = _ipam_subnet_stats()
    c = _ipam_conn()
    try:
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM vlans"); vlans = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM devices"); devs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM ip_conflicts WHERE resolved=0"); conflicts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM discovered_hosts WHERE adopted=0"); unadopted = cur.fetchone()[0]
    finally:
        try:
            c.close()
        except Exception:
            pass
    data = {"ok": True, "subnets": subs, "counts": {"subnets": len(subs), "vlans": vlans,
            "devices": devs, "conflicts": conflicts, "unadopted": unadopted}}
    _IPAM_CACHE["data"] = data
    _IPAM_CACHE["t"] = now
    return data


_TRAFFIC_LOCK = threading.Lock()

def traffic_db():
    try:
        c = sqlite3.connect(TRAFFIC_DB, timeout=10)
        c.execute("PRAGMA journal_mode=WAL")
        try:
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA wal_autocheckpoint=500")
        except Exception:
            pass
        c.execute("""CREATE TABLE IF NOT EXISTS wg_traffic(
            ts INTEGER NOT NULL, iface TEXT NOT NULL, peer TEXT NOT NULL,
            rx INTEGER NOT NULL, tx INTEGER NOT NULL,
            PRIMARY KEY(ts, iface, peer))""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_traffic_peer_ts ON wg_traffic(peer, ts)")
        c.commit()
        return c
    except Exception:
        return None

def traffic_tick():
    """One 30s sample: insert cumulative counters per peer. Returns rows inserted."""
    try:
        wg = parse_wg_show()
    except Exception:
        return 0
    ts = int(time.time())
    rows = []
    for iface in (wg.get("interfaces") or []):
        for p in (iface.get("peers") or []):
            rows.append((ts, iface.get("name",""), p.get("public_key",""), int(p.get("transfer_rx") or 0), int(p.get("transfer_tx") or 0)))
    if not rows:
        return 0
    c = traffic_db()
    if not c:
        return 0
    try:
        with _TRAFFIC_LOCK:
            c.executemany("INSERT OR REPLACE INTO wg_traffic(ts,iface,peer,rx,tx) VALUES(?,?,?,?,?)", rows)
            c.execute("DELETE FROM wg_traffic WHERE ts < ?", (ts - 7*86400,))
            c.commit()
    except Exception:
        try:
            c.rollback()
        except Exception:
            pass
        return 0
    finally:
        try:
            c.close()
        except Exception:
            pass
    return len(rows)

def traffic_collector():
    while True:
        try:
            traffic_tick()
        except Exception:
            pass
        time.sleep(30)

# start collector once at boot
try:
    _t = threading.Thread(target=traffic_collector, daemon=True)
    _t.start()
except Exception:
    pass

# ---- perf: cached heavy subprocess calls ----
_BGP_CACHE = {"t": 0, "data": None}
_BGP_TTL = 30

_SMB_CACHE = {"t": 0, "data": None}
_SMB_TTL = 15

def bgp_correlation_cached():
    now = time.time()
    if _BGP_CACHE["data"] is not None and (now - _BGP_CACHE["t"]) < _BGP_TTL:
        return _BGP_CACHE["data"]
    try:
        data = bgp_correlation()
        _BGP_CACHE["data"] = data
        _BGP_CACHE["t"] = now
        return data
    except Exception:
        if _BGP_CACHE["data"] is not None:
            return _BGP_CACHE["data"]
        return {"local_as": None, "router_id": None, "received_count": 0, "advertised_count": 0, "rows": [], "error": "bgp fetch failed"}


# ---------------- Auth core ----------------

def load_secret():
    """Persisted random secret key for session signing."""
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    key = secrets.token_hex(32).encode()
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key

app.secret_key = load_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,   # set True if you put it behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(users):
    fd = os.open(USERS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(users, f, indent=2)

# First boot: create default admin if no users exist.
# DARKVEDA LAB demo build: admin/admin for easy first access.
# *** CHANGE THIS IMMEDIATELY after first login (Setting is not enough —
# use /password): this default is intentionally weak for demo sharing. ***
if not load_users():
    save_users({"admin": generate_password_hash("admin", method="scrypt")})

# Brute-force protection: {key: [fail_count, lock_until_ts]}
_locks = {}
_locks_lock = threading.Lock()
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60

def is_locked(key):
    with _locks_lock:
        rec = _locks.get(key)
        if not rec:
            return 0
        fails, until = rec
        if until and time.time() < until:
            return int(until - time.time())
        if until and time.time() >= until:
            del _locks[key]
        return 0

def register_fail(key):
    with _locks_lock:
        fails, until = _locks.get(key, (0, 0))
        fails += 1
        until_ts = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
        _locks[key] = (fails, until_ts)
        return fails, until_ts

def clear_fails(key):
    with _locks_lock:
        _locks.pop(key, None)

def client_key():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
    user = (request.form.get("username") or "").strip().lower()
    return f"{ip}|{user}"

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

def check_csrf():
    token = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf"):
        abort(400, description="CSRF token mismatch")

# ---------------- WG config management ----------------

WG_CONF = "/etc/wireguard/wg0.conf"
WG_IFACE = "wg0"

def validate_cidr_list(raw):
    """Parse comma/space/newline separated CIDRs. Returns (list[str], error|None)."""
    tokens = [t.strip() for t in re.split(r"[,\s]+", raw or "") if t.strip()]
    if not tokens:
        return None, "AllowedIPs list is empty."
    seen, clean = set(), []
    for tok in tokens:
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            return None, f"Invalid CIDR: {tok}"
        s = str(net)
        if s not in seen:
            seen.add(s)
            clean.append(s)
    try:
        clean.sort(key=lambda c: (ipaddress.ip_network(c).version,
                                  int(ipaddress.ip_network(c).network_address),
                                  ipaddress.ip_network(c).prefixlen))
    except ValueError:
        pass
    return clean, None

def read_allowed_ips():
    """Read current AllowedIPs from wg0.conf."""
    try:
        with open(WG_CONF) as f:
            txt = f.read()
    except OSError as e:
        return None, f"Cannot read {WG_CONF}: {e}"
    m = re.search(r"^\s*AllowedIPs\s*=\s*(.+)$", txt, re.M)
    if not m:
        return None, "AllowedIPs line not found in wg0.conf"
    cidrs, err = validate_cidr_list(m.group(1))
    if err:
        return None, f"Existing config has invalid entry: {err}"
    return cidrs, None

def write_allowed_ips(cidrs):
    """Backup, update AllowedIPs in wg0.conf atomically, apply live. Returns (ok, msg)."""
    try:
        with open(WG_CONF) as f:
            orig = f.read()
    except OSError as e:
        return False, f"Cannot read {WG_CONF}: {e}"

    if "AllowedIPs" not in orig:
        return False, "AllowedIPs line not found — refusing to rewrite config."

    new_line = "AllowedIPs = " + ", ".join(cidrs)
    new_txt, n = re.subn(r"^\s*AllowedIPs\s*=.*$", new_line, orig, count=1, flags=re.M)
    if n != 1:
        return False, "Failed to locate AllowedIPs line."
    if "[Interface]" not in new_txt or "[Peer]" not in new_txt:
        return False, "Config sections missing after edit — not applied."

    # Backup original (keep last 5)
    try:
        stamps = sorted(f for f in os.listdir(os.path.dirname(WG_CONF))
                        if f.startswith("wg0.conf.bak."))
        for old in stamps[:-4]:
            os.remove(os.path.join(os.path.dirname(WG_CONF), old))
        shutil.copy2(WG_CONF, WG_CONF + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S"))
    except OSError as e:
        return False, f"Backup failed, aborting: {e}"

    # Atomic replace + chmod 600
    try:
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new_txt)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        os.chmod(WG_CONF, 0o600)
    except OSError as e:
        return False, f"Write failed: {e}"

    # Apply live: `wg set` via netlink (no handshake drop, no restart).
    # Fallback to full restart if wg set fails.
    peer_pub = ""
    try:
        pr = subprocess.run(["wg", "show", WG_IFACE, "peers"],
                            capture_output=True, text=True, timeout=5)
        peer_pub = (pr.stdout or "").strip().split("\n")[0].strip()
    except (IndexError, AttributeError):
        peer_pub = ""
    apply_err = ""
    if peer_pub:
        s = subprocess.run(["wg", "set", WG_IFACE, "peer", peer_pub,
                            "allowed-ips", ",".join(cidrs)],
                           capture_output=True, text=True, timeout=10)
        if s.returncode != 0:
            apply_err = (s.stderr or s.stdout).strip()[:200]
    else:
        apply_err = "peer public key not found"
    if not apply_err:
        # Keep kernel routes in sync: wg set doesn't manage routes
        # (only wg-quick up does). Add new, remove dropped (wg0-scoped only).
        try:
            old_set = set()
            m_old = re.search(r"^\s*AllowedIPs\s*=\s*(.+)$", orig, re.M)
            if m_old:
                old_list, _ = validate_cidr_list(m_old.group(1))
                old_set = set(old_list or [])
            new_set = set(cidrs)
            for c in sorted(new_set - old_set):
                subprocess.run(["ip", "route", "replace", c, "dev", WG_IFACE],
                               capture_output=True, timeout=5)
            for c in sorted(old_set - new_set):
                chk = subprocess.run(["ip", "route", "show", c, "dev", WG_IFACE],
                                     capture_output=True, text=True, timeout=5)
                if (chk.stdout or "").strip():
                    subprocess.run(["ip", "route", "del", c, "dev", WG_IFACE],
                                   capture_output=True, timeout=5)
        except (OSError, ValueError):
            pass
        return True, f"Saved & applied live (no drop). {len(cidrs)} CIDR(s)."
    # Fallback: full restart
    down = subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                          capture_output=True, text=True, timeout=30)
    if down.returncode == 0:
        return True, f"Saved. Live apply unavailable, interface restarted. {len(cidrs)} CIDR(s)."
    # Rollback
    try:
        with open(WG_CONF) as f:
            bad = f.read()
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(orig)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                       capture_output=True, timeout=30)
    except OSError:
        pass
    err = (apply_err or (down.stderr or down.stdout or "")).strip()[:200]
    return False, f"Apply failed, rolled back. {err}"

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

def validate_wg_conf(text):
    """Validate full wg0.conf text. Returns (normalized_text|None, error|None)."""
    if text is None:
        return None, "Empty config."
    if len(text) > 32768:
        return None, "Config too large (max 32KB)."
    lines = text.splitlines()
    # strip trailing whitespace, drop leading blank lines but keep structure
    cleaned = [ln.rstrip() for ln in lines]
    # must have sections
    if not any(l.strip() == "[Interface]" for l in cleaned):
        return None, "Missing [Interface] section."
    if not any(l.strip() == "[Peer]" for l in cleaned):
        return None, "Missing [Peer] section (at least one required)."
    section = None
    n_iface = 0
    n_peer = 0
    iface_keys = {}
    peer_keys = {}
    peer_pubs = set()
    IFACE_ALLOWED = {"Address", "ListenPort", "PrivateKey", "DNS", "MTU", "Table",
                     "PreUp", "PreDown", "PostUp", "PostDown"}
    PEER_ALLOWED = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
    for i, raw in enumerate(cleaned, start=1):
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            name = m.group(1).strip()
            if name not in ("Interface", "Peer"):
                return None, f"Line {i}: unknown section [{name}]. Only [Interface]/[Peer] allowed."
            section = name
            if section == "Interface":
                n_iface += 1
                if n_iface > 1:
                    return None, "Only one [Interface] section allowed."
                iface_keys = {}
            else:
                n_peer += 1
                peer_keys = {}
            continue
        if section is None:
            return None, f"Line {i}: setting outside any section."
        if "=" not in s:
            return None, f"Line {i}: invalid line (missing '=')."
        k, v = [x.strip() for x in s.split("=", 1)]
        if not k or not v:
            return None, f"Line {i}: empty key or value."
        if section == "Interface":
            if k not in IFACE_ALLOWED:
                return None, f"Line {i}: key '{k}' not allowed in [Interface]. Allowed: {', '.join(sorted(IFACE_ALLOWED))}."
            if k in iface_keys:
                return None, f"Line {i}: duplicate '{k}' in [Interface]."
            iface_keys[k] = v
            if k == "PrivateKey" and not WG_KEY_RE.match(v):
                return None, f"Line {i}: PrivateKey must be 44-char WireGuard base64 key."
            if k == "Address":
                for tok in re.split(r"[,\s]+", v):
                    if not tok:
                        continue
                    try:
                        ipaddress.ip_interface(tok)
                    except ValueError:
                        return None, f"Line {i}: invalid Address '{tok}' (expect e.g. 10.99.0.1/24)."
            if k == "ListenPort":
                if not v.isdigit() or not (1 <= int(v) <= 65535):
                    return None, f"Line {i}: ListenPort must be 1-65535."
            if k == "MTU":
                if not v.isdigit() or not (68 <= int(v) <= 9000):
                    return None, f"Line {i}: MTU must be 68-9000."
            if k == "DNS":
                if len(v) > 512:
                    return None, f"Line {i}: DNS value too long."
        else:
            if k not in PEER_ALLOWED:
                return None, f"Line {i}: key '{k}' not allowed in [Peer]. Allowed: {', '.join(sorted(PEER_ALLOWED))}."
            if k in ("PublicKey", "AllowedIPs") and k in peer_keys:
                return None, f"Line {i}: duplicate '{k}' in same [Peer]."
            peer_keys[k] = v
            if k in ("PublicKey", "PresharedKey") and not WG_KEY_RE.match(v):
                return None, f"Line {i}: {k} must be 44-char WireGuard base64 key."
            if k == "AllowedIPs":
                _, err = validate_cidr_list(v)
                if err:
                    return None, f"Line {i}: AllowedIPs: {err}"
            if k == "Endpoint":
                m2 = re.match(r"^(.+):(\d+)$", v)
                if not m2:
                    return None, f"Line {i}: Endpoint must be host:port."
                try:
                    port = int(m2.group(2))
                except ValueError:
                    return None, f"Line {i}: Endpoint port invalid."
                if not (1 <= port <= 65535):
                    return None, f"Line {i}: Endpoint port must be 1-65535."
                if len(m2.group(1)) > 253 or not m2.group(1):
                    return None, f"Line {i}: Endpoint host invalid."
            if k == "PersistentKeepalive":
                if not v.isdigit() or not (0 <= int(v) <= 65535):
                    return None, f"Line {i}: PersistentKeepalive must be 0-65535."
            if k == "PublicKey":
                if v in peer_pubs:
                    return None, f"Line {i}: duplicate peer PublicKey."
                peer_pubs.add(v)
    if "PrivateKey" not in iface_keys:
        return None, "[Interface] missing PrivateKey."
    if "Address" not in iface_keys:
        return None, "[Interface] missing Address."
    # wg-quick syntax check. NOTE: wg-quick only accepts configs matching
    # ^[a-zA-Z0-9_=+.-]{1,15}\.conf$ and refuses /tmp paths in this
    # environment (Permission denied), so validate via a short-lived
    # file inside /etc/wireguard (basename wgv<PID>, always <=15 chars).
    import tempfile
    tmp = os.path.join(os.path.dirname(WG_CONF), f"wgv{os.getpid()}.conf")
    try:
        normalized = "\n".join(cleaned).rstrip("\n") + "\n"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(normalized)
        r = subprocess.run(["wg-quick", "strip", tmp],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "wg-quick strip failed").strip()[:300]
            return None, f"wg-quick validation failed: {err}"
        if "[Interface]" not in (r.stdout or ""):
            return None, "wg-quick validation produced empty output."
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"Validation error: {e}"
    finally:
        try:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
    return normalized, None


def read_wg_conf():
    """Read full wg0.conf text."""
    try:
        with open(WG_CONF) as f:
            return f.read(), None
    except OSError as e:
        return None, f"Cannot read {WG_CONF}: {e}"


def write_wg_conf(new_text):
    """Validate, backup, atomically write full wg0.conf, restart tunnel. Returns (ok, msg)."""
    normalized, err = validate_wg_conf(new_text)
    if err:
        return False, err
    try:
        with open(WG_CONF) as f:
            orig = f.read()
    except OSError as e:
        return False, f"Cannot read {WG_CONF}: {e}"
    if normalized == orig:
        return True, "No changes."
    try:
        stamps = sorted(f for f in os.listdir(os.path.dirname(WG_CONF))
                        if f.startswith("wg0.conf.bak."))
        for old in stamps[:-9]:
            os.remove(os.path.join(os.path.dirname(WG_CONF), old))
        shutil.copy2(WG_CONF, WG_CONF + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S"))
    except OSError as e:
        return False, f"Backup failed, aborting: {e}"
    try:
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(normalized)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        os.chmod(WG_CONF, 0o600)
    except OSError as e:
        return False, f"Write failed: {e}"
    r = subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        try:
            fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(orig)
            os.rename(WG_CONF + ".tmp", WG_CONF)
            subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                           capture_output=True, timeout=30)
        except OSError:
            pass
        return False, f"Restart failed, rolled back: {(r.stderr or r.stdout).strip()[:200]}"
    time.sleep(2)
    st = subprocess.run(["systemctl", "is-active", f"wg-quick@{WG_IFACE}"],
                        capture_output=True, text=True, timeout=5)
    if st.stdout.strip() != "active":
        try:
            fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(orig)
            os.rename(WG_CONF + ".tmp", WG_CONF)
            subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                           capture_output=True, timeout=30)
        except OSError:
            pass
        return False, "Service not active after restart, rolled back."
    return True, "Saved full wg0.conf & restarted tunnel."


def restart_wg():
    """Restart wg-quick@wg0. Returns (ok, msg)."""
    r = subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return False, f"Restart failed: {(r.stderr or r.stdout).strip()[:200]}"
    time.sleep(2)
    st = subprocess.run(["systemctl", "is-active", f"wg-quick@{WG_IFACE}"],
                        capture_output=True, text=True, timeout=5)
    hs = subprocess.run(["wg", "show", WG_IFACE, "latest-handshakes"],
                        capture_output=True, text=True, timeout=5)
    ago = None
    try:
        parts = hs.stdout.strip().split()
        if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 0:
            ago = format_seconds(time.time() - int(parts[1]))
    except (ValueError, IndexError):
        pass
    active = st.stdout.strip() == "active"
    detail = f" Handshake {ago}." if ago else " No handshake yet."
    if active:
        return True, f"wg0 restarted, service active.{detail}"
    return False, f"Service state: {st.stdout.strip() or 'unknown'}.{detail}"

# ---------------- WireGuard road-warrior peer manager ----------------

PEER_DIR = os.path.join(BASE_DIR, "peers")
PEER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,31}$")
WG_HOME_NET = ipaddress.ip_network("10.99.0.0/24")

def wg_server_pubkey():
    try:
        r = subprocess.run(["wg", "show", WG_IFACE, "public-key"],
                           capture_output=True, text=True, timeout=5)
        return (r.stdout or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def wg_default_endpoint():
    """Prefill for road-warrior client configs: <eth0-ip>:<listen-port>."""
    port = "51820"
    try:
        with open(WG_CONF) as f:
            m = re.search(r"^\s*ListenPort\s*=\s*(\d+)\s*$", f.read(), re.M)
            if m:
                port = m.group(1)
    except OSError:
        pass
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show", "eth0"],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", r.stdout or "")
        if m:
            return f"{m.group(1)}:{port}"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return f":{port}"


def wg_parse_peers(txt):
    """Parse wg0.conf into [{name, public_key, allowed_ips(list), start, end}]. Name = preceding # comments."""
    peers = []
    pending_comments = []
    cur = None
    for i, ln in enumerate(txt.splitlines()):
        s = ln.strip()
        if not s:
            pending_comments = []
            continue
        if s.startswith("#") or s.startswith(";"):
            pending_comments.append(s.lstrip("#;").strip())
            continue
        if re.match(r"^\[Interface\]$", s, re.I):
            cur = None
            pending_comments = []
            continue
        if re.match(r"^\[Peer\]$", s, re.I):
            cur = {"name": " ".join(pending_comments) or "", "public_key": "",
                   "allowed_ips": [], "start": i}
            peers.append(cur)
            pending_comments = []
            continue
        if cur is not None and "=" in s:
            k, v = [x.strip() for x in s.split("=", 1)]
            if k.lower() == "publickey":
                cur["public_key"] = v
            elif k.lower() == "allowedips":
                cur["allowed_ips"] = [t.strip() for t in re.split(r"[,\s]+", v) if t.strip()]
            cur["end"] = i
    return peers


def wg_peer_deletable(peer):
    """Only road-warrior style peers (single 10.99.0.x/32) may be deleted via GUI (protects the site peer)."""
    ips = peer.get("allowed_ips") or []
    if len(ips) != 1:
        return False
    try:
        net = ipaddress.ip_network(ips[0], strict=False)
    except ValueError:
        return False
    return (net.prefixlen == 32 and net.network_address in WG_HOME_NET
            and str(net.network_address) != str(WG_HOME_NET.network_address)
            and int(net.network_address) != int(WG_HOME_NET.network_address) + 1)


def wg_suggest_ip(txt):
    """Smallest free 10.99.0.x host address (>= .2, excluding .1)."""
    used = set()
    for p in wg_parse_peers(txt):
        for tok in p["allowed_ips"]:
            try:
                n = ipaddress.ip_network(tok, strict=False)
                if n.version == 4 and n.prefixlen == 32 and n.network_address in WG_HOME_NET:
                    used.add(int(n.network_address))
            except ValueError:
                pass
    base = int(WG_HOME_NET.network_address)
    for host in range(2, 254):
        if base + host not in used:
            return str(WG_HOME_NET.network_address + host)
    return None


def wg_live_peers():
    """{pubkey: live_info} from `wg show`."""
    out = {}
    try:
        wg = parse_wg_show()
        for iface in (wg.get("interfaces") or []):
            for p in (iface.get("peers") or []):
                if p.get("public_key"):
                    out[p["public_key"]] = p
    except Exception:
        pass
    return out


def wg_backup_conf():
    d = os.path.dirname(WG_CONF)
    stamps = sorted(f for f in os.listdir(d) if f.startswith("wg0.conf.bak."))
    for old in stamps[:-9]:
        os.remove(os.path.join(d, old))
    shutil.copy2(WG_CONF, WG_CONF + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S"))


def wg_apply_full_restart(orig):
    """Restart tunnel after a full-file change; rollback on failure. Returns (ok, msg)."""
    r = subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        st = subprocess.run(["systemctl", "is-active", f"wg-quick@{WG_IFACE}"],
                            capture_output=True, text=True, timeout=5)
        if st.stdout.strip() == "active":
            return True, "Tunnel restarted."
    try:
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(orig)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        subprocess.run(["systemctl", "restart", f"wg-quick@{WG_IFACE}"],
                       capture_output=True, timeout=30)
    except OSError:
        pass
    return False, f"Restart failed, rolled back: {(r.stderr or r.stdout or '').strip()[:200]}"


def wg_syncconf():
    """Hitless reload of wg0.conf (no handshake drop). Returns (ok, err)."""
    import tempfile
    tmp = os.path.join(os.path.dirname(WG_CONF), f"wgsync{os.getpid()}.conf")
    try:
        r = subprocess.run(["wg-quick", "strip", WG_CONF],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0 or "[Interface]" not in (r.stdout or ""):
            return False, "wg-quick strip failed validation."
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(r.stdout)
        s = subprocess.run(["wg", "syncconf", WG_IFACE, tmp],
                           capture_output=True, text=True, timeout=10)
        if s.returncode != 0:
            return False, (s.stderr or s.stdout).strip()[:200]
        return True, ""
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)[:200]
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def wg_client_config(client_priv, client_ip, endpoint, dns):
    lines = ["[Interface]",
             f"PrivateKey = {client_priv}",
             f"Address = {client_ip}/32"]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["",
              "[Peer]",
              f"PublicKey = {wg_server_pubkey() or 'SERVER_PUBLIC_KEY'}",
              f"Endpoint = {endpoint}",
              "AllowedIPs = 0.0.0.0/0, ::/0",
              "PersistentKeepalive = 25"]
    return "\n".join(lines) + "\n"


def wg_peer_qr_png(client_conf):
    """QR PNG bytes for a client config (segno + pillow)."""
    import segno
    import io
    qr = segno.make(client_conf, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=6, border=2)
    return buf.getvalue()

def restart_samba():
    """Validate smb.conf with testparm, restart smbd (+nmbd if it was active). Returns (ok, msg)."""
    try:
        tp = subprocess.run(["testparm", "-s"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"testparm error: {e}"
    if tp.returncode != 0:
        err = (tp.stderr or tp.stdout or "testparm failed").strip()[:300]
        return False, f"Config invalid, not restarted. {err}"
    nmb_active = False
    try:
        st = subprocess.run(["systemctl", "is-active", "nmbd"],
                            capture_output=True, text=True, timeout=5)
        nmb_active = st.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        pass
    units = ["smbd"] + (["nmbd"] if nmb_active else [])
    for u in units:
        r = subprocess.run(["systemctl", "restart", u],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, f"Restart {u} failed: {(r.stderr or r.stdout).strip()[:200]}"
    time.sleep(1)
    st = subprocess.run(["systemctl", "is-active", "smbd"],
                        capture_output=True, text=True, timeout=5)
    if st.stdout.strip() != "active":
        return False, f"smbd state: {st.stdout.strip() or 'unknown'} after restart."
    extra = " (+nmbd)" if nmb_active else ""
    return True, f"Samba restarted{extra}, smbd active."

# ---------------- Data collectors ----------------

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception as e:
        return str(e)

def parse_wg_show():
    """Parse wg show all dump output into structured data
    Interface line (5 cols): ifname \t public_key \t private_key \t listen_port \t fwmark
    Peer line (9 cols): ifname \t public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t transfer_rx \t transfer_tx \t keepalive
    """
    raw = run_cmd("wg show all dump")
    if not raw:
        return {"interfaces": [], "error": "wg show returned empty"}

    interfaces = []
    current_iface = None

    for line in raw.strip().split('\n'):
        parts = line.split('\t')

        if len(parts) == 5:
            iface_name = parts[0]
            current_iface = {
                "name": iface_name,
                "public_key": parts[1],
                "listen_port": parts[3],
                "fwmark": parts[4],
                "peers": []
            }
            interfaces.append(current_iface)

        elif len(parts) == 9 and current_iface:
            try:
                handshake_epoch = int(parts[5]) if parts[5].isdigit() else 0
                handshake_ago = time.time() - handshake_epoch if handshake_epoch > 0 else None

                current_iface["peers"].append({
                    "public_key": parts[1],
                    "endpoint": parts[3] if parts[3] != '(none)' else None,
                    "allowed_ips": parts[4],
                    "latest_handshake": handshake_epoch,
                    "handshake_ago": handshake_ago,
                    "handshake_human": format_seconds(handshake_ago) if handshake_ago else "Never",
                    "transfer_rx": int(parts[6]) if parts[6].isdigit() else 0,
                    "transfer_tx": int(parts[7]) if parts[7].isdigit() else 0,
                    "rx_human": format_bytes(int(parts[6])) if parts[6].isdigit() else "0 B",
                    "tx_human": format_bytes(int(parts[7])) if parts[7].isdigit() else "0 B",
                    "keepalive": parts[8],
                    "connected": handshake_ago is not None and handshake_ago < 150
                })
            except (ValueError, IndexError):
                pass

    return {"interfaces": interfaces}

def parse_ip_addr():
    """Get IP addresses for wg interfaces"""
    raw = run_cmd("ip -br addr show")
    addrs = {}
    for line in raw.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith(('wg', 'br', 'eth')):
            addrs[parts[0]] = {
                "state": parts[1],
                "ips": [p for p in parts[2:] if '/' in p]
            }
    return addrs

def parse_routes():
    """Get routes via wg interfaces"""
    raw = run_cmd("ip route show")
    routes = []
    for line in raw.strip().split('\n'):
        if 'wg' in line:
            routes.append(line)
    return routes

def parse_bgp_summary():
    """Get BGP neighbor summary via FRR"""
    raw = run_cmd("vtysh -c 'show ip bgp summary' 2>&1")
    peers = []
    lines = raw.strip().split('\n')

    for line in lines:
        # Match FRR format:
        # 10.99.0.2       4      65002      1212      1213        5    0    0 20:08:38            4        1 N/A
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)', line)
        if match:
            peers.append({
                "neighbor": match.group(1),
                "remote_as": match.group(3),
                "state": match.group(12) if match.group(12) != 'N/A' else 'Established',
                "pfx_rcd": match.group(10),
                "up_time": match.group(9)
            })

    return {"peers": peers, "raw": raw[:500] if not peers else None}

def parse_bgp_detail():
    """JSON-based BGP detail: local AS, prefixes, nexthops. Falls back to text on failure."""
    out = {"local_as": None, "router_id": None, "received": [], "advertised": [], "peers": [], "error": None}
    try:
        r = subprocess.run(["vtysh", "-c", "show ip bgp summary json"], capture_output=True, text=True, timeout=8)
        if r.returncode == 0 and r.stdout.strip():
            j = json.loads(r.stdout)
            uni = j.get("ipv4Unicast", j)
            out["local_as"] = uni.get("as") or uni.get("localAS")
            out["router_id"] = uni.get("routerId")
            for nip, pinfo in (uni.get("peers", {}) or {}).items():
                out["peers"].append({
                    "neighbor": nip,
                    "remote_as": pinfo.get("remoteAs"),
                    "state": pinfo.get("state", "Established"),
                    "pfx_rcd": pinfo.get("pfxRcd", 0),
                    "pfx_snt": pinfo.get("pfxSnt", 0),
                    "up_time": pinfo.get("peerUptime", ""),
                })
    except Exception as ex:
        out["error"] = str(ex)[:200]
    try:
        r2 = subprocess.run(["vtysh", "-c", "show ip bgp json"], capture_output=True, text=True, timeout=8)
        if r2.returncode == 0 and r2.stdout.strip():
            j2 = json.loads(r2.stdout)
            routes = j2.get("routes", {})
            if out["local_as"] is None:
                out["local_as"] = j2.get("localAS")
            if out["router_id"] is None:
                out["router_id"] = j2.get("routerId")
            for net, paths in routes.items():
                for pth in (paths or []):
                    nhs = pth.get("nexthops", []) or []
                    nh = (nhs[0].get("ip") if nhs else "") or ""
                    entry = {"prefix": net, "nexthop": nh, "peer": pth.get("peerId", ""), "path": pth.get("path", ""), "valid": bool(pth.get("valid")), "best": bool(pth.get("bestpath"))}
                    if nh == "0.0.0.0" or (pth.get("peerId") in ("(unspec)", None, "")):
                        out["advertised"].append(entry)
                    else:
                        out["received"].append(entry)
    except Exception as ex:
        if not out["error"]:
            out["error"] = str(ex)[:200]
    return out

def bgp_correlation():
    """Correlate BGP prefixes with WG peer AllowedIPs + kernel routes."""
    det = parse_bgp_detail()
    try:
        kr = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=5)
        kroutes = (kr.stdout or "").splitlines()
    except Exception:
        kroutes = []
    try:
        wg = parse_wg_show()
    except Exception:
        wg = {"interfaces": []}
    # peer allowed nets
    peer_nets = []  # [(shortkey, endpoint, [ip_network,...], fullkey)]
    for iface in (wg.get("interfaces") or []):
        for p in (iface.get("peers") or []):
            nets = []
            for tok in (p.get("allowed_ips") or "").split(","):
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    nets.append(ipaddress.ip_network(tok, strict=False))
                except ValueError:
                    pass
            peer_nets.append({
                "key": (p.get("public_key") or "")[:12],
                "full": p.get("public_key") or "",
                "endpoint": p.get("endpoint") or "",
                "nets": nets,
            })
    rows = []
    for e in det.get("received", []):
        try:
            pfx = ipaddress.ip_network(e["prefix"], strict=False)
        except ValueError:
            continue
        covering = [pn["key"] for pn in peer_nets if any(pfx.subnet_of(n) or pfx == n for n in pn["nets"])]
        in_kernel = any(l.split()[0] == str(pfx) and "wg" in l for l in kroutes if l.split())
        if not covering:
            status = "NOT_IN_WG"
        elif not in_kernel:
            status = "NO_KERNEL_ROUTE"
        else:
            status = "OK"
        rows.append({"prefix": str(pfx), "nexthop": e.get("nexthop"), "path": e.get("path"),
                     "wg_peers": covering, "in_kernel": in_kernel, "status": status, "dir": "received"})
    for e in det.get("advertised", []):
        rows.append({"prefix": e.get("prefix"), "nexthop": e.get("nexthop"), "path": e.get("path", "local"),
                     "wg_peers": [], "in_kernel": True, "status": "ADVERTISED", "dir": "advertised"})
    # WG-only nets missing from BGP
    bgp_set = set()
    for e in det.get("received", []):
        try:
            bgp_set.add(ipaddress.ip_network(e["prefix"], strict=False))
        except ValueError:
            pass
    for pn in peer_nets:
        for n in pn["nets"]:
            if n.prefixlen == 32:
                continue
            if not any(n == b for b in bgp_set) and not any(n.subnet_of(b) or b.subnet_of(n) for b in bgp_set):
                in_kernel = any(l.split()[0] == str(n) for l in kroutes if l.split())
                rows.append({"prefix": str(n), "nexthop": "-", "path": "-",
                             "wg_peers": [pn["key"]], "in_kernel": in_kernel, "status": "MISSING_IN_BGP", "dir": "wg-only"})
    det_peers = det.get("peers") or []
    return {"local_as": det.get("local_as"), "router_id": det.get("router_id"),
            "neighbor": det_peers[0].get("neighbor") if det_peers else None,
            "remote_as": det_peers[0].get("remote_as") if det_peers else None,
            "state": det_peers[0].get("state") if det_peers else None,
            "received_count": len(det.get("received", [])), "advertised_count": len(det.get("advertised", [])),
            "rows": rows, "error": det.get("error")}

def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def format_seconds(s):
    if s < 60:
        return f"{s:.0f}s ago"
    elif s < 3600:
        return f"{s/60:.0f}m ago"
    elif s < 86400:
        return f"{s/3600:.1f}h ago"
    else:
        return f"{s/86400:.1f}d ago"

# ---------------- Routes ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        key = client_key()
        wait = is_locked(key)
        if wait:
            error = f"Too many attempts. Locked for {wait}s."
        else:
            username = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""
            users = load_users()
            stored = users.get(username)
            if stored and check_password_hash(stored, password):
                clear_fails(key)
                session.clear()
                session.permanent = True
                session["user"] = username
                session["csrf"] = secrets.token_urlsafe(32)
                session["login_at"] = datetime.now(timezone.utc).isoformat()
                return redirect(url_for("index"))
            fails, until = register_fail(key)
            if until:
                error = "Too many failed attempts. Locked for 15 minutes."
            else:
                error = f"Invalid credentials. {MAX_FAILS - fails} attempts left."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    ok = None
    if request.method == "POST":
        check_csrf()
        current = request.form.get("current") or ""
        new = request.form.get("new") or ""
        confirm = request.form.get("confirm") or ""
        users = load_users()
        me = session.get("user")
        if not check_password_hash(users.get(me, ""), current):
            error = "Current password is wrong."
        elif len(new) < 12:
            error = "New password must be at least 12 characters."
        elif new != confirm:
            error = "New passwords do not match."
        elif new == current:
            error = "New password must differ from current."
        elif not re.search(r"[A-Za-z]", new) or not re.search(r"\d", new):
            error = "New password must contain letters and numbers."
        else:
            users[me] = generate_password_hash(new, method="scrypt")
            save_users(users)
            session["csrf"] = secrets.token_urlsafe(32)
            ok = "Password updated successfully."
    return render_template_string(
        PW_TEMPLATE, error=error, ok=ok, csrf=csrf_token(), user=session.get("user")
    )

@app.route('/')
@login_required
def index():
    resp = app.make_response(render_template_string(HTML_TEMPLATE, csrf=csrf_token()))
    # portal is fully dynamic (session CSRF + live state): never cache it,
    # otherwise browsers can run a stale copy where tab switching breaks.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp

@app.route('/api/status')
@login_required
def api_status():
    wg = parse_wg_show()
    ips = parse_ip_addr()
    routes = parse_routes()
    bgp = parse_bgp_summary()

    # Merge interface info with IP addresses
    for iface in wg.get('interfaces', []):
        info = ips.get(iface['name'], {})
        iface['ip_info'] = info
        # WireGuard is point-to-point: kernel operstate is ALWAYS "unknown"
        # (no carrier/duplex negotiation like Ethernet) — that is normal, not a fault.
        # Derive real state: DOWN if admin down/missing, UP if a peer handshake is
        # fresh, IDLE otherwise.
        kernel = (info.get('state') or '').upper() or 'MISSING'
        peers = iface.get('peers') or []
        if kernel in ('DOWN', 'MISSING'):
            eff = 'DOWN'
        elif any(p.get('connected') for p in peers):
            eff = 'UP'
        else:
            eff = 'IDLE'
        iface['kernel_state'] = kernel
        iface['effective_state'] = eff

    return jsonify({
        "timestamp": datetime.now(MYTZ).isoformat(),
        "wg": wg,
        "routes": routes,
        "bgp": bgp,
        "bgp_corr": bgp_correlation_cached(),
        "uptime": run_cmd("uptime -p")
    })

@app.route('/api/bgp/correlation')
@login_required
def api_bgp_corr():
    return jsonify(bgp_correlation_cached())


BGP_ANNOUNCE_PREFIX = "192.168.10.0/24"


def bgp_origin_announced():
    """True if `network 192.168.10.0/24` is configured locally (FRR running-config)."""
    try:
        r = subprocess.run(["vtysh", "-c", "show running-config"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        return bool(re.search(r"^\s*network\s+192\.168\.10\.0/24\s*$", r.stdout or "", re.M))
    except (OSError, subprocess.TimeoutExpired):
        return None


@app.route('/api/bgp/origin', methods=["GET"])
@login_required
def api_bgp_origin():
    announced = bgp_origin_announced()
    if announced is None:
        return jsonify({"ok": False, "error": "FRR query failed."}), 500
    return jsonify({"ok": True, "prefix": BGP_ANNOUNCE_PREFIX, "announced": announced})


@app.route('/api/bgp/announce', methods=["POST"])
@login_required
def api_bgp_announce():
    check_csrf()
    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip().lower()
    if action not in ("announce", "withdraw"):
        return jsonify({"ok": False, "error": "action must be announce or withdraw."}), 400
    verb = "" if action == "announce" else "no "
    seq = ["configure", "router bgp 65001", "address-family ipv4 unicast",
           f"{verb}network {BGP_ANNOUNCE_PREFIX}", "end", "write"]
    args = []
    for c in seq:
        args += ["-c", c]
    try:
        r = subprocess.run(["vtysh"] + args, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return jsonify({"ok": False, "error": f"vtysh failed: {e}"}), 500
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr or r.stdout or "vtysh failed").strip()[:300]}), 500
    time.sleep(2)
    now = bgp_origin_announced()
    want = (action == "announce")
    if now != want:
        return jsonify({"ok": False, "error": "FRR accepted the change but running-config does not reflect it."}), 500
    try:
        subprocess.run(["vtysh", "-c", "clear ip bgp 10.99.0.2 soft"],
                       capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return jsonify({"ok": True,
                    "message": f"{BGP_ANNOUNCE_PREFIX} {'announced' if want else 'withdrawn'} & saved."}), 200


@app.route('/api/bgp/reset', methods=["POST"])
@login_required
def api_bgp_reset():
    check_csrf()
    body = request.get_json(silent=True) or {}
    if (body.get("confirm") or "").strip().lower() != "reset":
        return jsonify({"ok": False, "error": "Type 'reset' to confirm."}), 400
    try:
        r = subprocess.run(["vtysh", "-c", "clear ip bgp 10.99.0.2 soft"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return jsonify({"ok": False, "error": f"vtysh failed: {e}"}), 500
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr or r.stdout or "reset failed").strip()[:200]}), 500
    return jsonify({"ok": True, "message": "BGP soft reset sent to 10.99.0.2."}), 200

@app.route('/api/wg/traffic/history')
@login_required
def api_wg_traffic_history():
    peer = (request.args.get("peer") or "").strip()
    window = (request.args.get("window") or "24h").strip().lower()
    if not peer:
        return jsonify({"ok": False, "error": "peer required"}), 400
    secs = {"1h": 3600, "24h": 86400, "7d": 604800}.get(window, 86400)
    cutoff = int(time.time()) - secs
    c = traffic_db()
    if not c:
        return jsonify({"ok": False, "error": "db unavailable"}), 500
    try:
        cur = c.execute("SELECT ts, rx, tx FROM wg_traffic WHERE peer=? AND ts>=? ORDER BY ts", (peer, cutoff))
        rows = cur.fetchall()
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500
    finally:
        try:
            c.close()
        except Exception:
            pass
    # downsample to <=240 points
    if len(rows) > 240:
        step = len(rows) / 240.0
        rows = [rows[int(i*step)] for i in range(240)]
    pts = []
    prev = None
    for ts, rx, tx in rows:
        if prev is None:
            drx, dtx = 0, 0
        else:
            drx = max(0, (rx or 0) - (prev[1] or 0))
            dtx = max(0, (tx or 0) - (prev[2] or 0))
        pts.append([ts, drx, dtx])
        prev = (ts, rx, tx)
    return jsonify({"ok": True, "peer": peer, "window": window, "points": pts})

@app.route('/api/search')
@login_required
def api_search():
    q = (request.args.get("q") or "").strip().lower()
    if len(q) < 2:
        return jsonify({"q": q, "results": []})
    out = []
    def push(kind, label, sub, action):
        out.append({"kind": kind, "label": label, "sub": sub, "action": action})
    # WG peers + interfaces
    try:
        wg = parse_wg_show()
        for iface in (wg.get("interfaces") or []):
            for p in (iface.get("peers") or []):
                hay = " ".join([p.get("endpoint") or "", p.get("allowed_ips") or "", p.get("public_key") or "", iface.get("name") or ""]).lower()
                if q in hay:
                    push("wg_peer", (p.get("endpoint") or "no-endpoint"), "%s | %s | %s" % (iface.get("name",""), "ACTIVE" if p.get("connected") else "STALE", p.get("allowed_ips","")), "tab:wg")
            iface_hay = " ".join([iface.get("name") or "", iface.get("effective_state") or ""]).lower()
            if q in iface_hay and len(out) < 30:
                push("wg_iface", iface.get("name",""), iface.get("effective_state",""), "tab:wg")
    except Exception:
        pass
    # BGP
    try:
        bgp = parse_bgp_summary()
        for bp in (bgp.get("peers") or []):
            hay = " ".join([bp.get("neighbor") or "", str(bp.get("remote_as") or ""), bp.get("state") or ""]).lower()
            if q in hay and len(out) < 30:
                push("bgp", "%s AS%s" % (bp.get("neighbor"), bp.get("remote_as")), bp.get("state",""), "tab:wg")
    except Exception:
        pass
    # routes
    try:
        for r in (parse_routes() or []):
            if q in r.lower() and len(out) < 30:
                push("route", r, "wg route", "tab:wg")
    except Exception:
        pass
    # samba shares
    try:
        shares, _ = smb_parse_shares()
        for s in shares:
            hay = " ".join([s.get("name") or "", s.get("path") or "", s.get("valid_users") or ""]).lower()
            if q in hay and len(out) < 30:
                push("samba_share", s.get("name",""), "%s | %s | %s" % (s.get("path",""), s.get("valid_users") or "ALL", "RW" if s.get("writable") else "RO"), "tab:smb")
    except Exception:
        pass
    # mvnbc files (cap 30/vendor scan)
    try:
        if os.path.isdir(MVNBC_BACKUPS):
            for vf in sorted(os.listdir(MVNBC_BACKUPS)):
                vdir = os.path.join(MVNBC_BACKUPS, vf)
                if not os.path.isdir(vdir):
                    continue
                try:
                    fns = sorted(os.listdir(vdir), reverse=True)[:30]
                except OSError:
                    continue
                for fn in fns:
                    if q in (vf + " " + fn).lower() and len(out) < 30:
                        push("mvnbc_file", vf + "/" + fn, vf, "mvnbc:" + vf + "/" + fn)
    except Exception:
        pass
    # run logs
    try:
        if os.path.isdir(MVNBC_LOGS):
            for fn in sorted([n for n in os.listdir(MVNBC_LOGS) if n.startswith("run_")], reverse=True)[:30]:
                if q in fn.lower() and len(out) < 30:
                    push("log", fn, "run log", "mvnbc:log:" + fn)
    except Exception:
        pass
    # IPAM subnets
    try:
        for s in (_ipam_summary_cached().get("subnets") or []):
            hay = " ".join([s.get("cidr") or "", s.get("name") or "", s.get("site") or "", s.get("gateway") or ""]).lower()
            if q in hay and len(out) < 30:
                push("ipam_sub", s.get("cidr",""), "%s | %s | %s/%s" % (s.get("name",""), s.get("site",""), s.get("used",0), s.get("total",0)), "ipam:" + s.get("cidr",""))
    except Exception:
        pass
    return jsonify({"q": q, "results": out[:30]})

@app.route('/api/ping/<ip>')
@login_required
def api_ping(ip):
    """Ping a specific IP"""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"error": "bad ip"}), 400
    result = run_cmd(f"ping -c 2 -W 2 {ip}")
    loss_match = re.search(r'(\d+)% packet loss', result)
    rtt_match = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/', result)

    return jsonify({
        "target": ip,
        "loss": int(loss_match.group(1)) if loss_match else 100,
        "rtt_avg": float(rtt_match.group(2)) if rtt_match else None,
        "alive": bool(loss_match and int(loss_match.group(1)) < 100)
    })

@app.route('/api/allowed-ips', methods=["GET"])
@login_required
def api_allowed_ips_get():
    cidrs, err = read_allowed_ips()
    if err:
        return jsonify({"error": err}), 500
    raw = ""
    try:
        with open(WG_CONF) as f:
            m = re.search(r"^\s*AllowedIPs\s*=\s*(.+)$", f.read(), re.M)
            raw = m.group(1).strip() if m else ""
    except OSError:
        pass
    return jsonify({"cidrs": cidrs, "raw": raw, "file": WG_CONF})

@app.route('/api/allowed-ips', methods=["POST"])
@login_required
def api_allowed_ips_post():
    check_csrf()
    body = request.get_json(silent=True) or {}
    raw = body.get("allowed_ips") or request.form.get("allowed_ips") or ""
    cidrs, err = validate_cidr_list(raw)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    ok, msg = write_allowed_ips(cidrs)
    status = 200 if ok else 500
    return jsonify({"ok": ok, "message": msg, "cidrs": cidrs if ok else None}), status

@app.route('/api/wg-conf', methods=["GET"])
@login_required
def api_wg_conf_get():
    txt, err = read_wg_conf()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"ok": True, "raw": txt, "file": WG_CONF})


@app.route('/api/wg-conf', methods=["POST"])
@login_required
def api_wg_conf_post():
    check_csrf()
    body = request.get_json(silent=True) or {}
    raw = body.get("wg_conf") or body.get("config") or request.form.get("wg_conf") or ""
    if not raw or not raw.strip():
        return jsonify({"ok": False, "error": "Empty config — nothing to save."}), 400
    ok, msg = write_wg_conf(raw)
    status = 200 if ok else (400 if "Line " in msg or "must be" in msg or "Missing" in msg or "Unknown" in msg or "unknown" in msg or "invalid" in msg.lower() else 500)
    if ok:
        return jsonify({"ok": True, "message": msg}), 200
    return jsonify({"ok": False, "error": msg}), status


@app.route('/api/restart-wg', methods=["POST"])
@login_required
def api_restart_wg():
    check_csrf()
    body = request.get_json(silent=True) or {}
    confirm = body.get("confirm") or request.form.get("confirm") or ""
    if confirm.strip().lower() != "restart":
        return jsonify({"ok": False, "error": "Type 'restart' to confirm."}), 400
    ok, msg = restart_wg()
    status = 200 if ok else 500
    return jsonify({"ok": ok, "message": msg}), status


@app.route('/api/wg/peers', methods=["GET"])
@login_required
def api_wg_peers():
    try:
        with open(WG_CONF) as f:
            txt = f.read()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {WG_CONF}: {e}"}), 500
    live = wg_live_peers()
    peers = []
    for p in wg_parse_peers(txt):
        pub = p["public_key"]
        li = live.get(pub, {})
        peers.append({
            "name": p["name"], "public_key": pub,
            "public_short": (pub[:12] + "…") if len(pub) > 12 else pub,
            "allowed_ips": p["allowed_ips"],
            "deletable": wg_peer_deletable(p),
            "endpoint": li.get("endpoint"),
            "connected": bool(li.get("connected")),
            "handshake": li.get("handshake_human"),
            "rx": li.get("rx_human"), "tx": li.get("tx_human"),
            "has_client": os.path.isfile(os.path.join(PEER_DIR, (pub[:16] or "x") + ".conf")),
        })
    return jsonify({"ok": True, "peers": peers, "suggest_ip": wg_suggest_ip(txt),
                    "endpoint_default": wg_default_endpoint()})


@app.route('/api/wg/peers', methods=["POST"])
@login_required
def api_wg_peer_add():
    check_csrf()
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not PEER_NAME_RE.match(name):
        return jsonify({"ok": False, "error": "Name: A-Z a-z 0-9 . _ - (max 32, must start alnum)."}), 400
    try:
        with open(WG_CONF) as f:
            orig = f.read()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {WG_CONF}: {e}"}), 500
    existing = wg_parse_peers(orig)
    if any((p["name"] or "").split("—")[0].strip().lower() == name.lower() for p in existing):
        return jsonify({"ok": False, "error": f"A peer named '{name}' already exists."}), 409
    ip = (body.get("ip") or wg_suggest_ip(orig) or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "error": f"'{ip}' is not a valid IP address."}), 400
    if addr not in WG_HOME_NET or addr == WG_HOME_NET.network_address or str(addr).endswith(".0") or str(addr).endswith(".255"):
        return jsonify({"ok": False, "error": f"{ip} is not a usable host in 10.99.0.0/24."}), 400
    if int(addr) == int(WG_HOME_NET.network_address) + 1:
        return jsonify({"ok": False, "error": "10.99.0.1 is the server address."}), 400
    taken = set()
    for p in existing:
        for tok in p["allowed_ips"]:
            try:
                n = ipaddress.ip_network(tok, strict=False)
                if n.prefixlen == 32 and n.network_address in WG_HOME_NET:
                    taken.add(str(n.network_address))
            except ValueError:
                pass
    if str(addr) in taken:
        return jsonify({"ok": False, "error": f"{ip} is already assigned to a peer."}), 409
    endpoint = (body.get("endpoint") or "").strip() or wg_default_endpoint()
    if not re.match(r"^(.+):(\d+)$", endpoint) or not (1 <= int(endpoint.rsplit(":", 1)[1]) <= 65535):
        return jsonify({"ok": False, "error": "Endpoint must be host:port (1-65535)."}), 400
    dns = (body.get("dns") or "").strip()
    if dns and len(dns) > 253:
        return jsonify({"ok": False, "error": "DNS value too long."}), 400
    # Generate keypair (private key never leaves via argv)
    try:
        g = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=10)
        priv = (g.stdout or "").strip()
        p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, _ = p.communicate(priv + "\n", timeout=10)
        pub = (out or "").strip()
        if not priv or not pub or p.returncode != 0:
            raise OSError("key generation failed")
    except (OSError, subprocess.TimeoutExpired) as e:
        return jsonify({"ok": False, "error": f"Key generation failed: {e}"}), 500
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    block = (f"\n# {name} — added {stamp}\n[Peer]\nPublicKey = {pub}\n"
             f"AllowedIPs = {addr}/32\n")
    new_txt = orig.rstrip("\n") + "\n" + block
    normalized, err = validate_wg_conf(new_txt)
    if err:
        return jsonify({"ok": False, "error": f"Generated config invalid: {err}"}), 500
    try:
        wg_backup_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Backup failed, aborting: {e}"}), 500
    try:
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(normalized)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        os.chmod(WG_CONF, 0o600)
    except OSError as e:
        return jsonify({"ok": False, "error": f"Write failed: {e}"}), 500
    ok, sync_err = wg_syncconf()
    how = "applied live (no drop)"
    if not ok:
        ok2, msg2 = wg_apply_full_restart(orig)
        if not ok2:
            return jsonify({"ok": False, "error": msg2}), 500
        how = "interface restarted"
    client_conf = wg_client_config(priv, str(addr), endpoint, dns)
    try:
        os.makedirs(PEER_DIR, mode=0o700, exist_ok=True)
        with open(os.path.join(PEER_DIR, pub[:16] + ".conf"), "w") as f:
            f.write(f"# {name} — client config, generated {stamp}\n" + client_conf)
        os.chmod(os.path.join(PEER_DIR, pub[:16] + ".conf"), 0o600)
        with open(os.path.join(PEER_DIR, pub[:16] + ".png"), "wb") as f:
            f.write(wg_peer_qr_png(client_conf))
        os.chmod(os.path.join(PEER_DIR, pub[:16] + ".png"), 0o600)
    except OSError as e:
        return jsonify({"ok": True, "message": f"Peer added & {how}, but client files not saved: {e}",
                        "name": name, "ip": str(addr), "public_key": pub,
                        "client_conf": client_conf, "qr": None}), 200
    import base64
    with open(os.path.join(PEER_DIR, pub[:16] + ".png"), "rb") as f:
        qr_b64 = base64.b64encode(f.read()).decode()
    return jsonify({"ok": True, "message": f"Peer '{name}' added ({addr}) & {how}.",
                    "name": name, "ip": str(addr), "public_key": pub,
                    "client_conf": client_conf,
                    "qr": "data:image/png;base64," + qr_b64}), 200


@app.route('/api/wg/peers', methods=["DELETE"])
@login_required
def api_wg_peer_del():
    check_csrf()
    body = request.get_json(silent=True) or {}
    pub = (body.get("public_key") or "").strip()
    if not WG_KEY_RE.match(pub):
        return jsonify({"ok": False, "error": "Valid peer public key required."}), 400
    try:
        with open(WG_CONF) as f:
            orig = f.read()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {WG_CONF}: {e}"}), 500
    peers = wg_parse_peers(orig)
    hit = next((p for p in peers if p["public_key"] == pub), None)
    if not hit:
        return jsonify({"ok": False, "error": "Peer not found in wg0.conf."}), 404
    if not wg_peer_deletable(hit):
        return jsonify({"ok": False, "error": "Refusing to delete: not a road-warrior (/32) peer (site peer protected)."}), 403
    lines = orig.splitlines()
    # drop the [Peer] block plus directly preceding # comment lines
    s, e = hit["start"], hit.get("end", hit["start"])
    while s > 0 and lines[s - 1].strip().startswith(("#", ";")):
        s -= 1
    new_txt = "\n".join(lines[:s] + lines[e + 1:]).rstrip("\n") + "\n"
    normalized, err = validate_wg_conf(new_txt)
    if err:
        return jsonify({"ok": False, "error": f"Resulting config invalid: {err}"}), 500
    try:
        wg_backup_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Backup failed, aborting: {e}"}), 500
    try:
        fd = os.open(WG_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(normalized)
        os.rename(WG_CONF + ".tmp", WG_CONF)
        os.chmod(WG_CONF, 0o600)
    except OSError as e:
        return jsonify({"ok": False, "error": f"Write failed: {e}"}), 500
    r = subprocess.run(["wg", "set", WG_IFACE, "peer", pub, "remove"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        ok2, msg2 = wg_apply_full_restart(orig)
        if not ok2:
            return jsonify({"ok": False, "error": msg2}), 500
    else:
        for tok in hit["allowed_ips"]:
            subprocess.run(["ip", "route", "del", tok, "dev", WG_IFACE],
                           capture_output=True, timeout=5)
    for fn in (pub[:16] + ".conf", pub[:16] + ".png"):
        try:
            os.remove(os.path.join(PEER_DIR, fn))
        except OSError:
            pass
    return jsonify({"ok": True, "message": f"Peer '{hit['name'] or pub[:12]}' removed."}), 200


@app.route('/api/wg/peers/qr')
@login_required
def api_wg_peer_qr():
    pub = (request.args.get("pub") or "").strip()
    if not WG_KEY_RE.match(pub):
        abort(400)
    fp = os.path.join(PEER_DIR, pub[:16] + ".png")
    if not os.path.isfile(fp):
        abort(404)
    return send_file(fp, mimetype="image/png", download_name="wg-qr.png")


@app.route('/api/wg/peers/conf')
@login_required
def api_wg_peer_conf():
    pub = (request.args.get("pub") or "").strip()
    if not WG_KEY_RE.match(pub):
        abort(400)
    fp = os.path.join(PEER_DIR, pub[:16] + ".conf")
    if not os.path.isfile(fp):
        abort(404)
    return send_file(fp, as_attachment=True, download_name="wg-client.conf")


# ---------------- Configuration backup & restore ----------------

BACKUP_DIR = os.path.join(BASE_DIR, "backups")
BACKUP_FILES = [
    "/etc/network/interfaces",
    "/etc/wireguard/wg0.conf",
    "/etc/frr/frr.conf",
    "/etc/iptables/rules.v4",
    "/etc/iptables/rules.v6",
    "/etc/samba/smb.conf",
    "/etc/systemd/system/ns10.service",
]
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]+\.tar\.gz$")


def backup_safe_path(name):
    name = (name or "").strip()
    if not BACKUP_NAME_RE.match(name) or ".." in name or "/" in name:
        return None
    fp = os.path.realpath(os.path.join(BACKUP_DIR, name))
    if os.path.dirname(fp) != os.path.realpath(BACKUP_DIR):
        return None
    return fp if os.path.isfile(fp) else None


@app.route('/api/backups', methods=["GET"])
@login_required
def api_backups_list():
    items = []
    try:
        for fn in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if not BACKUP_NAME_RE.match(fn):
                continue
            fp = os.path.join(BACKUP_DIR, fn)
            try:
                st = os.stat(fp)
                items.append({"name": fn, "size": st.st_size,
                              "date": _myfmt(st.st_mtime)})
            except OSError:
                continue
    except OSError:
        pass
    return jsonify({"ok": True, "backups": items})


@app.route('/api/backups', methods=["POST"])
@login_required
def api_backup_create():
    check_csrf()
    import tarfile
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot create backup dir: {e}"}), 500
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"netbackup-{stamp}.tar.gz"
    fp = os.path.join(BACKUP_DIR, name)
    try:
        manifest = [f"host: {run_cmd('hostname')}", f"date: {_myt_now()}",
                    "files:"]
        with tarfile.open(fp, "w:gz") as tf:
            for src in BACKUP_FILES:
                if os.path.isfile(src):
                    tf.add(src, arcname=src.lstrip("/"))
                    manifest.append(f"  {src}")
                else:
                    manifest.append(f"  {src} (MISSING)")
        with open(os.path.join(BACKUP_DIR, "MANIFEST-" + stamp + ".txt"), "w") as f:
            f.write("\n".join(manifest) + "\n")
        os.chmod(fp, 0o600)
        stamps = sorted(f for f in os.listdir(BACKUP_DIR)
                        if f.startswith("netbackup-") and f.endswith(".tar.gz"))
        for old in stamps[:-20]:
            os.remove(os.path.join(BACKUP_DIR, old))
    except OSError as e:
        return jsonify({"ok": False, "error": f"Backup failed: {e}"}), 500
    st = os.stat(fp)
    return jsonify({"ok": True, "message": f"Backup {name} created.",
                    "name": name, "size": st.st_size}), 200


@app.route('/api/backups/download')
@login_required
def api_backup_download():
    fp = backup_safe_path(request.args.get("name"))
    if not fp:
        abort(400)
    return send_file(fp, as_attachment=True, download_name=os.path.basename(fp))


@app.route('/api/backups', methods=["DELETE"])
@login_required
def api_backup_delete():
    check_csrf()
    fp = backup_safe_path((request.get_json(silent=True) or {}).get("name"))
    if not fp:
        return jsonify({"ok": False, "error": "Backup not found."}), 404
    try:
        os.remove(fp)
    except OSError as e:
        return jsonify({"ok": False, "error": f"Delete failed: {e}"}), 500
    return jsonify({"ok": True, "message": "Backup deleted."})


@app.route('/api/backups/restore', methods=["POST"])
@login_required
def api_backup_restore():
    check_csrf()
    body = request.get_json(silent=True) or {}
    if (body.get("confirm") or "").strip().lower() != "restore":
        return jsonify({"ok": False, "error": "Type 'restore' to confirm."}), 400
    fp = backup_safe_path(body.get("name"))
    if not fp:
        return jsonify({"ok": False, "error": "Backup not found."}), 404
    import tarfile
    import tempfile
    steps = []
    # Pre-restore safety snapshot (best effort)
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        snap = os.path.join(BACKUP_DIR, "netbackup-prerestore-" +
                            datetime.now().strftime("%Y%m%d_%H%M%S") + ".tar.gz")
        with tarfile.open(snap, "w:gz") as tf:
            for src in BACKUP_FILES:
                if os.path.isfile(src):
                    tf.add(src, arcname=src.lstrip("/"))
        os.chmod(snap, 0o600)
        steps.append("pre-restore snapshot: OK")
    except OSError as e:
        steps.append(f"pre-restore snapshot: FAILED ({e})")
        return jsonify({"ok": False, "error": "Aborting: safety snapshot failed.", "steps": steps}), 500
    tmp = tempfile.mkdtemp(prefix="netrestore-")
    try:
        with tarfile.open(fp, "r:gz") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            for m in members:
                target = os.path.realpath(os.path.join(tmp, m.name))
                if not target.startswith(os.path.realpath(tmp) + os.sep):
                    return jsonify({"ok": False, "error": "Unsafe paths in archive, aborting.", "steps": steps}), 400
            tf.extractall(tmp, members=members)
    except (OSError, tarfile.TarError) as e:
        return jsonify({"ok": False, "error": f"Extract failed: {e}", "steps": steps}), 500
    applied = []
    for src in BACKUP_FILES:
        staged = os.path.join(tmp, src.lstrip("/"))
        if not os.path.isfile(staged):
            steps.append(f"{src}: not in backup, skipped")
            continue
        if src == WG_CONF:
            with open(staged) as f:
                _, err = validate_wg_conf(f.read())
            if err:
                steps.append(f"{src}: INVALID ({err}), skipped")
                continue
        if src == SMB_CONF:
            r = subprocess.run(["testparm", "-s", staged],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                steps.append(f"{src}: testparm FAILED, skipped")
                continue
        try:
            shutil.copy2(staged, src)
            if src == WG_CONF:
                os.chmod(src, 0o600)
            applied.append(src)
            steps.append(f"{src}: restored")
        except OSError as e:
            steps.append(f"{src}: write FAILED ({e})")
    shutil.rmtree(tmp, ignore_errors=True)
    # Apply live state (interfaces file intentionally NOT applied: needs reboot / ifup)
    if "/etc/iptables/rules.v4" in applied:
        r = subprocess.run(["iptables-restore", "/etc/iptables/rules.v4"],
                           capture_output=True, text=True, timeout=15)
        steps.append("iptables-restore v4: " + ("OK" if r.returncode == 0 else "FAILED"))
    if "/etc/iptables/rules.v6" in applied and os.path.isfile("/etc/iptables/rules.v6"):
        r = subprocess.run(["ip6tables-restore", "/etc/iptables/rules.v6"],
                           capture_output=True, text=True, timeout=15)
        steps.append("iptables-restore v6: " + ("OK" if r.returncode == 0 else "FAILED"))
    for svc, label in [("wg-quick@wg0", "wg-quick"), ("frr", "frr"),
                       ("smbd", "smbd"), ("ns10.service", "ns10")]:
        if ((svc == "wg-quick@wg0" and WG_CONF in applied)
                or (svc == "frr" and "/etc/frr/frr.conf" in applied)
                or (svc == "smbd" and SMB_CONF in applied)
                or (svc == "ns10.service" and "/etc/systemd/system/ns10.service" in applied)):
            r = subprocess.run(["systemctl", "restart", svc],
                               capture_output=True, text=True, timeout=30)
            steps.append(f"restart {label}: " + ("OK" if r.returncode == 0 else "FAILED"))
    if _SMB_CACHE["data"] is not None and SMB_CONF in applied:
        _SMB_CACHE["data"] = None
    steps.append("NOTE: /etc/network/interfaces needs reboot (or manual ifup) to apply.")
    return jsonify({"ok": True, "message": f"Restore applied ({len(applied)} file(s)).", "steps": steps}), 200


@app.route("/api/samba/restart", methods=["POST"])
@login_required
def api_samba_restart():
    check_csrf()
    body = request.get_json(silent=True) or {}
    confirm = body.get("confirm") or request.form.get("confirm") or ""
    if confirm.strip().lower() != "restart":
        return jsonify({"ok": False, "error": "Type 'restart' to confirm."}), 400
    ok, msg = restart_samba()
    _SMB_CACHE["data"] = None
    if ok:
        return jsonify({"ok": True, "message": msg}), 200
    return jsonify({"ok": False, "error": msg}), 500


@app.route("/api/samba/conf", methods=["GET"])
@login_required
def api_samba_conf_get():
    try:
        txt = smb_read_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {SMB_CONF}: {e}"}), 500
    return jsonify({"ok": True, "raw": txt, "file": SMB_CONF})


@app.route("/api/samba/conf", methods=["POST"])
@login_required
def api_samba_conf_post():
    check_csrf()
    body = request.get_json(silent=True) or {}
    raw = body.get("smb_conf") or body.get("config") or request.form.get("smb_conf") or ""
    if not raw or not raw.strip():
        return jsonify({"ok": False, "error": "Empty config — nothing to save."}), 400
    if len(raw) > 262144:
        return jsonify({"ok": False, "error": "Config too large (max 256KB)."}), 400
    if not re.search(r"^\[global\]", raw, re.M | re.I):
        return jsonify({"ok": False, "error": "Missing [global] section."}), 400
    try:
        orig = smb_read_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {SMB_CONF}: {e}"}), 500
    normalized = raw.rstrip("\n") + "\n"
    if normalized == orig:
        return jsonify({"ok": True, "message": "No changes."}), 200
    try:
        smb_backup_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Backup failed, aborting: {e}"}), 500
    try:
        smb_atomic_write(normalized)
    except OSError as e:
        return jsonify({"ok": False, "error": f"Write failed: {e}"}), 500
    ok, msg = smb_apply(orig)
    _SMB_CACHE["data"] = None
    if ok:
        return jsonify({"ok": True, "message": msg}), 200
    return jsonify({"ok": False, "error": msg}), 500

# ---------------- Service control (Setting tab) ----------------

SERVICE_UNITS = [
    ("wg-quick@wg0", "WireGuard tunnel (wg0)"),
    ("frr", "FRRouting (BGP/Zebra)"),
    ("smbd", "Samba (smbd)"),
    ("ns10.service", "Lab netns (ns10 on br10)"),
    ("netfilter-persistent", "Saved firewall rules loader"),
    ("networking", "Network interfaces (ifupdown)"),
     ("darkveda-lab", "This portal (darkveda-lab)"),
]
# Restarting networking drops this very session — status only, never restartable here.
SERVICE_NO_RESTART = {"networking"}


def lab_containers():
    """Lab-only Docker containers (Darkveda IPAM stack + big-bear apps)."""
    out = []
    try:
        r = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Image}} {{.Status}}"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                name, image, status = parts
                if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
                    continue
                if not (name.startswith(("darkveda", "big-bear"))
                        or "darkveda" in image):
                    continue
                out.append({"unit": name, "label": f"{name} ({image})", "kind": "docker",
                            "active": status, "enabled": "", "restartable": True})
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def service_status():
    units = []
    for unit, label in SERVICE_UNITS:
        try:
            a = subprocess.run(["systemctl", "is-active", unit],
                               capture_output=True, text=True, timeout=5)
            active = a.stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            active = "unknown"
        try:
            e = subprocess.run(["systemctl", "is-enabled", unit],
                               capture_output=True, text=True, timeout=5)
            enabled = e.stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            enabled = "unknown"
        units.append({"unit": unit, "label": label, "kind": "systemd",
                      "active": active, "enabled": enabled,
                      "restartable": unit not in SERVICE_NO_RESTART})
    return {"units": units, "containers": lab_containers()}


@app.route('/api/services', methods=["GET"])
@login_required
def api_services():
    # CTL_MODE=systemd (host install) vs supervisor (docker: systemctl is shimmed).
    # Enable/Disable only makes sense against real systemd — hide it otherwise.
    return jsonify({"ok": True, "ctl": os.environ.get("CTL_MODE", "systemd"),
                    **service_status()})


@app.route('/api/services/restart', methods=["POST"])
@login_required
def api_service_restart():
    check_csrf()
    body = request.get_json(silent=True) or {}
    if (body.get("confirm") or "").strip().lower() != "restart":
        return jsonify({"ok": False, "error": "Type 'restart' to confirm."}), 400
    kind = (body.get("kind") or "systemd").strip()
    unit = (body.get("unit") or "").strip()
    if kind == "systemd":
        allowed = {u for u, _ in SERVICE_UNITS} - SERVICE_NO_RESTART
        if unit not in allowed:
            return jsonify({"ok": False, "error": "Restart not allowed for this unit."}), 403
        if unit == "darkveda-lab":
            # Self-restart would kill this request mid-flight: schedule it via a
            # transient timer (outside our cgroup) and answer immediately.
            try:
                t = subprocess.run(["systemd-run", "--quiet", "--on-active=3",
                                    "/bin/systemctl", "restart", "darkveda-lab"],
                                   capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired) as e:
                return jsonify({"ok": False, "error": f"Scheduling failed: {e}"}), 500
            if t.returncode != 0:
                return jsonify({"ok": False, "error": (t.stderr or "scheduling failed").strip()[:200]}), 500
            return jsonify({"ok": True, "message": "Portal restart scheduled (~3s). Reload this page shortly."}), 200
        r = subprocess.run(["systemctl", "restart", unit],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return jsonify({"ok": False, "error": (r.stderr or r.stdout or "restart failed").strip()[:200]}), 500
        time.sleep(2)
        st = subprocess.run(["systemctl", "is-active", unit],
                            capture_output=True, text=True, timeout=5)
        if st.stdout.strip() != "active":
            return jsonify({"ok": False, "error": f"{unit} state after restart: {st.stdout.strip() or 'unknown'}."}), 500
        return jsonify({"ok": True, "message": f"{unit} restarted, active."}), 200
    if kind == "docker":
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", unit):
            return jsonify({"ok": False, "error": "Bad container name."}), 400
        live = {c["unit"] for c in service_status()["containers"]}
        if unit not in live:
            return jsonify({"ok": False, "error": "Container not running."}), 404
        r = subprocess.run(["docker", "restart", unit],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return jsonify({"ok": False, "error": (r.stderr or r.stdout or "restart failed").strip()[:200]}), 500
        return jsonify({"ok": True, "message": f"Container {unit} restarted."}), 200
    return jsonify({"ok": False, "error": "kind must be systemd or docker."}), 400


@app.route('/api/services/enable', methods=["POST"])
@login_required
def api_service_enable():
    check_csrf()
    body = request.get_json(silent=True) or {}
    unit = (body.get("unit") or "").strip()
    action = (body.get("action") or "").strip().lower()
    if action not in ("enable", "disable"):
        return jsonify({"ok": False, "error": "action must be enable or disable."}), 400
    if unit not in {u for u, _ in SERVICE_UNITS}:
        return jsonify({"ok": False, "error": "Unknown unit."}), 404
    r = subprocess.run(["systemctl", action, unit],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr or r.stdout or f"{action} failed").strip()[:200]}), 500
    st = subprocess.run(["systemctl", "is-enabled", unit],
                        capture_output=True, text=True, timeout=5)
    state = st.stdout.strip() or "unknown"
    if (action == "enable") != state.startswith("enabled"):
        return jsonify({"ok": False, "error": f"{unit} is-enabled now reports: {state}."}), 500
    return jsonify({"ok": True, "message": f"{unit} {action}d (autostart {state})."}), 200


@app.route('/api/logs', methods=["GET"])
@login_required
def api_logs():
    kind = (request.args.get("kind") or "systemd").strip()
    unit = (request.args.get("unit") or "").strip()
    try:
        lines = max(10, min(500, int(request.args.get("lines") or 100)))
    except ValueError:
        return jsonify({"ok": False, "error": "lines must be a number."}), 400
    if kind == "systemd":
        if unit not in {u for u, _ in SERVICE_UNITS}:
            return jsonify({"ok": False, "error": "Unknown unit."}), 404
        cmd = ["journalctl", "-u", unit, "--no-pager", "-n", str(lines),
               "--output=short-iso", "--no-hostname"]
    elif kind == "docker":
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", unit):
            return jsonify({"ok": False, "error": "Bad container name."}), 400
        if unit not in {c["unit"] for c in lab_containers()}:
            return jsonify({"ok": False, "error": "Container not running."}), 404
        cmd = ["docker", "logs", "--tail", str(lines), unit]
    else:
        return jsonify({"ok": False, "error": "kind must be systemd or docker."}), 400
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return jsonify({"ok": False, "error": f"log fetch failed: {e}"}), 500
    if r.returncode != 0 and not (r.stdout or "").strip():
        return jsonify({"ok": False, "error": (r.stderr or "log fetch failed").strip()[:200]}), 500
    return jsonify({"ok": True, "unit": unit, "kind": kind, "lines": lines,
                    "output": (r.stdout or "")[-200000:]}), 200


# ---------------- Samba management ----------------

SMB_CONF = "/etc/samba/smb.conf"
SMB_NAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,31}$")
RESERVED_SMB_SECTIONS = {"global", "printers", "print$"}
BAD_SMB_PATHS = {"/", "/etc", "/root", "/var", "/usr", "/bin", "/sbin", "/boot",
                 "/dev", "/proc", "/sys", "/run", "/lib", "/lib64", "/srv"}

def smb_service_status():
    active = run_cmd("systemctl is-active smbd") or "unknown"
    ver = run_cmd("smbd --version")
    return {"active": active, "version": (ver or "").strip() or "unknown"}

def smb_parse_shares():
    """Parse resolved shares from testparm -s."""
    try:
        r = subprocess.run(["testparm", "-s"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"testparm failed: {e}"
    shares, current = {}, None
    for line in (r.stdout or "").splitlines():
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            current = m.group(1)
            shares[current] = {}
            continue
        m = re.match(r"^\s+(\S.*?)\s*=\s*(.*)$", line)
        if m and current is not None:
            shares[current][m.group(1).strip().lower()] = m.group(2).strip()
    out = []
    for name, params in shares.items():
        if name in RESERVED_SMB_SECTIONS:
            continue
        wl = params.get("write list", "").strip()
        ro = params.get("read only", "").strip().lower()
        # New model: read only=yes + write list. Legacy: read only=no (all valid users write).
        writable = bool(wl) or ro in ("no", "false")
        out.append({
            "name": name,
            "path": params.get("path", ""),
            "comment": params.get("comment", ""),
            "valid_users": params.get("valid users", ""),
            "write_list": wl,
            "writable": writable,
            "hosts_allow": params.get("hosts allow", "ALL"),
        })
    return out, None

def smb_list_users():
    raw = run_cmd("pdbedit -L") or ""
    users = []
    for line in raw.splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[0]:
            users.append({"username": parts[0], "uid": parts[1]})
    return users

def smb_connections():
    try:
        r = subprocess.run(["smbstatus", "--brief"], capture_output=True, text=True, timeout=10)
        txt = (r.stdout or r.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        txt = f"smbstatus failed: {e}"
    return [l.rstrip() for l in txt.splitlines() if l.strip() and not re.match(r"^-{5,}", l.strip())]

def smb_connections_json():
    """Parse smbstatus --json into [{pid,user,ip,service}]. Falls back to brief parse."""
    try:
        r = subprocess.run(["smbstatus", "--json"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return [], ("smbstatus rc=%s: %s" % (r.returncode, (r.stderr or r.stdout or "").strip()[:200]))
        if not (r.stdout or "").strip():
            return [], "smbstatus returned empty output"
        j = json.loads(r.stdout)
        sess = j.get("sessions", {}) or {}
        tcons = j.get("tcons", {}) or {}
        rows = []
        for tid, tc in tcons.items():
            sid = tc.get("session_id", "")
            s = sess.get(str(sid), {}) or sess.get(sid, {}) or {}
            pid = str((tc.get("server_id") or {}).get("pid") or (s.get("server_id") or {}).get("pid") or "")
            if not pid:
                continue
            rows.append({
                "pid": pid,
                "user": s.get("username") or "",
                "ip": tc.get("machine") or s.get("remote_machine") or "",
                "service": tc.get("service") or "",
                "tcon": str(tid),
                "sid": str(sid),
            })
        # also bare sessions without tcon (idle)
        seen_pids = {x["pid"] for x in rows}
        for sid, s in sess.items():
            pid = str((s.get("server_id") or {}).get("pid") or "")
            if pid and pid not in seen_pids:
                rows.append({"pid": pid, "user": s.get("username") or "", "ip": s.get("remote_machine") or "", "service": "-", "tcon": "", "sid": str(sid)})
        return rows, None
    except Exception as ex:
        return [], str(ex)[:200]

def smb_share_usage(path):
    try:
        u = shutil.disk_usage(path)
        pct = int(u.used * 100 / u.total) if u.total else 0
        return {"total": u.total, "used": u.used, "free": u.free, "pct": pct}, None
    except Exception as ex:
        return None, str(ex)[:200]


def smb_read_conf():
    with open(SMB_CONF) as f:
        return f.read()

def smb_section_span(txt, name):
    """(start, end) char span of a [section] block including trailing newlines."""
    m = re.search(r"^\[" + re.escape(name) + r"\]\s*$", txt, re.M)
    if not m:
        return None
    m2 = re.search(r"^\[", txt[m.end():], re.M)
    end = m.end() + m2.start() if m2 else len(txt)
    return m.start(), end

def smb_backup_conf():
    d = os.path.dirname(SMB_CONF)
    stamps = sorted(f for f in os.listdir(d) if f.startswith("smb.conf.bak."))
    for old in stamps[:-4]:
        os.remove(os.path.join(d, old))
    shutil.copy2(SMB_CONF, SMB_CONF + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S"))

def smb_atomic_write(txt):
    fd = os.open(SMB_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(txt)
    os.rename(SMB_CONF + ".tmp", SMB_CONF)
    os.chmod(SMB_CONF, 0o644)

def smb_apply(orig_txt):
    """Validate with testparm, restart smbd. Rollback conf on invalid."""
    try:
        tp = subprocess.run(["testparm", "-s"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"testparm error: {e}"
    if tp.returncode != 0:
        try:
            smb_atomic_write(orig_txt)
        except OSError:
            pass
        err = (tp.stderr or tp.stdout or "testparm failed").strip()[:300]
        return False, f"Config invalid, rolled back. {err}"
    r = subprocess.run(["systemctl", "restart", "smbd"], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, "Config OK but smbd restart failed: " + (r.stderr or "").strip()[:200]
    return True, "Saved & applied. smbd restarted."

def smb_render_section(name, path, comment, valid_users, writable, hosts_allow, write_list=""):
    """Render a share. Access model: read only=yes + write list (per-user RW).
    No force user/group: daemons access files as the connecting user, so
    filesystem ACLs (managed alongside) are actually enforced per user."""
    vu = " ".join((valid_users or "").split())
    wl = " ".join((write_list or "").split())
    if writable and not wl:
        wl = vu
    lines = [f"[{name}]"]
    if comment:
        lines.append(f"   comment = {comment}")
    lines += [
        f"   path = {path}",
        "   browseable = yes",
        "   read only = yes",
        f"   valid users = {vu}",
    ]
    if wl:
        lines.append(f"   write list = {wl}")
    if hosts_allow:
        lines.append(f"   hosts allow = {hosts_allow}")
    lines += ["   hosts deny = 0.0.0.0/0",
              "   create mask = 0664",
              "   directory mask = 0775"]
    return "\n".join(lines) + "\n"


def smb_valid_username_list(raw):
    """Split + validate a space separated samba username list."""
    users = (raw or "").split()
    for u in users:
        if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", u):
            return None, f"bad username '{u}'"
    return users, None


def smb_system_user_exists(user):
    try:
        r = subprocess.run(["getent", "passwd", user],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and bool((r.stdout or "").strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def smb_account_exists(user):
    try:
        r = subprocess.run(["pdbedit", "-L", user],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and bool(re.search(rf"^{re.escape(user)}:", r.stdout or "", re.M))
    except (OSError, subprocess.TimeoutExpired):
        return False


def smb_path_acl(path, user, level):
    """Set (rw|ro) or remove (none) POSIX ACLs for user on path, recursive
    with defaults on dirs so new files inherit. Returns (ok, msg)."""
    if not os.path.isdir(path):
        return False, f"{path}: folder does not exist"
    if level == "none":
        seq = [
            ["setfacl", "-R", "-x", f"u:{user}", path],
        ]
        duo = ["find", path, "-type", "d", "-exec", "setfacl", "-d", "-x", f"u:{user}", "{}", "+"]
    elif level in ("rw", "ro"):
        fperm, dperm = ("rw", "rwx") if level == "rw" else ("r", "r-x")
        seq = [
            ["find", path, "-type", "f", "-exec", "setfacl", "-m", f"u:{user}:{fperm}", "{}", "+"],
            ["find", path, "-type", "d", "-exec", "setfacl", "-m", f"u:{user}:{dperm}", "{}", "+"],
            ["find", path, "-type", "d", "-exec", "setfacl", "-d", "-m", f"u:{user}:{dperm}", "{}", "+"],
        ]
        duo = None
    else:
        return False, f"bad level '{level}'"
    try:
        for cmd in seq:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return False, (r.stderr or r.stdout or "setfacl failed").strip()[:200]
        if duo:
            r = subprocess.run(duo, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return False, (r.stderr or r.stdout or "setfacl failed").strip()[:200]
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"ACL error: {e}"
    return True, f"{user} -> {level} on {path}"


def smb_ensure_share_dir(path):
    """mkdir -p a share folder owned by root with group-less 2770 + setgid,
    so file access is governed purely by per-user ACLs. Returns (ok, msg)."""
    try:
        os.makedirs(path, mode=0o2770, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, 0o2770)
    except OSError as e:
        return False, f"mkdir failed: {e}"
    return True, f"{path} ready (root:root 2770)"


def smb_sync_share_fs(path, valid_users, write_users):
    """Apply per-user ACLs for a share's membership. Returns [notes]."""
    notes = []
    write = set(write_users or [])
    for u in sorted(set(valid_users or []) | write):
        ok, msg = smb_path_acl(path, u, "rw" if u in write else "ro")
        notes.append(("ok: " if ok else "FS-WARN: ") + msg)
    return notes

def smb_validate_name(name):
    """Share names are case-insensitive in Samba, so normalize to lowercase
    (phone keyboards autocapitalize — without this every mobile entry fails).
    Returns (normalized_name, None) or (None, error)."""
    name = (name or "").strip()
    if not name:
        return None, "Name is required."
    if len(name) > 32:
        return None, "Name must be 32 characters or fewer."
    name = name.lower()
    if not SMB_NAME_RE.match(name):
        return None, "Name may only contain a-z, 0-9, - and _."
    if name.lower() in RESERVED_SMB_SECTIONS:
        return None, f"'{name}' is a reserved section."
    return name, None

def smb_validate_path(path):
    path = (path or "").strip()
    if not path.startswith("/") or ".." in path or not re.fullmatch(r"/[A-Za-z0-9._\-/ ]*", path):
        return None, "Path must be absolute, no '..'."
    real = os.path.realpath(path)
    if real in BAD_SMB_PATHS:
        return None, "Refusing to share a system root path."
    return real, None

# ---------------- Samba API routes ----------------

def smb_status_cached():
    now = time.time()
    if _SMB_CACHE["data"] is not None and (now - _SMB_CACHE["t"]) < _SMB_TTL:
        return _SMB_CACHE["data"]
    st = smb_service_status()
    shares, err = smb_parse_shares()
    users = smb_list_users()
    conns = smb_connections()
    conn_rows, _ = smb_connections_json()
    usage = {}
    for s in (shares if not err else []):
        p = (s.get("path") or "").strip()
        if p:
            u, _e = smb_share_usage(p)
            if u:
                usage[s["name"]] = u
    data = {"service": st, "shares": shares if not err else [], "share_error": err, "users": users, "connections": conns, "conn_rows": conn_rows, "usage": usage, "conf": SMB_CONF}
    _SMB_CACHE["data"] = data
    _SMB_CACHE["t"] = now
    return data


@app.route("/api/samba/status")
@login_required
def api_samba_status():
    return jsonify(smb_status_cached())

@app.route("/api/samba/sessions/kill", methods=["POST"])
@login_required
def api_samba_session_kill():
    check_csrf()
    d = request.get_json(silent=True) or {}
    pid = str(d.get("pid") or "").strip()
    if not re.fullmatch(r"\d+", pid):
        return jsonify({"ok": False, "error": "pid required (digits)"}), 400
    # allowlist: must be a live session pid from smbstatus
    live, live_err = smb_connections_json()
    if live_err and not live:
        return jsonify({"ok": False, "error": "smbstatus failed: %s" % live_err}), 500
    allowed = {r["pid"] for r in live if r.get("pid")}
    if pid not in allowed:
        return jsonify({"ok": False, "error": "pid not in active sessions allowlist"}), 400
    # prefer smbcontrol kill-client-ip / close-share if we have share/ip context, fallback to SIGTERM
    sess = next((r for r in live if r["pid"] == pid), {})
    share = (d.get("share") or sess.get("service") or "").strip()
    ip = (d.get("ip") or sess.get("ip") or "").strip()
    # try smbcontrol first (no shell). Extract IPv4 robustly from any format
    # e.g. "172.16.30.3", "172.16.30.3 (ipv4:172.16.30.3:50137)", "ipv4:172.16.30.3:50137"
    tried = []
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", ip or "")
    host = m.group(1) if m else ""
    if host:
        try:
            r = subprocess.run(["smbcontrol", "smbd", "kill-client-ip", host], capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                _SMB_CACHE["data"] = None
                return jsonify({"ok": True, "message": "killed client %s via smbcontrol" % host})
            tried.append("kill-client-ip: " + (r.stderr or r.stdout or "")[:120])
        except Exception as ex:
            tried.append(str(ex)[:120])
    if share and share not in ("-", "") and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", share):
        try:
            r = subprocess.run(["smbcontrol", pid, "close-share", share], capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                _SMB_CACHE["data"] = None
                return jsonify({"ok": True, "message": "closed share %s on pid %s" % (share, pid)})
            tried.append("close-share: " + (r.stderr or r.stdout or "")[:120])
        except Exception as ex:
            tried.append(str(ex)[:120])
    # fallback TERM then KILL
    try:
        import signal
        os.kill(int(pid), signal.SIGTERM)
        _SMB_CACHE["data"] = None
        return jsonify({"ok": True, "message": "SIGTERM sent to %s (%s)" % (pid, "; ".join(tried) if tried else "fallback")})
    except OSError as ex:
        return jsonify({"ok": False, "error": "kill failed: %s (%s)" % (ex, "; ".join(tried))}), 500


def _smb_inputs(d, need_name=True):
    """Validate common share inputs; returns (data, None) or (None, (msg, code))."""
    name = (d.get("name") or "").strip()
    if need_name:
        name, err = smb_validate_name(name)
        if err:
            return None, (err, 400)
    path, err = smb_validate_path(d.get("path"))
    if err:
        return None, (err, 400)
    comment = (d.get("comment") or "").strip()
    if not re.fullmatch(r"[\w .:\-/()]{0,64}", comment):
        return None, ("comment: only letters/numbers/space/:/.-()", 400)
    valid_users = (d.get("valid_users") or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_\- ]{0,200}", valid_users):
        return None, ("valid_users: samba usernames, space separated (a-z0-9_-)", 400)
    hosts_allow = (d.get("hosts_allow") or "").strip()
    if hosts_allow:
        cidrs, err = validate_cidr_list(hosts_allow)
        if err:
            return None, ("hosts allow: " + err, 400)
        hosts_allow = " ".join(cidrs)
    writable = bool(d.get("writable", True))
    return {"name": name, "path": path, "comment": comment,
            "valid_users": valid_users, "writable": writable,
            "hosts_allow": hosts_allow}, None

@app.route("/api/samba/shares", methods=["POST"])
@login_required
def api_samba_share_add():
    check_csrf()
    body = request.get_json(silent=True) or {}
    data, e = _smb_inputs(body)
    if e:
        return jsonify({"ok": False, "error": e[0]}), e[1]
    if not os.path.isdir(data["path"]):
        if not body.get("create_folder"):
            return jsonify({"ok": False, "error": f"Folder {data['path']} does not exist (tick 'create folder' to make it)."}), 400
        ok, msg = smb_ensure_share_dir(data["path"])
        if not ok:
            return jsonify({"ok": False, "error": msg}), 500
    txt = smb_read_conf()
    if smb_section_span(txt, data["name"]):
        return jsonify({"ok": False, "error": f"Share [{data['name']}] already exists"}), 409
    data["write_list"] = data["valid_users"] if data["writable"] else ""
    smb_backup_conf()
    new_txt = txt.rstrip("\n") + "\n\n" + smb_render_section(**data)
    try:
        smb_atomic_write(new_txt)
    except OSError as ex:
        return jsonify({"ok": False, "error": f"write failed: {ex}"}), 500
    ok, msg = smb_apply(txt)
    notes = smb_sync_share_fs(data["path"], data["valid_users"].split(), data["write_list"].split())
    _SMB_CACHE["data"] = None
    full = msg + (" | " + "; ".join(notes) if notes else "")
    return jsonify({"ok": ok, "message": full}), (200 if ok else 500)

@app.route("/api/samba/shares", methods=["PUT"])
@login_required
def api_samba_share_update():
    check_csrf()
    body = request.get_json(silent=True) or {}
    data, e = _smb_inputs(body)
    if e:
        return jsonify({"ok": False, "error": e[0]}), e[1]
    if not os.path.isdir(data["path"]):
        if not body.get("create_folder"):
            return jsonify({"ok": False, "error": f"Folder {data['path']} does not exist (tick 'create folder' to make it)."}), 400
        ok, msg = smb_ensure_share_dir(data["path"])
        if not ok:
            return jsonify({"ok": False, "error": msg}), 500
    txt = smb_read_conf()
    span = smb_section_span(txt, data["name"])
    if not span:
        return jsonify({"ok": False, "error": f"Share [{data['name']}] not found"}), 404
    # Preserve existing per-user RW grants that are still members when flipping writable.
    shares, _ = smb_parse_shares()
    cur = next((s for s in (shares or []) if s["name"] == data["name"]), None)
    cur_write = set((cur.get("write_list") or "").split()) if cur else set()
    new_valid = set(data["valid_users"].split())
    data["write_list"] = data["valid_users"] if data["writable"] else " ".join(sorted(cur_write & new_valid))
    smb_backup_conf()
    new_txt = txt[:span[0]] + smb_render_section(**data) + "\n" + txt[span[1]:]
    try:
        smb_atomic_write(new_txt)
    except OSError as ex:
        return jsonify({"ok": False, "error": f"write failed: {ex}"}), 500
    ok, msg = smb_apply(txt)
    notes = smb_sync_share_fs(data["path"], data["valid_users"].split(), data["write_list"].split())
    _SMB_CACHE["data"] = None
    full = msg + (" | " + "; ".join(notes) if notes else "")
    return jsonify({"ok": ok, "message": full}), (200 if ok else 500)

@app.route("/api/samba/shares", methods=["DELETE"])
@login_required
def api_samba_share_delete():
    check_csrf()
    name = ((request.get_json(silent=True) or {}).get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    if name in RESERVED_SMB_SECTIONS:
        return jsonify({"ok": False, "error": "Cannot delete built-in section"}), 403
    txt = smb_read_conf()
    span = smb_section_span(txt, name)
    if not span:
        return jsonify({"ok": False, "error": f"Share [{name}] not found"}), 404
    smb_backup_conf()
    new_txt = txt[:span[0]] + txt[span[1]:]
    try:
        smb_atomic_write(new_txt)
    except OSError as ex:
        return jsonify({"ok": False, "error": f"write failed: {ex}"}), 500
    ok, msg = smb_apply(txt)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)

@app.route("/api/samba/shares/browse")
@login_required
def api_samba_browse():
    """List files in a share path (read-only)."""
    name = (request.args.get("name") or "").strip()
    shares, err = smb_parse_shares()
    if err:
        return jsonify({"ok": False, "error": err}), 500
    share = next((s for s in shares if s["name"] == name), None)
    if not share:
        return jsonify({"ok": False, "error": "share not found"}), 404
    base = os.path.realpath(share["path"])
    sub = (request.args.get("sub") or "").strip()
    target = os.path.realpath(os.path.join(base, sub))
    if not (target == base or target.startswith(base + os.sep)):
        return jsonify({"ok": False, "error": "path escapes share"}), 400
    if not os.path.isdir(target):
        return jsonify({"ok": False, "error": "not a directory"}), 404
    items = []
    try:
        with os.scandir(target) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    items.append({
                        "name": e.name, "dir": e.is_dir(follow_symlinks=False),
                        "size": st.st_size,
                        "mtime": _myfmt(st.st_mtime, "%Y-%m-%d %H:%M"),
                    })
                except OSError:
                    continue
    except PermissionError:
        return jsonify({"ok": False, "error": "permission denied"}), 403
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return jsonify({"ok": True, "share": name, "path": target, "base": base,
                    "sub": sub, "items": items[:300], "total": len(items)})

@app.route("/api/samba/users", methods=["POST"])
@login_required
def api_samba_user_add():
    check_csrf()
    d = request.get_json(silent=True) or {}
    user = (d.get("username") or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", user):
        return jsonify({"ok": False, "error": "username: a-z, 0-9, -, _ (max 32)"}), 400
    pw = d.get("password") or ""
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return jsonify({"ok": False, "error": "password: min 8 chars, letters + numbers"}), 400
    # system user first (nologin)
    if not run_cmd(f"getent passwd {user}"):
        r = subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", user],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return jsonify({"ok": False, "error": "useradd failed: " + (r.stderr or "").strip()[:200]}), 500
    # samba account: password via stdin, never in argv/log
    try:
        p = subprocess.Popen(["smbpasswd", "-a", "-s", user],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        out, errtxt = p.communicate(f"{pw}\n{pw}\n", timeout=15)
        if p.returncode != 0:
            return jsonify({"ok": False, "error": (errtxt or out or "smbpasswd failed").strip()[:200]}), 500
    except (OSError, subprocess.TimeoutExpired) as ex:
        return jsonify({"ok": False, "error": f"smbpasswd error: {ex}"}), 500
    # Optional per-share access granted at creation time ({share: none|ro|rw})
    access = d.get("access") or {}
    notes = []
    if isinstance(access, dict) and access:
        shares, err = smb_parse_shares()
        if err:
            return jsonify({"ok": True, "message": f"User '{user}' added, but access not applied: {err}"}), 200
        try:
            txt = smb_read_conf()
        except OSError as e:
            return jsonify({"ok": True, "message": f"User '{user}' added, but access not applied: {e}"}), 200
        new_txt, notes, aerr = smb_apply_access_map(user, access, txt, {s["name"]: s for s in shares})
        if aerr:
            return jsonify({"ok": True, "message": f"User '{user}' added, but access not applied: {aerr}"}), 200
        if new_txt != txt:
            smb_backup_conf()
            try:
                smb_atomic_write(new_txt)
            except OSError as ex:
                return jsonify({"ok": True, "message": f"User '{user}' added, but access write failed: {ex}"}), 200
            ok, msg = smb_apply(txt)
            _SMB_CACHE["data"] = None
            notes.append(msg)
    msg = f"User '{user}' added to Samba"
    if notes:
        msg += " | " + "; ".join(notes)
    return jsonify({"ok": True, "message": msg})


def smb_effective_access(shares, users):
    """{username: {share: none|ro|rw}} from parsed shares + samba users."""
    out = {u["username"]: {} for u in users}
    for s in shares:
        valid = set((s.get("valid_users") or "").split())
        write = set((s.get("write_list") or "").split())
        legacy_open = bool(s.get("writable")) and not write
        for u in out:
            if u not in valid:
                out[u][s["name"]] = "none"
            elif u in write or legacy_open:
                out[u][s["name"]] = "rw"
            else:
                out[u][s["name"]] = "ro"
    return out


def smb_apply_access_map(username, access, txt, shares_by_name):
    """Rewrite conf sections + filesystem ACLs for one user's access map.
    access: {share: none|ro|rw}. Returns (new_txt, notes[], error|None).
    FS ACLs are applied before conf write; missing folders become warnings."""
    notes = []
    new_txt = txt
    for share, level in access.items():
        if share not in shares_by_name:
            return None, notes, f"Unknown share '{share}'."
        if level not in ("none", "ro", "rw"):
            return None, notes, f"Bad level '{level}' for '{share}' (none|ro|rw)."
        s = shares_by_name[share]
        valid = set((s.get("valid_users") or "").split())
        write = set((s.get("write_list") or "").split())
        if level == "none":
            valid.discard(username)
            write.discard(username)
        elif level == "ro":
            valid.add(username)
            write.discard(username)
        else:
            valid.add(username)
            write.add(username)
        span = smb_section_span(new_txt, share)
        if not span:
            return None, notes, f"Share [{share}] not found in smb.conf."
        rendered = smb_render_section(share, s["path"], s.get("comment", ""),
                                      " ".join(sorted(valid)), bool(write),
                                      s.get("hosts_allow", "") if s.get("hosts_allow") != "ALL" else "",
                                      " ".join(sorted(write)))
        new_txt = new_txt[:span[0]] + rendered + "\n" + new_txt[span[1]:]
        if s.get("path") and os.path.isdir(s["path"]):
            ok, msg = smb_path_acl(s["path"], username, "rw" if level == "rw" else ("ro" if level == "ro" else "none"))
            notes.append(("ok: " if ok else "FS-WARN: ") + msg)
            if not ok and level != "none":
                pass
        elif level != "none":
            notes.append(f"FS-WARN: {s.get('path') or '?'} missing — conf updated, ACL skipped")
    return new_txt, notes, None


@app.route("/api/samba/access", methods=["GET"])
@login_required
def api_samba_access_get():
    shares, err = smb_parse_shares()
    if err:
        return jsonify({"ok": False, "error": err}), 500
    users = smb_list_users()
    return jsonify({"ok": True, "shares": [{"name": s["name"], "path": s["path"]} for s in shares],
                    "access": smb_effective_access(shares, users)})


@app.route("/api/samba/access", methods=["POST"])
@login_required
def api_samba_access_post():
    check_csrf()
    d = request.get_json(silent=True) or {}
    user = (d.get("username") or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", user):
        return jsonify({"ok": False, "error": "bad username"}), 400
    if not smb_system_user_exists(user):
        return jsonify({"ok": False, "error": f"System user '{user}' does not exist."}), 404
    if not smb_account_exists(user):
        return jsonify({"ok": False, "error": f"No Samba account for '{user}' — add the user first."}), 404
    access = d.get("access") or {}
    if not isinstance(access, dict) or not access:
        return jsonify({"ok": False, "error": "access map required ({share: none|ro|rw})."}), 400
    shares, err = smb_parse_shares()
    if err:
        return jsonify({"ok": False, "error": err}), 500
    try:
        txt = smb_read_conf()
    except OSError as e:
        return jsonify({"ok": False, "error": f"Cannot read {SMB_CONF}: {e}"}), 500
    new_txt, notes, aerr = smb_apply_access_map(user, access, txt, {s["name"]: s for s in shares})
    if aerr:
        return jsonify({"ok": False, "error": aerr}), 400
    if new_txt == txt and not notes:
        return jsonify({"ok": True, "message": "No changes."}), 200
    smb_backup_conf()
    try:
        smb_atomic_write(new_txt)
    except OSError as ex:
        return jsonify({"ok": False, "error": f"write failed: {ex}"}), 500
    ok, msg = smb_apply(txt)
    _SMB_CACHE["data"] = None
    full = msg + (" | " + "; ".join(notes) if notes else "")
    return jsonify({"ok": ok, "message": full}), (200 if ok else 500)

@app.route("/api/samba/users", methods=["DELETE"])
@login_required
def api_samba_user_delete():
    check_csrf()
    user = ((request.get_json(silent=True) or {}).get("username") or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", user):
        return jsonify({"ok": False, "error": "bad username"}), 400
    r = subprocess.run(["smbpasswd", "-x", user], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr or r.stdout or "").strip()[:200]}), 500
    return jsonify({"ok": True, "message": f"Removed '{user}' from Samba (system user kept)"})

@app.route("/api/samba/users", methods=["PUT"])
@login_required
def api_samba_user_password():
    """Set/reset password for existing samba user."""
    check_csrf()
    d = request.get_json(silent=True) or {}
    user = (d.get("username") or "").strip()
    pw = d.get("password") or ""
    if not re.fullmatch(r"[a-z_][a-z0-9_\-]{0,31}", user):
        return jsonify({"ok": False, "error": "bad username"}), 400
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return jsonify({"ok": False, "error": "password: min 8 chars, letters + numbers"}), 400
    try:
        p = subprocess.Popen(["smbpasswd", "-s", user],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        out, errtxt = p.communicate(f"{pw}\n{pw}\n", timeout=15)
        if p.returncode != 0:
            return jsonify({"ok": False, "error": (errtxt or out or "failed").strip()[:200]}), 500
    except (OSError, subprocess.TimeoutExpired) as ex:
        return jsonify({"ok": False, "error": f"smbpasswd error: {ex}"}), 500
    return jsonify({"ok": True, "message": f"Password updated for '{user}'"})

# ---------------- MVNBC (Multi-Vendor Network Backup Config) ----------------
# Container-friendly: MVNBC_DIR env (default keeps historic host path).
MVNBC_DIR = os.environ.get("MVNBC_DIR", "/root/MVNBC_Dashboard")
MVNBC_CONF = os.path.join(MVNBC_DIR, "config", "devices.conf")
MVNBC_BACKUPS = os.path.join(MVNBC_DIR, "backups")
MVNBC_LOGS = os.path.join(MVNBC_DIR, "logs")
MVNBC_SCRIPT = os.path.join(MVNBC_DIR, "MVNBC.sh")
MVNPC_LOCK = os.path.join(MVNBC_LOGS, ".run.lock")


def mvnbc_devices():
    """Parse devices.conf -> [{vendor, ip, user}]. Passwords NEVER leave this function."""
    out = []
    try:
        with open(MVNBC_CONF) as fh:
            raw = fh.read()
    except OSError:
        return out
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        out.append({"vendor": parts[0], "ip": parts[1],
                    "user": parts[2] if len(parts) > 2 else ""})
    return out


def mvnbc_validate(vendor, path):
    """Port of MVNBC.sh validate_backup() / api_stats.php validateBackup()."""
    try:
        if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
            return False
        with open(path, "r", errors="replace") as fh:
            content = fh.read(300000)
    except OSError:
        return False
    v = (vendor or "").lower()
    err = ("SSH CONNECTION FAILED|LOGIN FAILED|TIMEOUT|Connection refused|"
           "No route to host|Connection timed out|Permission denied")
    try:
        if v == "cisco":
            return bool(re.search(r"Current configuration|Building configuration|^hostname ", content, re.M))
        if v == "ciscoasa":
            return bool(re.search(r"^ASA Version|^hostname ", content, re.M))
        if v == "mikrotik":
            return ("RouterOS" in content and
                    bool(re.search(r"/interface|/ip |/system ", content)))
        if v in ("h3c", "h3c_1920"):
            if re.search(err, content, re.I):
                return False
            return bool(re.search(r"^sysname |System View|display cu|display current-configuration", content, re.M))
        if v == "arista":
            if re.search(err, content, re.I):
                return False
            return bool(re.search(r"! Command: show running-config|^hostname |interface Ethernet|router ", content, re.M | re.I))
        if v == "aruba":
            if re.search(err, content, re.I):
                return False
            return bool(re.search(r"Current configuration:|^hostname |^user admin |^vlan ", content, re.M | re.I))
        if v == "fortigate":
            if re.search(err, content, re.I):
                return False
            return bool(re.search(r"#config-version=|^config system|^config firewall", content, re.M | re.I))
        if v == "juniper":
            if re.search(err, content, re.I):
                return False
            return bool(re.search(r"^set system|^set interfaces|^set routing-options|^set security", content, re.M))
    except re.error:
        return os.path.getsize(path) > 0
    return os.path.getsize(path) > 0


def mvnbc_safe_file(rel, kind="b"):
    """Resolve rel under backups/ (kind=b, 'vendor/file') or logs/ (kind=l, basename)."""
    rel = (rel or "").strip()
    if not rel or chr(0) in rel:
        return None
    if kind == "l":
        if "/" in rel or ".." in rel:
            return None
        base, target = MVNBC_LOGS, os.path.join(MVNBC_LOGS, rel)
    else:
        if ".." in rel:
            return None
        base, target = MVNBC_BACKUPS, os.path.join(MVNBC_BACKUPS, rel)
    try:
        rb, rt = os.path.realpath(base), os.path.realpath(target)
    except OSError:
        return None
    if not (rt == rb or rt.startswith(rb + os.sep)):
        return None
    return rt if os.path.isfile(rt) else None


def mvnbc_run_status():
    running, lock_pid = False, 0
    try:
        with open(MVNPC_LOCK) as fh:
            lock_pid = int(fh.read().strip() or "0")
    except (OSError, ValueError):
        lock_pid = 0
    if lock_pid > 0:
        try:
            with open("/proc/%d/cmdline" % lock_pid, "rb") as fh:
                running = b"MVNBC" in fh.read()
        except OSError:
            running = False
    logs = []
    if os.path.isdir(MVNBC_LOGS):
        try:
            names = [n for n in os.listdir(MVNBC_LOGS)
                     if n.startswith("run_") and n.endswith(".log")]
        except OSError:
            names = []
        names.sort(key=lambda n: os.path.getmtime(os.path.join(MVNBC_LOGS, n)),
                   reverse=True)
        for n in names[:50]:
            fp = os.path.join(MVNBC_LOGS, n)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            logs.append({"name": n, "size": round(st.st_size / 1024, 2),
                         "date": _myfmt(st.st_mtime)})
    latest = logs[0]["name"] if logs else None
    ok = fail = 0
    done = False
    tail = []
    if latest:
        try:
            with open(os.path.join(MVNBC_LOGS, latest), "r", errors="replace") as fh:
                lines = fh.read().splitlines()
            for ln in lines:
                if ln.startswith("[OK] Backup saved:"):
                    ok += 1
                elif ln.startswith("[FAIL]"):
                    fail += 1
                elif ln.startswith("[DONE]"):
                    done = True
            tail = [t for t in (x.strip() for x in lines) if t][-8:]
        except OSError:
            pass
    return {"running": running, "ok": ok, "fail": fail, "done": done,
            "log": latest, "lines": tail, "logs": logs}


def mvnbc_cron():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in (r.stdout or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "MVNBC.sh" in s:
            return s
    return None


@app.route("/api/mvnbc/summary")
@login_required
def api_mvnbc_summary():
    now = time.time()
    rows, ok_c, fail_c = [], 0, 0
    for d in mvnbc_devices():
        latest, latest_mt = None, None
        vdir = os.path.join(MVNBC_BACKUPS, d["vendor"])
        if os.path.isdir(vdir):
            try:
                cands = [f for f in os.listdir(vdir)
                         if f.startswith(d["ip"] + "_") and f.endswith(".log")]
            except OSError:
                cands = []
            cands.sort(key=lambda f: os.path.getmtime(os.path.join(vdir, f)), reverse=True)
            fresh = [f for f in cands if now - os.path.getmtime(os.path.join(vdir, f)) > 30]
            pick = (fresh or cands or [None])[0]
            if pick:
                latest = os.path.join(vdir, pick)
                latest_mt = os.path.getmtime(latest)
        valid = mvnbc_validate(d["vendor"], latest) if latest else False
        if valid:
            ok_c += 1
        else:
            fail_c += 1
        rows.append({
            "vendor": d["vendor"], "ip": d["ip"], "user": d["user"],
            "status": "OK" if valid else "FAIL",
            "latest": os.path.basename(latest) if latest else None,
            "date": _myfmt(latest_mt) if latest_mt else None,
            "age": int(now - latest_mt) if latest_mt else None,
            "size": round(os.path.getsize(latest) / 1024, 2) if latest else 0,
        })
    file_total = file_ok = file_fail = 0
    newest = None
    if os.path.isdir(MVNBC_BACKUPS):
        for vf in sorted(os.listdir(MVNBC_BACKUPS)):
            vdir = os.path.join(MVNBC_BACKUPS, vf)
            if not os.path.isdir(vdir):
                continue
            try:
                fns = os.listdir(vdir)
            except OSError:
                continue
            for fn in fns:
                fp = os.path.join(vdir, fn)
                if not os.path.isfile(fp):
                    continue
                file_total += 1
                if mvnbc_validate(vf, fp):
                    file_ok += 1
                else:
                    file_fail += 1
                mt = os.path.getmtime(fp)
                if newest is None or mt > newest[0]:
                    newest = (mt, fn, vf)
    _cr = mvnbc_cron()
    _nr0, _nr1 = (mvnbc_next_run(" ".join(_cr.split()[:5])) if _cr else (None, None))
    return jsonify({
        "devices": rows, "total": len(rows), "ok": ok_c, "fail": fail_c,
        "files": {"total": file_total, "ok": file_ok, "fail": file_fail},
        "newest": ({"name": newest[1], "vendor": newest[2],
                    "date": _myfmt(newest[0])}
                   if newest else None),
        "run": mvnbc_run_status(),
        "cron": _cr,
        "has_script": os.path.isfile(MVNBC_SCRIPT),
        "next_run": {"epoch": _nr0, "human": _nr1},
    })


@app.route("/api/mvnbc/run-status")
@login_required
def api_mvnbc_run_status():
    return jsonify(mvnbc_run_status())


@app.route("/api/mvnbc/files")
@login_required
def api_mvnbc_files():
    q = (request.args.get("q") or "").strip().lower()
    groups = []
    if os.path.isdir(MVNBC_BACKUPS):
        for vf in sorted(os.listdir(MVNBC_BACKUPS)):
            vdir = os.path.join(MVNBC_BACKUPS, vf)
            if not os.path.isdir(vdir):
                continue
            try:
                fns = os.listdir(vdir)
            except OSError:
                continue
            items = []
            for fn in fns:
                fp = os.path.join(vdir, fn)
                if not os.path.isfile(fp):
                    continue
                try:
                    st = os.stat(fp)
                except OSError:
                    continue
                date = _myfmt(st.st_mtime)
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", fn)
                ip = m.group(1) if m else "unknown"
                if q and q not in (vf + " " + ip + " " + fn + " " + date).lower():
                    continue
                items.append({"name": fn, "ip": ip, "size": round(st.st_size / 1024, 2),
                              "date": date,
                              "status": "OK" if mvnbc_validate(vf, fp) else "FAIL"})
            items.sort(key=lambda x: x["date"], reverse=True)
            groups.append({"vendor": vf, "files": items})
    return jsonify({"groups": groups, "total": sum(len(g["files"]) for g in groups)})


@app.route("/api/mvnbc/file")
@login_required
def api_mvnbc_file():
    kind = request.args.get("k") or "b"
    if kind not in ("b", "l"):
        return jsonify({"ok": False, "error": "bad kind"}), 400
    fp = mvnbc_safe_file(request.args.get("p"), kind)
    if not fp:
        return jsonify({"ok": False, "error": "invalid file"}), 400
    try:
        with open(fp, "r", errors="replace") as fh:
            data = fh.read(300000)
        size = round(os.path.getsize(fp) / 1024, 2)
    except OSError as ex:
        return jsonify({"ok": False, "error": "read failed: %s" % ex}), 500
    return jsonify({"ok": True, "name": os.path.basename(fp), "size": size, "content": data})


@app.route("/api/mvnbc/download")
@login_required
def api_mvnbc_download():
    kind = request.args.get("k") or "b"
    if kind not in ("b", "l"):
        abort(400)
    fp = mvnbc_safe_file(request.args.get("p"), kind)
    if not fp:
        abort(400)
    return send_file(fp, as_attachment=True, download_name=os.path.basename(fp))


@app.route("/api/mvnbc/delete", methods=["POST"])
@login_required
def api_mvnbc_delete():
    check_csrf()
    d = request.get_json(silent=True) or {}
    kind = d.get("k") or "b"
    rel = d.get("p") or ""
    if kind not in ("b", "l"):
        return jsonify({"ok": False, "error": "bad kind"}), 400
    fp = mvnbc_safe_file(rel, kind)
    if not fp:
        return jsonify({"ok": False, "error": "invalid file"}), 400
    try:
        os.remove(fp)
    except OSError as ex:
        return jsonify({"ok": False, "error": "delete failed: %s" % ex}), 500
    return jsonify({"ok": True, "message": "Deleted %s" % os.path.basename(fp)})



@app.route("/api/mvnbc/bulk-delete", methods=["POST"])
@login_required
def api_mvnbc_bulk_delete():
    check_csrf()
    d = request.get_json(silent=True) or {}
    files = d.get("files") or d.get("paths") or d.get("selected") or []
    if not isinstance(files, list):
        files = [files] if files else []
    ok = 0; fail = 0
    for it in files:
        if isinstance(it, dict):
            k = it.get("k") or it.get("kind") or "b"
            p = it.get("p") or it.get("path") or it.get("file") or ""
        else:
            k = "b"; p = str(it)
        fp = mvnbc_safe_file(p, k)
        if not fp:
            fail+=1; continue
        try:
            os.remove(fp); ok+=1
            mvnbc_audit("backup bulk-delete", p)
        except Exception:
            fail+=1
    return jsonify({"ok": fail==0, "deleted": ok, "failed": fail, "message": "%d deleted, %d failed" % (ok, fail)})

@app.route("/api/mvnbc/download-zip", methods=["GET", "POST"])
@login_required
def api_mvnbc_download_zip():
    import tempfile as _tf
    vendor = (request.args.get("vendor") or "").strip()
    files = None
    label = "selected"
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        if d.get("vendor"): vendor = str(d.get("vendor")).strip()
        files = d.get("files") or d.get("paths") or d.get("selected")
        if isinstance(files, str): files=[files]
    tmp = _tf.mktemp(suffix=".zip")
    added = 0
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            if files:
                for it in files:
                    if isinstance(it, dict):
                        k=it.get("k") or "b"; p=it.get("p") or ""
                    else:
                        k="b"; p=str(it)
                    fp = mvnbc_safe_file(p, k)
                    if not fp or not os.path.isfile(fp): continue
                    arc = p if "/" in p else os.path.basename(fp)
                    zf.write(fp, arc); added+=1
                label="selected"
            elif vendor == "__all__" or vendor == "":
                if not os.path.isdir(MVNBC_BACKUPS):
                    return jsonify({"ok":False,"error":"no backups"}),404
                for vd in sorted(os.listdir(MVNBC_BACKUPS)):
                    vdir=os.path.join(MVNBC_BACKUPS, vd)
                    if not os.path.isdir(vdir): continue
                    for root, dirs, fns in os.walk(vdir):
                        for fn in fns:
                            if fn==".gitkeep": continue
                            fp=os.path.join(root,fn)
                            arc=os.path.relpath(fp, MVNBC_BACKUPS)
                            zf.write(fp, arc); added+=1
                label="all"; vendor="__all__"
            else:
                if not re.fullmatch(r"[A-Za-z0-9_-]+", vendor):
                    return jsonify({"ok":False,"error":"invalid vendor"}),400
                vdir=os.path.join(MVNBC_BACKUPS, vendor)
                rp=os.path.realpath(vdir) if os.path.exists(vdir) else ""
                rb=os.path.realpath(MVNBC_BACKUPS)
                if not rp or not (rp==rb or rp.startswith(rb+os.sep)) or not os.path.isdir(vdir):
                    return jsonify({"ok":False,"error":"vendor not found"}),404
                for root, dirs, fns in os.walk(vdir):
                    for fn in fns:
                        if fn==".gitkeep": continue
                        fp=os.path.join(root,fn)
                        arc=os.path.relpath(fp, MVNBC_BACKUPS)
                        zf.write(fp, arc); added+=1
                label=vendor
            if added==0:
                return jsonify({"ok":False,"error":"no files to zip"}),404
        stamp=_myt_now("%Y%m%d_%H%M%S")
        if label=="all":
            name="mvnbc_backups_all_%s.zip" % stamp
        elif label=="selected":
            name="mvnbc_selected_%s.zip" % stamp
        else:
            name="mvnbc_backups_%s_%s.zip" % (label, stamp)
        return send_file(tmp, as_attachment=True, download_name=name, mimetype="application/zip")
    except Exception as ex:
        return jsonify({"ok":False,"error":str(ex)}),500
@app.route("/api/mvnbc/run", methods=["POST"])
@login_required
def api_mvnbc_run():
    check_csrf()
    if not os.path.isfile(MVNBC_SCRIPT):
        return jsonify({"ok": False, "error": "MVNBC.sh not found"}), 404
    st = mvnbc_run_status()
    if st["running"]:
        return jsonify({"ok": False, "error": "A backup is already running"}), 409
    os.makedirs(MVNBC_LOGS, exist_ok=True)
    try:
        env = dict(os.environ); env["TZ"] = MYTZ_NAME; env["MVNBC_NOTIFY"] = "python"
        try:
            import time as _tz; _tz.tzset()
        except Exception:
            pass
        p = subprocess.Popen(
            ["/bin/bash", MVNBC_SCRIPT, "--auto"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, cwd=MVNBC_DIR,
            env=env
        )
    except OSError as ex:
        return jsonify({"ok": False, "error": "launch failed: %s" % ex}), 500
    try:
        with open(MVNPC_LOCK, "w") as fh:
            fh.write(str(p.pid))
    except OSError:
        pass
    mvnbc_watch_and_notify(p.pid)
    return jsonify({"ok": True, "pid": p.pid})

# ---------------- MVNBC PHASE 2: devices CRUD, compare, alerts, schedule ----------------
import json as _mjson
import threading as _mthread
import difflib as _mdiff
import smtplib as _msmtp
import ssl as _mssl
import socket as _msocket
import urllib.request as _murlreq
import urllib.parse as _murlparse

MVNBC_SETTINGS = os.path.join(MVNBC_DIR, "config", "settings.json")
MVNBC_AUDIT = os.path.join(MVNBC_LOGS, "audit.log")
MVNBC_VENDORS_BUILTIN = ("arista", "aruba", "arubacx", "cisco", "ciscoasa",
                 "fortigate", "h3c", "h3c_1920", "juniper", "mikrotik")
MVNBC_VENDORS = MVNBC_VENDORS_BUILTIN

def mvnbc_discover_vendors():
    """Built-ins + any <vendor>.exp in templates dir (custom templates)."""
    found = set(MVNBC_VENDORS_BUILTIN)
    try:
        tdir = os.path.join(MVNBC_DIR, "templates")
        for fn in os.listdir(tdir):
            if fn.endswith(".exp") and len(fn) > 4:
                v = fn[:-4].lower()
                if re.match(r"^[a-z0-9_\-]+$", v):
                    found.add(v)
    except OSError:
        pass
    return sorted(found)

def mvnbc_template_path(vendor):
    p = os.path.join(MVNBC_DIR, "templates", vendor + ".exp")
    return p if os.path.isfile(p) else None
MVNBC_ALERT_DEFAULTS = {
    "alerts": {"notify_on": "failure"},
    "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "smtp_secure": "tls",
              "username": "", "password": "", "from": "", "to": ""},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "retention": {"keep_backups": 50, "keep_logs": 30, "auto_prune_30d": False, "max_age_days": 30},
}


def mvnbc_audit(action, detail=""):
    """Append to logs/audit.log (never raises)."""
    try:
        os.makedirs(MVNBC_LOGS, exist_ok=True)
        with open(MVNBC_AUDIT, "a") as fh:
            fh.write("%s | %s | %s\n" % (_myt_now(),
                                         action, detail))
    except OSError:
        pass


@app.route("/api/ipam/summary")
@login_required
def api_ipam_summary():
    try:
        return jsonify(_ipam_summary_cached())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500

@app.route("/api/ipam/subnet/<int:sid>/ips")
@login_required
def api_ipam_subnet_ips(sid):
    try:
        c = _ipam_conn()
        try:
            cur = c.cursor()
            cur.execute("SELECT cidr, name FROM subnets WHERE id=%s", (sid,))
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "subnet not found"}), 404
            cur.execute("""SELECT address, status, hostname, mac_address, description, last_seen
                           FROM ip_addresses WHERE subnet_id=%s ORDER BY INET_ATON(address)""", (sid,))
            ips = [{"address": a, "status": s, "hostname": h, "mac": m, "description": d,
                    "last_seen": str(ls) if ls else None} for a, s, h, m, d, ls in cur.fetchall()]
            return jsonify({"ok": True, "cidr": row[0], "name": row[1], "ips": ips})
        finally:
            try:
                c.close()
            except Exception:
                pass
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500

@app.route("/api/ipam/subnet", methods=["POST"])
@login_required
def api_ipam_subnet_create():
    check_csrf()
    try:
        d = request.get_json(force=True) or {}
        cidr = (d.get("cidr") or "").strip()
        name = (d.get("name") or "").strip() or None
        gw = (d.get("gateway") or "").strip() or None
        desc = (d.get("description") or "").strip() or None
        try:
            import ipaddress as _ip
            import socket as _so
            net = _ip.ip_network(cidr, strict=False)
            nbin = _so.inet_pton(_so.AF_INET6 if net.version == 6 else _so.AF_INET, str(net.network_address))
            ver = net.version
            plen = net.prefixlen
        except Exception:
            return jsonify({"ok": False, "error": "invalid CIDR"}), 400
        c = _ipam_conn()
        try:
            cur = c.cursor()
            cur.execute("""INSERT INTO subnets (cidr, network_bin, prefix_len, ip_version, name, gateway, status, description)
                           VALUES (%s,%s,%s,%s,%s,%s,'active',%s)""",
                        (f"{net.network_address}/{plen}", nbin, plen, ver, name, gw, desc))
        finally:
            try:
                c.close()
            except Exception:
                pass
        _IPAM_CACHE["t"] = 0
        try:
            mvnbc_audit("ipam subnet create", cidr)
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        msg = str(e)
        if "Duplicate" in msg:
            return jsonify({"ok": False, "error": "subnet already exists"}), 400
        return jsonify({"ok": False, "error": msg[:200]}), 500


# ---------------- Portal tabs visibility (Setting card: hide/unhide cards) ----------------
PORTAL_TABS_FILE = os.path.join(BASE_DIR, "portal_tabs.json")
PORTAL_TABS_ALLOWED = ("wg", "mvnbc", "smb", "ipam", "backup", "logviewer")
PORTAL_TABS_DEFAULT = {"wg": True, "mvnbc": True, "smb": True, "ipam": True, "backup": True, "logviewer": True}

def portal_tabs_load():
    """Load tab/card visibility map. Defaults to all visible."""
    data = dict(PORTAL_TABS_DEFAULT)
    try:
        with open(PORTAL_TABS_FILE) as fh:
            raw = fh.read().strip()
        if raw:
            got = json.loads(raw)
            if isinstance(got, dict):
                for k in PORTAL_TABS_ALLOWED:
                    if isinstance(got.get(k), bool):
                        data[k] = got[k]
    except (OSError, ValueError):
        pass
    return data

def portal_tabs_save(tabs):
    try:
        clean = {k: bool(tabs.get(k, True)) for k in PORTAL_TABS_ALLOWED}
        fd = os.open(PORTAL_TABS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w") as fh:
            json.dump(clean, fh, indent=2)
        return True, clean
    except OSError as ex:
        return False, str(ex)

@app.route("/api/portal/tabs")
@login_required
def api_portal_tabs():
    return jsonify({"ok": True, "tabs": portal_tabs_load()})

@app.route("/api/portal/tabs/save", methods=["POST"])
@login_required
def api_portal_tabs_save():
    check_csrf()
    d = request.get_json(silent=True) or {}
    tabs = d.get("tabs") or d
    if not isinstance(tabs, dict):
        return jsonify({"ok": False, "error": "tabs object required"}), 400
    clean = {}
    for k in PORTAL_TABS_ALLOWED:
        if k in tabs:
            v = tabs[k]
            if isinstance(v, bool):
                clean[k] = v
            elif isinstance(v, (int, float)):
                clean[k] = bool(v)
            elif isinstance(v, str):
                clean[k] = v.strip().lower() in ("1", "true", "yes", "on")
            else:
                return jsonify({"ok": False, "error": "bad value for '%s'" % k}), 400
        else:
            clean[k] = portal_tabs_load().get(k, True)
    ok, res = portal_tabs_save(clean)
    if not ok:
        return jsonify({"ok": False, "error": res}), 500
    try:
        mvnbc_audit("portal tabs save", str(res))
    except Exception:
        pass
    return jsonify({"ok": True, "tabs": res})



def mvnbc_load_devices_rows():
    """Full parse of devices.conf -> [{vendor, ip, user, pass, enable}]. NEVER sent to client."""
    rows = []
    try:
        with open(MVNBC_CONF) as fh:
            raw = fh.read()
    except OSError:
        return rows
    for line in raw.replace("\r\n", "\n").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = [x.strip() for x in line.split(",")]
        if len(p) < 4:
            continue
        rows.append({"vendor": p[0], "ip": p[1], "user": p[2], "pass": p[3],
                     "enable": p[4] if len(p) > 4 else ""})
    return rows


def mvnbc_write_devices_rows(rows):
    """Write devices.conf (LOCK_EX, chmod 600) + audit. Format: vendor,ip,user,pass[,enable]."""
    lines = []
    for r in rows:
        ln = "%s,%s,%s,%s" % (r["vendor"], r["ip"], r["user"], r["pass"])
        if r.get("enable"):
            ln += "," + r["enable"]
        lines.append(ln)
    data = "\n".join(lines) + ("\n" if lines else "")
    try:
        os.makedirs(os.path.dirname(MVNBC_CONF), exist_ok=True)
        with open(MVNBC_CONF, "w") as fh:
            fh.write(data)
        os.chmod(MVNBC_CONF, 0o600)
    except OSError as ex:
        return False, "Could not write devices.conf: %s" % ex
    mvnbc_audit("devices.conf updated", "%d device(s)" % len(rows))
    return True, "saved"


def mvnbc_clean_field(s):
    """Strip newlines/commas that would break the CSV line; keep credential chars."""
    return (s or "").strip().replace("\n", "").replace("\r", "").replace(",", "")


def mvnbc_settings_load():
    """Load settings.json with defaults deep-merged."""
    data = _mjson.loads(_mjson.dumps(MVNBC_ALERT_DEFAULTS))
    try:
        with open(MVNBC_SETTINGS) as fh:
            raw = fh.read().strip()
        if raw:
            got = _mjson.loads(raw)
            if isinstance(got, dict):
                for sec, vals in MVNBC_ALERT_DEFAULTS.items():
                    if isinstance(got.get(sec), dict):
                        data[sec].update(got[sec])
                # preserve retention if present but defaults missing key
                if "retention" in got and isinstance(got["retention"], dict):
                    for k in MVNBC_ALERT_DEFAULTS.get("retention", {}):
                        if k not in data["retention"] and k in got["retention"]:
                            data["retention"][k] = got["retention"][k]
    except (OSError, ValueError):
        pass
    return data


def mvnbc_settings_save(data):
    try:
        os.makedirs(os.path.dirname(MVNBC_SETTINGS), exist_ok=True)
        with open(MVNBC_SETTINGS, "w") as fh:
            fh.write(_mjson.dumps(data, indent=4))
        os.chmod(MVNBC_SETTINGS, 0o600)
        return True
    except OSError:
        return False


def _mvnbc_ipv4_gai():
    """Return (orig_getaddrinfo, ipv4_only_patch) to force IPv4.

    This host has slow/broken IPv6; plain connects hang on the IPv6
    address instead of falling back (no Happy Eyeballs in PHP streams,
    slow fallback in Python). gai.conf also prefers IPv4, this makes
    portal notifier deterministic + fast."""
    import socket as _so
    orig = _so.getaddrinfo

    def _ipv4_only(h, p, family=0, typ=0, proto=0, flags=0):
        try:
            return orig(h, p, _so.AF_INET, typ, proto, flags)
        except _so.gaierror:
            return orig(h, p, family, typ, proto, flags)

    return orig, _ipv4_only


def mvnbc_send_email(cfg, subject, body):
    """Raw SMTP send (STARTTLS/SSL/none). Returns (ok, message)."""
    host = (cfg.get("smtp_host") or "").strip()
    port = int(cfg.get("smtp_port") or 587)
    secure = cfg.get("smtp_secure") or "tls"
    user = (cfg.get("username") or "").strip()
    pw = cfg.get("password") or ""
    frm = (cfg.get("from") or "").strip() or user
    to_raw = (cfg.get("to") or "").strip()
    if not host or not frm or not to_raw:
        return False, "SMTP host, from, and to are required."
    rcpts = [r.strip() for r in to_raw.split(",") if r.strip()]
    if not rcpts:
        return False, "No valid recipients."
    msg = _memail_module()
    msg["Subject"] = subject
    msg["From"] = "MVNBC Backup <%s>" % frm
    msg["To"] = ", ".join(rcpts)
    msg.set_content(body)
    ctx = _mssl.create_default_context()
    import socket as _so
    orig_gai, patch_gai = _mvnbc_ipv4_gai()
    _so.getaddrinfo = patch_gai
    try:
        if secure == "ssl":
            s = _msmtp.SMTP_SSL(host, port, timeout=20, context=ctx)
        else:
            s = _msmtp.SMTP(host, port, timeout=20)
            if secure == "tls":
                s.starttls(context=ctx)
        if user:
            s.login(user, pw)
        s.sendmail(frm, rcpts, msg.as_string())
        s.quit()
        return True, "Email sent to %s." % ", ".join(rcpts)
    except Exception as ex:
        return False, "Email failed: %s" % ex
    finally:
        try:
            _so.getaddrinfo = orig_gai
        except Exception:
            pass


def _memail_module():
    from email.message import EmailMessage
    return EmailMessage()


def mvnbc_send_telegram(token, chat_id, text):
    """Telegram Bot API sendMessage. Returns (ok, message). Forces IPv4."""
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    if not token or not chat_id:
        return False, "Bot token and chat ID are required."
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    payload = _murlparse.urlencode({"chat_id": chat_id, "text": text,
                                    "parse_mode": "HTML",
                                    "disable_web_page_preview": "true"}).encode()
    import socket as _so
    orig_gai, patch_gai = _mvnbc_ipv4_gai()
    _so.getaddrinfo = patch_gai
    try:
        req = _murlreq.Request(url, data=payload, method="POST")
        with _murlreq.urlopen(req, timeout=15) as resp:
            j = _mjson.loads(resp.read().decode())
        if j.get("ok"):
            return True, "Telegram message sent."
        return False, "Telegram error: %s" % j.get("description", "unknown")
    except Exception as ex:
        return False, "Telegram request failed: %s" % ex
    finally:
        try:
            _so.getaddrinfo = orig_gai
        except Exception:
            pass


def mvnbc_dispatch_alert(settings, subject, body):
    results = {}
    if settings.get("email", {}).get("enabled"):
        results["email"] = mvnbc_send_email(settings["email"], subject, body)
    if settings.get("telegram", {}).get("enabled"):
        tg = settings["telegram"]
        esc = (body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        subj_esc = subject.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        results["telegram"] = mvnbc_send_telegram(
            tg.get("bot_token"), tg.get("chat_id"), "<b>%s</b>\n\n%s" % (subj_esc, esc))
    for ch, (ok, m) in results.items():
        mvnbc_audit("notify[%s]" % ch, "%s - %s" % ("OK" if ok else "ERR", m))
    return results


def _mvnbc_append_run_log(log_path, text):
    """Append notify results to the run_*.log so portal/cron/bot logs match."""
    try:
        with open(log_path, "a") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    except OSError:
        pass


def mvnbc_notify_after_run(log_path=None):
    """Port of notify_run.php: parse run log OK/FAIL, dispatch per notify_on mode.

    Also appends notify_run[...] lines to the run log (like the cron PHP
    notifier does) so Alerts & Notifications history is visible in one place.
    """
    try:
        if not log_path or not os.path.isfile(log_path):
            cands = [os.path.join(MVNBC_LOGS, n) for n in os.listdir(MVNBC_LOGS)
                     if n.startswith("run_") and n.endswith(".log")]
            if not cands:
                return {}
            cands.sort(key=os.path.getmtime, reverse=True)
            log_path = cands[0]
        with open(log_path, "r", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {}
    ok_list, fail_list = [], []
    for ln in lines:
        m = re.match(r"^\[OK\] Backup saved: .*/([^/]+)$", ln)
        if m:
            ok_list.append(m.group(1))
            continue
        m = re.match(r"^\[FAIL\] Backup validation failed: (.+)$", ln)
        if m:
            fail_list.append(m.group(1).strip())
    ok_n, fail_n = len(ok_list), len(fail_list)
    settings = mvnbc_settings_load()
    mode = settings.get("alerts", {}).get("notify_on", "failure")
    if mode == "never" or (mode == "failure" and fail_n == 0):
        # Log the SKIP so the run log explains why no alert was sent
        # (previously silent, looked like "alerts broken").
        _mvnbc_append_run_log(
            log_path,
            "notify_run[skip]: notify_on=%s, %d ok / %d failed — no alert needed." % (mode, ok_n, fail_n))
        return {}
    host = _msocket.gethostname() or "server"
    status = "SUCCESS" if fail_n == 0 else "FAILURES"
    subject = "MVNBC backup %s - %d ok, %d failed" % (status, ok_n, fail_n)
    body = ("MVNBC backup run summary\nHost:    %s\nTime:    %s\n"
            "Result:  %d succeeded, %d failed (of %d)\n%s\n"
            % (host, _myt_now(),
               ok_n, fail_n, ok_n + fail_n, "-" * 40))
    if fail_n:
        body += "FAILED:\n" + "".join("  x %s\n" % f for f in fail_list) + "\n"
    if ok_n:
        body += "OK:\n" + "".join("  + %s\n" % o for o in ok_list)
    body += "\nLog: %s\n" % os.path.basename(log_path)
    results = mvnbc_dispatch_alert(settings, subject, body)
    for ch, (ok, m) in results.items():
        _mvnbc_append_run_log(
            log_path,
            "notify_run[%s]: %s — %s" % (ch, "OK" if ok else "ERR", m))
    if not results:
        _mvnbc_append_run_log(log_path, "notify_run[skip]: no channels enabled.")
    return results


def mvnbc_watch_and_notify(pid):
    """Daemon thread: wait for MVNBC.sh process exit, then dispatch alerts.

    Notify results are appended to the run_*.log (via mvnbc_notify_after_run)
    so portal runs leave the same trail as cron runs.
    """
    def _w():
        deadline = time.time() + 7200
        while time.time() < deadline:
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as fh:
                    if b"MVNBC" not in fh.read():
                        break
            except OSError:
                break
            time.sleep(3)
        time.sleep(2)  # let log flush
        try:
            mvnbc_notify_after_run(None)
        except Exception as ex:
            try:
                cands = [os.path.join(MVNBC_LOGS, n) for n in os.listdir(MVNBC_LOGS)
                         if n.startswith("run_") and n.endswith(".log")]
                if cands:
                    cands.sort(key=os.path.getmtime, reverse=True)
                    _mvnbc_append_run_log(cands[0], "notify_run[ERR]: watcher failed: %s" % ex)
            except Exception:
                pass
            mvnbc_audit("notify[watcher]", "ERR - %s" % ex)
        try:
            _rs = mvnbc_settings_load().get("retention", {})
            _auto = _rs.get("auto_prune_30d")
            _kb = int(_rs.get("keep_backups", 50)); _kl = int(_rs.get("keep_logs", 30))
            _age = int(_rs.get("max_age_days", 30)) if _auto else None
            if _auto or _kb < 1000 or _kl < 1000:
                mvnbc_prune(keep_backups=_kb, keep_logs=_kl, max_age_days=_age, apply=True)
        except Exception:
            pass
    _mthread.Thread(target=_w, daemon=True).start()


# ---- devices API (passwords NEVER leave server; only has_pass bool) ----
@app.route("/api/mvnbc/devices")
@login_required
def api_mvnbc_devices():
    rows = []
    for r in mvnbc_load_devices_rows():
        rows.append({"vendor": r["vendor"], "ip": r["ip"], "user": r["user"],
                     "enable": bool(r.get("enable")), "has_pass": bool(r.get("pass"))})
    return jsonify({"devices": rows, "vendors": mvnbc_discover_vendors()})


@app.route("/api/mvnbc/devices/add", methods=["POST"])
@login_required
def api_mvnbc_devices_add():
    check_csrf()
    d = request.get_json(silent=True) or {}
    vendor = mvnbc_clean_field(d.get("vendor")).lower()
    ip = mvnbc_clean_field(d.get("ip"))
    user = mvnbc_clean_field(d.get("user"))
    pw = mvnbc_clean_field(d.get("pass"))
    enable = mvnbc_clean_field(d.get("enable"))
    if vendor not in mvnbc_discover_vendors():
        return jsonify({"ok": False, "error": "No template for vendor '%s'. Create one in Templates below." % vendor}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "error": "\"%s\" is not a valid IP address." % ip}), 400
    if not user or not pw:
        return jsonify({"ok": False, "error": "Username and password are required."}), 400
    rows = mvnbc_load_devices_rows()
    if any(r["vendor"].lower() == vendor and r["ip"] == ip for r in rows):
        return jsonify({"ok": False, "error": "A device with this vendor and IP already exists."}), 409
    rows.append({"vendor": vendor, "ip": ip, "user": user, "pass": pw, "enable": enable})
    ok, msg = mvnbc_write_devices_rows(rows)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 500
    mvnbc_audit("device add", "%s %s" % (vendor, ip))
    return jsonify({"ok": True, "message": "Device %s (%s) added." % (vendor, ip)})


@app.route("/api/mvnbc/devices/update", methods=["POST"])
@login_required
def api_mvnbc_devices_update():
    check_csrf()
    d = request.get_json(silent=True) or {}
    vendor = mvnbc_clean_field(d.get("vendor")).lower()
    ip = mvnbc_clean_field(d.get("ip"))
    user = mvnbc_clean_field(d.get("user"))
    pw = mvnbc_clean_field(d.get("pass"))
    enable = mvnbc_clean_field(d.get("enable"))
    if vendor not in mvnbc_discover_vendors():
        return jsonify({"ok": False, "error": "No template for vendor '%s'." % vendor}), 400
    rows = mvnbc_load_devices_rows()
    hit = None
    for r in rows:
        if r["vendor"].lower() == vendor and r["ip"] == ip:
            hit = r
            break
    if hit is None:
        return jsonify({"ok": False, "error": "Device not found."}), 404
    if not user:
        return jsonify({"ok": False, "error": "Username is required."}), 400
    hit["user"] = user
    if pw:
        hit["pass"] = pw
    hit["enable"] = enable
    ok, msg = mvnbc_write_devices_rows(rows)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 500
    mvnbc_audit("device update", "%s %s" % (vendor, ip))
    return jsonify({"ok": True, "message": "Device %s (%s) updated." % (vendor, ip)})


@app.route("/api/mvnbc/devices/delete", methods=["POST"])
@login_required
def api_mvnbc_devices_delete():
    check_csrf()
    d = request.get_json(silent=True) or {}
    vendor = mvnbc_clean_field(d.get("vendor")).lower()
    ip = mvnbc_clean_field(d.get("ip"))
    rows = mvnbc_load_devices_rows()
    before = len(rows)
    rows = [r for r in rows if not (r["vendor"].lower() == vendor and r["ip"] == ip)]
    if len(rows) == before:
        return jsonify({"ok": False, "error": "Device not found."}), 404
    ok, msg = mvnbc_write_devices_rows(rows)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 500
    mvnbc_audit("device delete", "%s %s" % (vendor, ip))
    return jsonify({"ok": True, "message": "Device removed."})




# ---- custom .exp templates + MVNBC.sh editor ----
@app.route("/api/mvnbc/templates")
@login_required
def api_mvnbc_templates():
    out=[]
    try:
        tdir=os.path.join(MVNBC_DIR,"templates")
        for fn in sorted(os.listdir(tdir)):
            if not fn.endswith(".exp"): continue
            p=os.path.join(tdir,fn)
            try:
                st=os.stat(p)
                fh=open(p,encoding="utf-8",errors="replace")
                body=fh.read()
                fh.close()
                out.append({"name":fn,"vendor":fn[:-4],"size":st.st_size,"mtime":int(st.st_mtime),
                            "mtime_h":_myfmt(int(st.st_mtime)),"builtin": fn[:-4] in MVNBC_VENDORS_BUILTIN,
                            "content": body if len(body)<30000 else body[:30000]+"\n# ... truncated"})
            except OSError:
                pass
    except OSError:
        pass
    return jsonify({"templates": out, "vendors": mvnbc_discover_vendors()})

@app.route("/api/mvnbc/templates/save", methods=["POST"])
@login_required
def api_mvnbc_templates_save():
    check_csrf()
    d=request.get_json(silent=True) or {}
    vendor=(d.get("vendor") or "").strip().lower()
    content=d.get("content") or ""
    if not vendor or not __import__("re").match(r"^[a-z0-9_\-]+$", vendor):
        return jsonify({"ok": False, "error": "Vendor slug must be a-z 0-9 _ -"}), 400
    if vendor in MVNBC_VENDORS_BUILTIN:
        return jsonify({"ok": False, "error": "Builtin vendor '%s' is locked. Create a different name (e.g. '%s_custom')." % (vendor,vendor)}), 400
    if len(content) > 80000:
        return jsonify({"ok": False, "error": "Template too large (max 80k)"}), 400
    tdir=os.path.join(MVNBC_DIR,"templates")
    os.makedirs(tdir, exist_ok=True)
    p=os.path.join(tdir,vendor+".exp")
    try:
        open(p,"w",encoding="utf-8").write(content if content.endswith("\n") else content+"\n")
        os.chmod(p,0o644)
        try: mvnbc_sync_mvnbc_sh()
        except Exception: pass
        mvnbc_audit("template save", vendor)
        return jsonify({"ok": True, "message": "Template %s saved." % (vendor+".exp")})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/mvnbc/templates/delete", methods=["POST"])
@login_required
def api_mvnbc_templates_delete():
    check_csrf()
    d=request.get_json(silent=True) or {}
    vendor=(d.get("vendor") or "").strip().lower()
    if not vendor:
        return jsonify({"ok": False, "error": "Missing vendor"}), 400
    if vendor in MVNBC_VENDORS_BUILTIN:
        return jsonify({"ok": False, "error": "Cannot delete builtin template"}), 400
    p=os.path.join(MVNBC_DIR,"templates",vendor+".exp")
    if not os.path.isfile(p):
        return jsonify({"ok": False, "error": "Not found"}), 404
    try:
        os.remove(p)
        try: mvnbc_sync_mvnbc_sh()
        except Exception: pass
        mvnbc_audit("template delete", vendor)
        return jsonify({"ok": True})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/mvnbc/script")
@login_required
def api_mvnbc_script():
    p=MVNBC_SCRIPT
    try:
        body=open(p,encoding="utf-8",errors="replace").read()
    except OSError:
        return jsonify({"ok": False, "error": "MVNBC.sh not found"}), 404
    return jsonify({"ok": True, "content": body, "size": len(body.encode("utf-8"))})

@app.route("/api/mvnbc/script/save", methods=["POST"])
@login_required
def api_mvnbc_script_save():
    check_csrf()
    d=request.get_json(silent=True) or {}
    body=d.get("content") or ""
    if len(body) > 120000:
        return jsonify({"ok": False, "error": "File too large"}), 400
    p=MVNBC_SCRIPT
    bak=p+".bak.%d" % int(__import__("time").time())
    try:
        if not body.strip().startswith("#!"):
            return jsonify({"ok": False, "error": "MVNBC.sh must start with shebang"}), 400
        if os.path.isfile(p):
            open(bak,"w",encoding="utf-8").write(open(p,encoding="utf-8",errors="replace").read())
        open(p,"w",encoding="utf-8").write(body if body.endswith("\n") else body+"\n")
        os.chmod(p,0o755)
        mvnbc_audit("script save", "manual edit")
        return jsonify({"ok": True, "message": "MVNBC.sh saved.", "backup": os.path.basename(bak)})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def mvnbc_sync_mvnbc_sh():
    """Ensure every *.exp has a case branch in MVNBC.sh (validation + run)."""
    sh=MVNBC_SCRIPT
    if not os.path.isfile(sh):
        return
    body=open(sh,encoding="utf-8",errors="replace").read()
    vendors=mvnbc_discover_vendors()
    custom=[v for v in vendors if v not in MVNBC_VENDORS_BUILTIN]
    if not custom:
        return
    # run_backup case: insert before default (*)
    for v in custom:
        if ('"%s")' % v) not in body and ("\'%s\')" % v) not in body and (v+" )") not in body:
            stub = "            %s)\n                expect \"$TEMPLATE_DIR/%s.exp\" \\\n                    \"$ip\" \"$username\" \"$password\" \"$enable_secret\" \\\n                    \"$BACKUP_PATH\" >> \"$LOG_FILE\" 2>&1\n                ;;\n" % (v,v)
            body=body.replace("            *)\n                echo \"[WARN] Unknown vendor: $vendor\"", stub+"            *)\n                echo \"[WARN] Unknown vendor: $vendor\"",1)
    # validate_backup generic: custom vendor falls through to *) -> ok, no patch needed
    import subprocess as _sp
    _sp.run(["bash","-n",sh], capture_output=True, timeout=5)
    open(sh,"w",encoding="utf-8").write(body)
    os.chmod(sh,0o755)

# ---- compare: unified diff of two backup snapshots ----
@app.route("/api/mvnbc/compare", methods=["POST"])
@login_required
def api_mvnbc_compare():
    check_csrf()
    d = request.get_json(silent=True) or {}
    fa = mvnbc_safe_file((d.get("a") or "").strip(), "b")
    fb = mvnbc_safe_file((d.get("b") or "").strip(), "b")
    if not fa or not fb:
        return jsonify({"ok": False, "error": "Invalid file selection."}), 400
    try:
        with open(fa, "r", errors="replace") as fh:
            la = fh.read().splitlines()
        with open(fb, "r", errors="replace") as fh:
            lb = fh.read().splitlines()
    except OSError as ex:
        return jsonify({"ok": False, "error": "read failed: %s" % ex}), 500
    diff = list(_mdiff.unified_diff(la, lb, fromfile=os.path.basename(fa),
                                    tofile=os.path.basename(fb), lineterm="", n=3))
    added = sum(1 for x in diff if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in diff if x.startswith("-") and not x.startswith("---"))
    cap = 2000
    truncated = len(diff) > cap
    return jsonify({"ok": True, "a": os.path.basename(fa), "b": os.path.basename(fb),
                    "added": added, "removed": removed, "lines": diff[:cap],
                    "truncated": truncated, "identical": not diff})


# ---- alerts API ----
@app.route("/api/mvnbc/alerts")
@login_required
def api_mvnbc_alerts():
    s = mvnbc_settings_load()
    e, t = s.get("email", {}), s.get("telegram", {})
    return jsonify({
        "notify_on": s.get("alerts", {}).get("notify_on", "failure"),
        "email": {"enabled": bool(e.get("enabled")), "smtp_host": e.get("smtp_host", ""),
                  "smtp_port": e.get("smtp_port", 587), "smtp_secure": e.get("smtp_secure", "tls"),
                  "username": e.get("username", ""), "from": e.get("from", ""),
                  "to": e.get("to", ""), "has_pass": bool(e.get("password"))},
        "telegram": {"enabled": bool(t.get("enabled")), "has_token": bool(t.get("bot_token")),
                     "chat_id": t.get("chat_id", "")},
    })


@app.route("/api/mvnbc/alerts/save", methods=["POST"])
@login_required
def api_mvnbc_alerts_save():
    check_csrf()
    d = request.get_json(silent=True) or {}
    s = mvnbc_settings_load()
    mode = d.get("notify_on")
    if mode not in ("failure", "always", "never"):
        mode = "failure"
    s["alerts"]["notify_on"] = mode
    e_in = d.get("email") or {}
    e = s["email"]
    e["enabled"] = bool(e_in.get("enabled"))
    e["smtp_host"] = (e_in.get("smtp_host") or "").strip()
    try:
        e["smtp_port"] = int(e_in.get("smtp_port") or 587)
    except (TypeError, ValueError):
        e["smtp_port"] = 587
    sec = (e_in.get("smtp_secure") or "tls")
    e["smtp_secure"] = sec if sec in ("tls", "ssl", "none") else "tls"
    e["username"] = mvnbc_clean_field(e_in.get("username"))
    if (e_in.get("password") or "").strip():
        e["password"] = e_in["password"].strip()
    e["from"] = mvnbc_clean_field(e_in.get("from"))
    # NOTE: `to` is comma-separated — preserve commas (clean_field strips them).
    e["to"] = (e_in.get("to") or "").strip().replace("\n", "").replace("\r", "")
    t_in = d.get("telegram") or {}
    t = s["telegram"]
    t["enabled"] = bool(t_in.get("enabled"))
    if (t_in.get("bot_token") or "").strip():
        t["bot_token"] = t_in["bot_token"].strip()
    t["chat_id"] = mvnbc_clean_field(t_in.get("chat_id"))
    if not mvnbc_settings_save(s):
        return jsonify({"ok": False, "error": "Could not write settings.json. Check file permissions."}), 500
    mvnbc_audit("alerts save", "notify_on=%s email=%s telegram=%s" % (mode, e["enabled"], t["enabled"]))
    return jsonify({"ok": True, "message": "Alert settings saved."})


@app.route("/api/mvnbc/alerts/test", methods=["POST"])
@login_required
def api_mvnbc_alerts_test():
    check_csrf()
    d = request.get_json(silent=True) or {}
    ch = (d.get("channel") or "").strip()
    s = mvnbc_settings_load()
    if ch == "email":
        ok, m = mvnbc_send_email(s["email"], "MVNBC test alert",
                                 "This is a test message from your MVNBC Backup Console.\n"
                                 "If you can read this, email alerts are working.")
    elif ch == "telegram":
        tg = s["telegram"]
        ok, m = mvnbc_send_telegram(tg.get("bot_token"), tg.get("chat_id"),
                                    "<b>MVNBC test alert</b>\n\nThis is a test message from your "
                                    "MVNBC Backup Console.\nIf you can read this, Telegram alerts are working.")
    else:
        return jsonify({"ok": False, "error": "bad channel"}), 400
    mvnbc_audit("alerts test[%s]" % ch, "%s - %s" % ("OK" if ok else "ERR", m))
    return jsonify({"ok": ok, "message": m})


# ---- schedule API (root crontab) ----
def mvnbc_read_crontab():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (r.stdout or "") if r.returncode == 0 else ""


def mvnbc_valid_cron(expr):
    parts = expr.split()
    if len(parts) != 5:
        return False
    return all(re.match(r"^[\d*/,?\-]+$", p) for p in parts)


def _cron_field_match(val, lo, hi):
    vals = set()
    for piece in val.split(","):
        step = 1
        if "/" in piece:
            piece, _, step_s = piece.partition("/")
            try:
                step = int(step_s)
            except ValueError:
                return set()
            if step < 1:
                return set()
        if piece in ("*", ""):
            a, b = lo, hi
        elif "-" in piece:
            try:
                a, b = (int(x) for x in piece.split("-", 1))
            except ValueError:
                return set()
            if a > b or a < lo or b > hi:
                return set()
        else:
            try:
                a = b = int(piece)
            except ValueError:
                return set()
            if a < lo or a > hi:
                return set()
        for v in range(a, b + 1, step):
            vals.add(v)
    return vals


def mvnbc_next_run(cron_expr, now=None):
    try:
        parts = cron_expr.split()
        if len(parts) < 5:
            return None, None
        m_set = _cron_field_match(parts[0], 0, 59)
        h_set = _cron_field_match(parts[1], 0, 23)
        dom_set = _cron_field_match(parts[2], 1, 31)
        mon_set = _cron_field_match(parts[3], 1, 12)
        dow_set_raw = _cron_field_match(parts[4], 0, 7)
        dow_set = {0 if v == 7 else v for v in dow_set_raw}
        dom_star = parts[2] in ("*", "*/1")
        dow_star = parts[4] in ("*", "*/1")
        try:
            base = datetime.fromtimestamp(now if now is not None else time.time(), tz=MYTZ)
        except Exception:
            base = datetime.now(MYTZ)
        base = base.replace(second=0, microsecond=0)
        from datetime import timedelta as _td
        for i in range(1, 525601):
            cand = base + _td(minutes=i)
            py_dow = (cand.weekday() + 1) % 7
            if cand.minute not in m_set or cand.hour not in h_set or cand.month not in mon_set:
                continue
            if dom_star and dow_star:
                ok = True
            elif dom_star:
                ok = py_dow in dow_set
            elif dow_star:
                ok = cand.day in dom_set
            else:
                ok = (cand.day in dom_set) or (py_dow in dow_set)
            if ok:
                return int(cand.timestamp()), _myfmt(int(cand.timestamp()))
        return None, None
    except Exception:
        return None, None


@app.route("/api/mvnbc/schedule")
@login_required
def api_mvnbc_schedule():
    txt = mvnbc_read_crontab()
    if txt is None:
        return jsonify({"ok": False, "available": False, "job": None, "next_run": None, "next_run_human": None})
    job = None
    for line in txt.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and MVNBC_SCRIPT in s:
            job = s
            break
    cron_expr = " ".join(job.split()[:5]) if job else ""
    nxt, nxt_h = (mvnbc_next_run(cron_expr) if cron_expr else (None, None))
    has_tz = bool(re.search(r"^\s*(TZ|CRON_TZ)\s*=\s*Asia/Kuala_Lumpur", txt or "", re.M))
    return jsonify({"ok": True, "available": True, "job": job, "cron_expr": cron_expr, "next_run": nxt, "next_run_human": nxt_h, "script": MVNBC_SCRIPT, "tz": "Asia/Kuala_Lumpur", "tz_pinned": has_tz})


@app.route("/api/mvnbc/schedule/save", methods=["POST"])
@login_required
def api_mvnbc_schedule_save():
    check_csrf()
    if not os.path.isfile(MVNBC_SCRIPT):
        return jsonify({"ok": False, "error": "MVNBC.sh not found"}), 404
    d = request.get_json(silent=True) or {}
    cron = (d.get("cron") or "").strip()
    if not mvnbc_valid_cron(cron):
        return jsonify({"ok": False, "error": "That cron expression doesn't look valid. Use 5 fields, e.g. 0 2 * * *"}), 400
    txt = mvnbc_read_crontab()
    if txt is None:
        return jsonify({"ok": False, "error": "crontab unavailable on this host"}), 500
    # System TZ is UTC but UI/next-run is Asia/Kuala_Lumpur: pin the job to MYT
    # via TZ/CRON_TZ so "Daily 02:00" really fires 02:00 MYT, not 02:00 UTC.
    kept = [l for l in txt.splitlines()
            if l.strip() and MVNBC_SCRIPT not in l
            and not re.match(r"^\s*(TZ|CRON_TZ)\s*=", l)]
    kept.insert(0, "CRON_TZ=Asia/Kuala_Lumpur")
    kept.insert(0, "TZ=Asia/Kuala_Lumpur")
    kept.append("%s /bin/bash %s --auto" % (cron, MVNBC_SCRIPT))
    new = "\n".join(kept) + "\n"
    try:
        r = subprocess.run(["crontab", "-"], input=new, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return jsonify({"ok": False, "error": "crontab write failed: %s" % ex}), 500
    if r.returncode != 0:
        return jsonify({"ok": False, "error": "crontab write failed: %s" % (r.stderr or "unknown")}), 500
    mvnbc_audit("schedule save", cron)
    return jsonify({"ok": True, "message": "Schedule saved."})


@app.route("/api/mvnbc/schedule/remove", methods=["POST"])
@login_required
def api_mvnbc_schedule_remove():
    check_csrf()
    txt = mvnbc_read_crontab()
    if txt is None:
        return jsonify({"ok": False, "error": "crontab unavailable on this host"}), 500
    kept = [l for l in txt.splitlines()
            if l.strip() and MVNBC_SCRIPT not in l]
    new = ("\n".join(kept) + "\n") if kept else ""
    try:
        r = subprocess.run(["crontab", "-"], input=new, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return jsonify({"ok": False, "error": "crontab write failed: %s" % ex}), 500
    if r.returncode != 0:
        return jsonify({"ok": False, "error": "crontab write failed: %s" % (r.stderr or "unknown")}), 500
    mvnbc_audit("schedule remove", "")
    return jsonify({"ok": True, "message": "Schedule removed."})

# ---------------- Retention & prune ----------------
RETENTION_SKIP = {"audit.log", "delete_audit.log", ".run.lock", ".gitkeep", "settings.json", "devices.conf", "password.txt"}

def mvnbc_prune(keep_backups=50, keep_logs=30, max_age_days=None, apply=False):
    res = {"backups": [], "logs": [], "deleted": 0, "failed": 0, "skipped": []}
    now = time.time()
    # backups per-vendor
    if os.path.isdir(MVNBC_BACKUPS):
        try:
            vendors = [d for d in os.listdir(MVNBC_BACKUPS) if os.path.isdir(os.path.join(MVNBC_BACKUPS, d))]
        except OSError:
            vendors = []
        for vd in sorted(vendors):
            vdir = os.path.join(MVNBC_BACKUPS, vd)
            try:
                fns = [f for f in os.listdir(vdir) if os.path.isfile(os.path.join(vdir, f)) and f not in RETENTION_SKIP]
            except OSError:
                continue
            items = []
            for fn in fns:
                fp = os.path.join(vdir, fn)
                try:
                    mt = os.path.getmtime(fp)
                except OSError:
                    continue
                items.append((mt, fn, fp))
            items.sort(reverse=True)
            for mt, fn, fp in items[keep_backups:]:
                if max_age_days is not None and (now - mt) <= max_age_days*86400:
                    # keep if within age, but still beyond keep_backups? spec says beyond keep => delete regardless
                    pass
                rel = vd + "/" + fn
                res["backups"].append(rel)
                if apply:
                    sf = mvnbc_safe_file(rel, "b")
                    if sf:
                        try:
                            os.remove(sf); res["deleted"] += 1; mvnbc_audit("retention prune backup", rel)
                        except Exception:
                            res["failed"] += 1
                    else:
                        res["failed"] += 1
            if max_age_days is not None:
                for mt, fn, fp in items[:keep_backups]:
                    if (now - mt) > max_age_days*86400:
                        rel = vd + "/" + fn
                        if rel not in res["backups"]:
                            res["backups"].append(rel)
                            if apply:
                                sf = mvnbc_safe_file(rel, "b")
                                if sf:
                                    try:
                                        os.remove(sf); res["deleted"] += 1; mvnbc_audit("retention prune backup (age)", rel)
                                    except Exception:
                                        res["failed"] += 1
    # logs: only run_*.log
    if os.path.isdir(MVNBC_LOGS):
        try:
            lns = [f for f in os.listdir(MVNBC_LOGS) if f.startswith("run_") and f.endswith(".log") and os.path.isfile(os.path.join(MVNBC_LOGS, f))]
        except OSError:
            lns = []
        items = []
        for fn in lns:
            fp = os.path.join(MVNBC_LOGS, fn)
            try:
                mt = os.path.getmtime(fp)
            except OSError:
                continue
            items.append((mt, fn, fp))
        items.sort(reverse=True)
        for mt, fn, fp in items[keep_logs:]:
            res["logs"].append(fn)
            if apply:
                sf = mvnbc_safe_file(fn, "l")
                if sf:
                    try:
                        os.remove(sf); res["deleted"] += 1; mvnbc_audit("retention prune log", fn)
                    except Exception:
                        res["failed"] += 1
                else:
                    res["failed"] += 1
        if max_age_days is not None:
            for mt, fn, fp in items[:keep_logs]:
                if (now - mt) > max_age_days*86400 and fn not in res["logs"]:
                    res["logs"].append(fn)
                    if apply:
                        sf = mvnbc_safe_file(fn, "l")
                        if sf:
                            try:
                                os.remove(sf); res["deleted"] += 1; mvnbc_audit("retention prune log (age)", fn)
                            except Exception:
                                res["failed"] += 1
    return res

@app.route("/api/mvnbc/retention", methods=["GET"])
@login_required
def api_mvnbc_retention():
    s = mvnbc_settings_load().get("retention", {})
    counts = {"backups": 0, "logs": 0}
    if os.path.isdir(MVNBC_BACKUPS):
        for vd in os.listdir(MVNBC_BACKUPS):
            vdir = os.path.join(MVNBC_BACKUPS, vd)
            if os.path.isdir(vdir):
                try:
                    counts["backups"] += len([f for f in os.listdir(vdir) if os.path.isfile(os.path.join(vdir,f)) and f not in RETENTION_SKIP])
                except OSError:
                    pass
    if os.path.isdir(MVNBC_LOGS):
        try:
            counts["logs"] = len([f for f in os.listdir(MVNBC_LOGS) if f.startswith("run_") and f.endswith(".log")])
        except OSError:
            pass
    preview = mvnbc_prune(keep_backups=int(s.get("keep_backups",50)), keep_logs=int(s.get("keep_logs",30)), max_age_days=int(s.get("max_age_days",30)) if s.get("auto_prune_30d") else None, apply=False)
    return jsonify({"ok": True, "retention": s, "counts": counts, "would_delete": {"backups": preview["backups"], "logs": preview["logs"]}})

@app.route("/api/mvnbc/retention/save", methods=["POST"])
@login_required
def api_mvnbc_retention_save():
    check_csrf()
    d = request.get_json(silent=True) or {}
    try:
        kb = max(1, min(1000, int(d.get("keep_backups", 50))))
        kl = max(1, min(1000, int(d.get("keep_logs", 30))))
        auto = bool(d.get("auto_prune_30d"))
        age = max(1, min(365, int(d.get("max_age_days", 30))))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "invalid numbers"}), 400
    s = mvnbc_settings_load()
    s["retention"] = {"keep_backups": kb, "keep_logs": kl, "auto_prune_30d": auto, "max_age_days": age}
    if not mvnbc_settings_save(s):
        return jsonify({"ok": False, "error": "save failed"}), 500
    mvnbc_audit("retention save", "keep_b=%d keep_l=%d auto=%s age=%d" % (kb,kl,auto,age))
    return jsonify({"ok": True, "message": "Retention saved."})

@app.route("/api/mvnbc/retention/prune", methods=["POST"])
@login_required
def api_mvnbc_retention_prune():
    check_csrf()
    d = request.get_json(silent=True) or {}
    dry = bool(d.get("dry_run"))
    s = mvnbc_settings_load().get("retention", {})
    kb = int(s.get("keep_backups",50)); kl=int(s.get("keep_logs",30))
    age = int(s.get("max_age_days",30)) if s.get("auto_prune_30d") else None
    res = mvnbc_prune(keep_backups=kb, keep_logs=kl, max_age_days=age, apply=not dry)
    if not dry:
        mvnbc_audit("retention prune", "deleted=%d failed=%d dry=%s" % (res["deleted"], res["failed"], dry))
    return jsonify({"ok": True, "dry_run": dry, "deleted": res["deleted"], "failed": res["failed"], "backups": res["backups"], "logs": res["logs"]})

# ---------------- Templates ----------------

BASE_CSS = """
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, 'Segoe UI', system-ui, sans-serif; background: #E9E0F8; color: #241651; min-height: 100vh; }
  body::before { content:''; position:fixed; inset:0; pointer-events:none; background: radial-gradient(900px 480px at 12% -8%, rgba(115,86,214,.16), transparent 60%), radial-gradient(800px 500px at 92% 4%, rgba(255,176,196,.10), transparent 60%); }
  .header { background: linear-gradient(160deg, #6F4ECC, #8066E0); padding: 22px 30px; border-bottom: 2px solid rgba(111,78,204,.30); display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.4em; color: #FFFFFF; font-weight: 600; letter-spacing: -1px; }
  .header h1 span { color: #FFB0C4; }
  .header .meta { font-size: 0.85em; color: #6B5CA5; }
  .container { max-width: 1200px; margin: 0 auto; padding: 25px; }
  .status-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
  .status-card { background: linear-gradient(160deg, #7356D6, #6A48C7); border: none; border-radius: 20px; padding: 18px 20px; box-shadow: 0 12px 30px rgba(95,65,180,.25); color: #fff; --muted: #D5CAFA; --line: rgba(255,255,255,.22); --line2: rgba(255,255,255,.30); }
  .status-card .label { font-size: 0.75em; text-transform: uppercase; color: #D5CAFA; margin-bottom: 6px; letter-spacing: 0.5px; }
  .status-card .value { font-size: 1.5em; font-weight: 700; }
  .status-card .value.up { color: #7CF0A0; }
  .status-card .value.down { color: #FF9B96; }
  .status-card .value.warn { color: #FFD37A; }
  .status-card .detail { font-size: 0.8em; color: #6B5CA5; margin-top: 4px; }
  .section { background: #FFFFFF; border: none; border-radius: 20px; padding: 22px 24px; margin-bottom: 20px; box-shadow: 0 8px 24px rgba(95,65,180,.18); color: #241651; }
  .section h2 { font-size: 1.1em; color: #6F4ECC; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
  .section h2::before { content: ''; width: 5px; height: 18px; border-radius: 999px; background: linear-gradient(180deg, #6F4ECC, #B487E8); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 12px; background: #F6F2FF; color: #6B5CA5; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid rgba(111,78,204,.10); }
  td { padding: 11px 12px; border-bottom: 1px solid rgba(111,78,204,.10); }
  tr:hover { background: rgba(111,78,204,.07); }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 600; }
  .badge.connected { background: rgba(63,185,80,0.14); color: #15803d; border: 1px solid rgba(21,128,61,0.35); }
  .badge.disconnected { background: rgba(248,81,73,0.12); color: #DC2626; border: 1px solid rgba(220,38,38,0.35); }
  .badge.stale { background: rgba(210,153,34,0.14); color: #B45309; border: 1px solid rgba(180,83,9,0.35); }
  .route-list { font-family: monospace; font-size: 0.85em; }
  .route-list div { padding: 6px 0; border-bottom: 1px solid rgba(111,78,204,.10); }
  .route-list div:last-child { border: none; }
  .refresh-btn { background: #FFFFFF; border: 1px solid rgba(111,78,204,.20); color: #6F4ECC; padding: 8px 16px; border-radius: 999px; cursor: pointer; font-size: 0.85em; transition: all .18s; }
  .refresh-btn:hover { background: #F3EEFF; transform: translateY(-1px); box-shadow: 0 6px 18px rgba(95,65,180,.24); }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
  .mono { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85em; }
  .dim { color: #6B5CA5; }
  .bright { color: #241651; }
"""

LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#6F4ECC">
<title>Login - DARKVEDA LAB</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, 'Segoe UI', system-ui, sans-serif; background: #E9E0F8; color: #241651; min-height: 100vh; }
  body::before { content:''; position:fixed; inset:0; pointer-events:none; background: radial-gradient(900px 480px at 12% -8%, rgba(115,86,214,.16), transparent 60%), radial-gradient(800px 500px at 92% 4%, rgba(255,176,196,.10), transparent 60%); }
  .login-wrap { display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px; position:relative; z-index:1; }
  .login-box { background:linear-gradient(160deg, #7356D6, #6A48C7); border:none; border-radius:20px; padding:30px; width:100%; max-width:400px; box-shadow: 0 12px 30px rgba(95,65,180,.25); }
  .login-box h1 { font-size:1.3em; color:#FFFFFF; text-align:center; margin-bottom:24px; }
  .login-box h1 span { color:#FFB0C4; }
  label { display:block; font-size:0.8em; text-transform:uppercase; letter-spacing:0.5px; color:#D5CAFA; margin:16px 0 6px; }
  input[type=text], input[type=password] { width:100%; padding:11px 13px; background:#FFFFFF; border:1px solid rgba(111,78,204,.30); border-radius:12px; color:#241651; font-size:0.95em; outline:none; transition:all .2s; }
  input:focus { border-color:#FFFFFF; box-shadow: 0 0 0 3px rgba(255,255,255,.25); }
  .btn { width:100%; margin-top:24px; padding:12px; background:#FFFFFF; border:none; border-radius:999px; color:#6F4ECC; font-size:0.95em; font-weight:700; cursor:pointer; transition:all .18s; box-shadow: 0 4px 14px rgba(0,0,0,.15); }
  .btn:hover { background:#F3EEFF; transform:translateY(-1px); box-shadow: 0 6px 18px rgba(0,0,0,.22); }
  .err { background:rgba(255,255,255,.2); border:1px solid rgba(255,255,255,.35); color:#FFE0E6; padding:10px 13px; border-radius:12px; font-size:0.85em; margin-top:16px; }
  .lock { background:rgba(255,255,255,.2); border:1px solid rgba(255,255,255,.35); color:#FFF0C8; padding:10px 13px; border-radius:12px; font-size:0.85em; margin-top:16px; }
  @media (max-width: 640px) {
    .login-wrap { padding: 16px; padding-bottom: calc(16px + env(safe-area-inset-bottom, 0px)); }
    .login-box { padding: 24px 20px; }
    input[type=text], input[type=password] { font-size: 16px; }
    .btn { min-height: 46px; }
  }

</style></head><body>
<div class="login-wrap"><div class="login-box">
  <h1>⚡ DARKVEDA <span>LAB</span></h1>
  {% if error %}<div class="lock">{{ error }}</div>{% endif %}
  <form method="post" autocomplete="off">
    <label>Username</label>
    <input type="text" name="username" required autofocus spellcheck="false">
    <label>Password</label>
    <input type="password" name="password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
</div></div>
</body></html>"""

PW_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#6F4ECC">
<title>Change Password - DARKVEDA LAB</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, 'Segoe UI', system-ui, sans-serif; background: #E9E0F8; color: #241651; min-height: 100vh; }
  body::before { content:''; position:fixed; inset:0; pointer-events:none; background: radial-gradient(900px 480px at 12% -8%, rgba(115,86,214,.16), transparent 60%), radial-gradient(800px 500px at 92% 4%, rgba(255,176,196,.10), transparent 60%); }
  .pw-wrap { display:flex; align-items:center; justify-content:center; min-height:80vh; padding:20px; position:relative; z-index:1; }
  .pw-box { background:#FFFFFF; border:none; border-radius:20px; padding:30px; width:100%; max-width:430px; box-shadow: 0 8px 24px rgba(95,65,180,.18); }
  .pw-box h1 { font-size:1.2em; color:#6F4ECC; margin-bottom:6px; }
  .pw-box p.sub { color:#6B5CA5; font-size:0.85em; margin-bottom:20px; }
  label { display:block; font-size:0.8em; text-transform:uppercase; letter-spacing:0.5px; color:#6B5CA5; margin:16px 0 6px; }
  input[type=password] { width:100%; padding:11px 13px; background:#F6F2FF; border:1px solid rgba(111,78,204,.30); border-radius:12px; color:#241651; font-size:0.95em; outline:none; transition:all .2s; }
  input:focus { border-color:#6F4ECC; box-shadow: 0 0 0 3px rgba(111,78,204,.18); }
  .btn { margin-top:22px; padding:11px 20px; background:linear-gradient(135deg, #6F4ECC, #8066E0); border:none; border-radius:999px; color:#fff; font-weight:600; cursor:pointer; transition:all .18s; box-shadow: 0 4px 14px rgba(95,65,180,.35); }
  .btn:hover { transform:translateY(-1px); box-shadow: 0 6px 18px rgba(95,65,180,.45); }
  .btn.secondary { background:#FFFFFF; border:1px solid rgba(111,78,204,.35); color:#4A3AA0; margin-left:10px; box-shadow:none; }
  .msg-ok { background:rgba(63,185,80,0.14); border:1px solid rgba(21,128,61,0.35); color:#15803d; padding:10px 13px; border-radius:12px; font-size:0.85em; margin-top:16px; }
  .msg-err { background:rgba(248,81,73,0.12); border:1px solid rgba(220,38,38,0.35); color:#DC2626; padding:10px 13px; border-radius:12px; font-size:0.85em; margin-top:16px; }
  .rule { font-size:0.78em; color:#6B5CA5; margin-top:8px; line-height:1.5; }
  a.back { color:#6B5CA5; text-decoration:none; font-size:0.85em; }
  @media (max-width: 640px) {
    .pw-wrap { padding: 16px; padding-bottom: calc(16px + env(safe-area-inset-bottom, 0px)); }
    .pw-box { padding: 24px 20px; }
    input[type=password] { font-size: 16px; }
    .btn { width: 100%; min-height: 46px; }
    .btn.secondary { margin-left: 0; margin-top: 10px; }
  }
</style></head><body>
<div class="pw-wrap"><div class="pw-box">
  <h1>🔒 Change Password</h1>
  <p class="sub">Signed in as <b>{{ user }}</b></p>
  {% if ok %}<div class="msg-ok">{{ ok }}</div>{% endif %}
  {% if error %}<div class="msg-err">{{ error }}</div>{% endif %}
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label>Current password</label>
    <input type="password" name="current" required autocomplete="current-password">
    <label>New password</label>
    <input type="password" name="new" required autocomplete="new-password">
    <label>Confirm new password</label>
    <input type="password" name="confirm" required autocomplete="new-password">
    <div class="rule">Min 12 characters, must include letters and numbers. Stored as scrypt hash.</div>
    <button class="btn" type="submit">Update password</button>
    <a class="back" href="/" style="margin-left:12px;">← Back</a>
  </form>
</div></div>
</body></html>"""

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#6F4ECC">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>DARKVEDA LAB</title>
<script>(function(){try{var k="darkveda-theme",t=localStorage.getItem(k);if(!t){t=window.matchMedia&&window.matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light"}document.documentElement.setAttribute("data-theme",t)}catch(e){}})();</script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #E9E0F8;
    --card: #6F4ECC;
    --line: rgba(111,78,204,.16);
    --line2: rgba(111,78,204,.30);
    --text: #241651;
    --muted: #6B5CA5;
    --blue: #7356D6;
    --cyan: #7356D6;
    --green: #15803d;
    --red: #DC2626;
    --amber: #B45309;
    --violet: #7356D6;
    --accent-pink: #FFB0C4;
    --accent-track: #A99AE8;
    --shadow-card: 0 8px 24px rgba(95,65,180,.18), 0 2px 8px rgba(95,65,180,.12);
    --r: 16px;
  }
  html, body { height: 100%; }
  html[data-theme="dark"] { --bg: #0F0C23; --card: #1E1B3A; --text: #EDE8FF; --muted: #9B8ED1; --line: rgba(255,255,255,.08); --line2: rgba(255,255,255,.14); }
  html[data-theme="dark"] .topbar { background: rgba(15,12,35,.85); border-bottom-color: rgba(255,255,255,.08); color: #EDE8FF; }
  html[data-theme="dark"] .tabs-inner { background: rgba(30,27,58,.9); border-color: rgba(255,255,255,.10); }
  html[data-theme="dark"] .section { background: #1A1633; color: #EDE8FF; --text: #EDE8FF; --muted: #9B8ED1; --line: rgba(255,255,255,.08); --line2: rgba(255,255,255,.14); }
  html[data-theme="dark"] textarea, html[data-theme="dark"] input[type=text], html[data-theme="dark"] input[type=password], html[data-theme="dark"] select { background: #211D42; border-color: rgba(255,255,255,.14); color: #EDE8FF; }
  html[data-theme="dark"] .form-panel { background: rgba(30,27,58,.7); border-color: rgba(255,255,255,.10); }
  html[data-theme="dark"] .vendor-block { background: #1A1633; border-color: rgba(255,255,255,.08); }
  html[data-theme="dark"] .vendor-block-head { background: #211D42; }
  html[data-theme="dark"] .vendor-block-head:hover { background: #2A2452; }
  html[data-theme="dark"] .btn { background: #25204A; color: #EDE8FF; }
  html[data-theme="dark"] .btn:hover { background: #2F285C; }
  /* Dark-theme contrast fixes: light theme hardcodes dark-purple text (#241651/#6B5CA5/#3B2A8C)
     which turns invisible on dark backgrounds. Override all of them here. */
  html[data-theme="dark"] .section h2 { color: #EDE8FF; }
  html[data-theme="dark"] .bright { color: #EDE8FF; }
  html[data-theme="dark"] .tab { color: #9B8ED1; }
  html[data-theme="dark"] .tab:hover { color: #EDE8FF; }
  html[data-theme="dark"] .clock { color: #C4B5FD; background: rgba(139,92,246,.14); border-color: rgba(139,92,246,.35); }
  html[data-theme="dark"] .form-title { color: #C4B5FD; }
  html[data-theme="dark"] .btn.danger { color: #F87171; border-color: rgba(248,113,113,.5); background: rgba(248,113,113,.12); }
  html[data-theme="dark"] .btn.danger:hover { background: rgba(248,113,113,.22); }
  html[data-theme="dark"] .badge.connected { background: rgba(74,222,128,.15); color: #4ADE80; border-color: rgba(74,222,128,.4); }
  html[data-theme="dark"] .badge.disconnected { background: rgba(248,113,113,.15); color: #F87171; border-color: rgba(248,113,113,.4); }
  html[data-theme="dark"] .badge.stale { background: rgba(251,191,36,.15); color: #FBBF24; border-color: rgba(251,191,36,.4); }
  html[data-theme="dark"] tbody tr:hover { background: rgba(139,92,246,.10); }
  html[data-theme="dark"] td { border-bottom-color: rgba(255,255,255,.07); }
  html[data-theme="dark"] .route-list div { border-bottom-color: rgba(255,255,255,.07); }
  html[data-theme="dark"] .copy-btn:hover { color: #C4B5FD; background: rgba(139,92,246,.15); }
  html[data-theme="dark"] textarea::placeholder, html[data-theme="dark"] input::placeholder { color: #7E739F; opacity: 1; }
  html[data-theme="dark"] .chip-btn { color: #9B8ED1; border-color: rgba(255,255,255,.14); background: rgba(255,255,255,.03); }
  html[data-theme="dark"] .chip-btn:hover { color: #C4B5FD; border-color: rgba(139,92,246,.5); background: rgba(139,92,246,.12); }
  html[data-theme="dark"] .footer { color: #6D6390; }
  /* vendor-block card headers (Run Logs pattern): hard Light-theme title/tag colors go invisible on dark */
  html[data-theme="dark"] .vendor-block-head .vtitle { color: #EDE8FF; }
  html[data-theme="dark"] .vendor-block-head .vtag { background: rgba(139,92,246,.18); color: #C4B5FD; }
  html[data-theme="dark"] .vendor-block-head .chevron { color: #C4B5FD; background: rgba(139,92,246,.15); }

  body { font-family: 'Inter', -apple-system, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; }
  body::before {
    content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background:
      radial-gradient(900px 480px at 12% -8%, rgba(115,86,214,.16), transparent 60%),
      radial-gradient(800px 500px at 92% 4%, rgba(255,176,196,.10), transparent 60%),
      radial-gradient(700px 420px at 50% 110%, rgba(169,154,232,.14), transparent 60%);
  }

  /* ---------- topbar ---------- */
  .topbar { position: sticky; top: 0; z-index: 50; display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 13px 26px; background: rgba(233,224,248,.85); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border-bottom: 1px solid rgba(111,78,204,.20); color: #241651; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo { width: 40px; height: 40px; border-radius: 11px; display: flex; align-items: center; justify-content: center; background: linear-gradient(145deg, #6F4ECC, #9A7DE8); box-shadow: 0 6px 18px rgba(95,65,180,.40), inset 0 1px 0 rgba(255,255,255,.25); flex-shrink: 0; }
  .brand-title { font-size: 1.12em; font-weight: 800; letter-spacing: .5px; }
  .brand-title span { background: linear-gradient(90deg, #6F4ECC, #B487E8); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .brand-sub { font-size: .66em; color: var(--muted); letter-spacing: 2.2px; text-transform: uppercase; margin-top: 2px; }
  .topbar-right { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  /* Global search lives in the middle: auto-margins centre it between brand and actions */
  .topbar-search { flex: 0 1 380px; margin-inline: auto; position: relative; min-width: 0; }
  .clock { font-family: \'SF Mono\',\'Cascadia Code\',\'Fira Code\',ui-monospace,monospace; font-size: .8em; color: #6F4ECC; background: rgba(111,78,204,.10); border: 1px solid rgba(111,78,204,.30); padding: 5px 10px; border-radius: 8px; }
  .meta { font-size: .78em; color: var(--muted); }
  .chip-btn { color: var(--muted); text-decoration: none; font-size: .8em; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line); background: rgba(255,255,255,.02); transition: all .18s; }
  /* Theme toggle + Refresh travel as one pair: identical metrics so they sit on the same level */
  #themeToggle { padding: 7px 13px; border-radius: 999px; font-size: .83em; font-weight: 600; }
  @media (pointer: coarse) { #themeToggle { min-height: 40px; } }
  .chip-btn:hover { color: var(--blue); border-color: rgba(111,78,204,.45); background: rgba(111,78,204,.10); }
  .chip-btn.danger:hover { color: var(--red); border-color: rgba(248,81,73,.4); background: rgba(248,81,73,.07); }

  .btn { border: none; background: #fff; color: #4A3AA0; padding: 7px 16px; border-radius: 999px; cursor: pointer; font-size: .83em; font-weight: 600; transition: all .18s; box-shadow: 0 4px 12px rgba(95,65,180,.16); }
  .btn:hover { background: #F3EEFF; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(95,65,180,.24); }
  .btn:active { transform: translateY(0); }
  .btn.primary { background: linear-gradient(135deg, #6F4ECC, #8066E0); border: none; color: #fff; box-shadow: 0 4px 14px rgba(95,65,180,.35); }
  .btn.primary:hover { box-shadow: 0 6px 20px rgba(95,65,180,.50); }
  .btn.success { background: linear-gradient(135deg, #15803d, #16a34a); border: none; color: #fff; border-radius: 999px; box-shadow: 0 4px 14px rgba(22,163,74,.28); }
  .btn.success:hover { box-shadow: 0 6px 20px rgba(22,163,74,.42); border-radius: 999px; }
  .btn.warn { background: linear-gradient(135deg, #b45309, #d97706); border: none; color: #fff; border-radius: 999px; box-shadow: 0 4px 14px rgba(217,119,6,.28); }
  .btn.danger { background: rgba(248,81,73,.14); border: 1px solid rgba(248,81,73,.45); color: #DC2626; border-radius: 999px; }
  .btn.danger:hover { background: rgba(248,81,73,.2); }
  .btn.xs { padding: 4px 10px; font-size: .72em; border-radius: 999px; }

  /* ---------- tabs ---------- */
  .tabs { position: sticky; top: 67px; z-index: 40; display: flex; gap: 4px; max-width: 1240px; margin: 18px auto 0; padding: 0 26px; }
  .tabs-inner { position: relative; display: flex; gap: 4px; background: rgba(255,255,255,.72); border: 1px solid rgba(111,78,204,.18); border-radius: 999px; padding: 5px; backdrop-filter: blur(10px); box-shadow: 0 6px 18px rgba(95,65,180,.14); }
  .tab { position: relative; z-index: 2; border: none; background: transparent; color: #6B5CA5; padding: 8px 20px; border-radius: 999px; cursor: pointer; font-size: .88em; font-weight: 600; transition: color .2s; }
  .tab:hover { color: #3B2A8C; }
  .tab.active { color: #fff; }
  .tab-glider { position: absolute; z-index: 1; top: 5px; bottom: 5px; left: 0; width: 0; border-radius: 9px; background: linear-gradient(135deg, #6F4ECC, #8066E0); box-shadow: 0 4px 14px rgba(95,65,180,.40); border-radius: 999px; transition: left .25s cubic-bezier(.4,0,.2,1), width .25s cubic-bezier(.4,0,.2,1); opacity: 0; }

  .container { max-width: 1240px; margin: 0 auto; padding: 20px 26px 44px; position: relative; z-index: 1; }

  /* ---------- status cards ---------- */
  .status-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(215px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .status-card { position: relative; overflow: hidden; background: linear-gradient(160deg, #7356D6, #6A48C7); border: none; border-radius: 20px; padding: 18px 20px; box-shadow: var(--shadow-card); color: #fff; --muted: #D5CAFA; --line: rgba(255,255,255,.22); --line2: rgba(255,255,255,.30); transition: transform .18s; }
  .status-card:hover { transform: translateY(-3px); }
  .status-card::after { content: \'\'; position: absolute; top: 0; left: 18px; right: 18px; height: 2px; background: linear-gradient(90deg, transparent, var(--accent, rgba(255,176,196,.75)), transparent); opacity: .75; }
  .sc-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .label { font-size: .67em; text-transform: uppercase; letter-spacing: 1.6px; color: var(--muted); font-weight: 600; }
  .sc-ico { font-size: .95em; opacity: .8; }
  .value { font-size: 1.5em; font-weight: 800; letter-spacing: .3px; }
  .value.up { color: var(--green); }
  .value.down { color: var(--red); }
  .value.warn { color: var(--amber); }
  .status-card .value.up { color: #7CF0A0; }
  .status-card .value.down { color: #FF9B96; }
  .status-card .value.warn { color: #FFD37A; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: currentColor; margin-right: 8px; vertical-align: 6px; animation: ping 1.8s infinite; }
  @keyframes ping { 0% { box-shadow: 0 0 0 0 rgba(124,240,160,.55); } 70% { box-shadow: 0 0 0 8px rgba(124,240,160,0); } 100% { box-shadow: 0 0 0 0 rgba(124,240,160,0); } }
  /* live pulse dot on table status badges (same feel as Tunnel Status card) */
  #peerTable .badge::before, #ifaceTable .badge::before, #smbSvcBadge::before, #mvDevTable .badge::before, #mvFilesTable .badge::before, #mvJobBadge::before { content: ''; display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: currentColor; margin-right: 6px; vertical-align: 1px; animation: ping-badge 1.8s ease-out infinite; }
  #peerTable .badge.connected::before, #ifaceTable .badge.connected::before, #smbSvcBadge.connected::before, #mvDevTable .badge.connected::before, #mvFilesTable .badge.connected::before, #mvJobBadge.connected::before { animation-name: ping-green; }
  #peerTable .badge.stale::before, #ifaceTable .badge.stale::before, #smbSvcBadge.stale::before, #mvDevTable .badge.stale::before, #mvFilesTable .badge.stale::before, #mvJobBadge.stale::before { animation-name: ping-amber; }
  #peerTable .badge.disconnected::before, #ifaceTable .badge.disconnected::before, #smbSvcBadge.disconnected::before, #mvDevTable .badge.disconnected::before, #mvFilesTable .badge.disconnected::before, #mvJobBadge.disconnected::before { animation-name: ping-red; }
  @keyframes ping-badge { 0% { box-shadow: 0 0 0 0 rgba(107,92,165,.45); } 70% { box-shadow: 0 0 0 7px rgba(107,92,165,0); } 100% { box-shadow: 0 0 0 0 rgba(107,92,165,0); } }
  @keyframes ping-green { 0% { box-shadow: 0 0 0 0 rgba(21,128,61,.50); } 70% { box-shadow: 0 0 0 7px rgba(21,128,61,0); } 100% { box-shadow: 0 0 0 0 rgba(21,128,61,0); } }
  @keyframes ping-amber { 0% { box-shadow: 0 0 0 0 rgba(180,83,9,.50); } 70% { box-shadow: 0 0 0 7px rgba(180,83,9,0); } 100% { box-shadow: 0 0 0 0 rgba(180,83,9,0); } }
  @keyframes ping-red { 0% { box-shadow: 0 0 0 0 rgba(220,38,38,.50); } 70% { box-shadow: 0 0 0 7px rgba(220,38,38,0); } 100% { box-shadow: 0 0 0 0 rgba(220,38,38,0); } }
  .detail { font-size: .77em; color: var(--muted); margin-top: 5px; }
  #trafficSpark { width: 100%; height: 34px; margin-top: 8px; display: block; }
  .peer-spark { width: 120px; height: 28px; display: inline-block; vertical-align: middle; }

  /* ---------- sections ---------- */
  .section { background: #FFFFFF; border: none; border-radius: 20px; padding: 22px 24px; margin-bottom: 18px; box-shadow: var(--shadow-card); color: #241651; --text: #241651; --muted: #6B5CA5; overflow: hidden; }
  .table-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; margin: 0 -4px; padding: 0 4px 4px; }
  .table-scroll table { min-width: 680px; }
  .table-scroll thead th:nth-child(5), .table-scroll thead th:nth-child(6), .table-scroll tbody td:nth-child(5), .table-scroll tbody td:nth-child(6) { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
  .table-scroll tbody td { white-space: nowrap; }
  .section h2 { font-size: 1em; font-weight: 700; color: #241651; margin-bottom: 14px; display: flex; align-items: center; gap: 10px; }
  .section h2::before { content: \'\'; width: 5px; height: 18px; border-radius: 999px; background: linear-gradient(180deg, #6F4ECC, #B487E8); }
  .sub-label { font-size: .67em; text-transform: uppercase; letter-spacing: 1.4px; color: var(--muted); margin-bottom: 8px; font-weight: 600; }

  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 9px 12px; color: var(--muted); font-size: .68em; text-transform: uppercase; letter-spacing: 1.2px; border-bottom: 1px solid var(--line2); font-weight: 600; }
  td { padding: 11px 12px; border-bottom: 1px solid rgba(111,78,204,.10); font-size: .86em; font-family: \'SF Mono\',\'Cascadia Code\',\'Fira Code\',ui-monospace,monospace; }
  tbody tr { transition: background .15s; }
  tbody tr:hover { background: rgba(111,78,204,.07); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: .72em; font-weight: 700; letter-spacing: .4px; }
  .badge.connected { background: rgba(63,185,80,.14); color: #15803d; border: 1px solid rgba(21,128,61,.35); }
  .badge.disconnected { background: rgba(248,81,73,.12); color: #DC2626; border: 1px solid rgba(220,38,38,.35); }
  .badge.stale { background: rgba(210,153,34,.14); color: #B45309; border: 1px solid rgba(180,83,9,.35); }

  .route-list { font-family: \'SF Mono\',\'Cascadia Code\',\'Fira Code\',ui-monospace,monospace; font-size: .83em; }
  .route-list div { padding: 6px 0; border-bottom: 1px solid rgba(111,78,204,.10); transition: padding-left .15s; }
  .route-list div:hover { padding-left: 6px; }
  .route-list div:last-child { border: none; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } .topbar { flex-direction: column; align-items: flex-start; } .tabs { top: auto; position: static; } }

  .mono { font-family: \'SF Mono\',\'Cascadia Code\',\'Fira Code\',ui-monospace,monospace; font-size: .85em; }
  .dim { color: var(--muted); }
  .bright { color: #241651; }
  .copy-btn { background: none; border: none; color: var(--muted); cursor: pointer; font-size: .8em; padding: 2px 6px; border-radius: 5px; transition: all .15s; }
  .copy-btn:hover { color: #6F4ECC; background: rgba(111,78,204,.12); }

  textarea, input[type=text], input[type=password], select { width: 100%; background: #F6F2FF; border: 1px solid rgba(111,78,204,.30); border-radius: 12px; color: #241651; font-family: \'SF Mono\',\'Cascadia Code\',\'Fira Code\',ui-monospace,monospace; font-size: .88em; padding: 10px 13px; outline: none; transition: border .18s, box-shadow .18s; }
  textarea:focus, input:focus, select:focus { border-color: #6F4ECC; box-shadow: 0 0 0 3px rgba(111,78,204,.18); }
  textarea { resize: vertical; }
  label.flabel { display: block; font-size: .66em; text-transform: uppercase; letter-spacing: 1.3px; color: var(--muted); margin-bottom: 5px; font-weight: 600; }

  .form-panel { background: #F3EEFF; border: 1px solid rgba(111,78,204,.18); border-radius: 16px; padding: 18px; margin-bottom: 16px; }
  .form-title { color: #6F4ECC; font-weight: 700; margin-bottom: 13px; font-size: .95em; }
  .msg-line { font-size: .83em; min-height: 1.2em; }
  .log-output { background: #F6F2FF; border: 1px solid rgba(111,78,204,.30); border-radius: 12px; color: #241651; font-family: 'SF Mono','Cascadia Code','Fira Code',ui-monospace,monospace; font-size: .76em; line-height: 1.55; padding: 12px 14px; max-height: 420px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
  html[data-theme="dark"] .log-output { background: #211D42; border-color: rgba(255,255,255,.14); color: #EDE8FF; }

  #globalSearch { padding: 7px 12px 7px 32px; }
  html[data-theme="dark"] #globalSearchResults { background: #1A1633; border-color: rgba(255,255,255,.12); color: #EDE8FF; }
  #globalSearchResults .gs-kind { font-size:.66em; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); padding:8px 14px 4px; font-weight:700; }
  #globalSearchResults .gs-item { display:block; padding:8px 14px; cursor:pointer; border-bottom:1px solid rgba(111,78,204,.08); }
  #globalSearchResults .gs-item:hover, #globalSearchResults .gs-item.active { background: rgba(111,78,204,.08); }
  #globalSearchResults .gs-label { font-weight:700; font-size:.85em; }
  #globalSearchResults .gs-sub { font-size:.75em; color: var(--muted); font-family: ui-monospace,monospace; }
  .toast-wrap { position: fixed; right: 18px; bottom: 18px; z-index: 999; display: flex; flex-direction: column; gap: 10px; max-width: 340px; }
  .toast { background: #FFFFFF; color: #241651; border: none; border-left: 4px solid #6F4ECC; padding: 11px 16px; border-radius: 14px; font-size: .84em; transform: translateX(130%); opacity: 0; transition: transform .3s cubic-bezier(.4,0,.2,1), opacity .3s; box-shadow: 0 12px 30px rgba(95,65,180,.28); }
  .toast.show { transform: none; opacity: 1; }
  .toast.ok { border-left-color: var(--green); }
  .toast.err { border-left-color: var(--red); }
  .toast.warn { border-left-color: var(--amber); }

  .footer { text-align: center; color: #6B5CA5; font-size: .75em; margin-top: 10px; letter-spacing: .4px; }
  .kbd { display: inline-block; padding: 1px 6px; border: 1px solid var(--line2); border-radius: 5px; font-size: .9em; margin: 0 2px; color: var(--muted); }

  .mvsubnav { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .mvsub { padding: 9px 17px; background: rgba(255,255,255,.55); border: 1px solid rgba(115,86,214,.25);
    border-radius: 999px; color: #6F4ECC; font-size: .8em; font-weight: 700; cursor: pointer; transition: all .18s; }
  .mvsub:hover { background: #FFFFFF; transform: translateY(-1px); }
  .mvsub.active { background: #6F4ECC; border-color: #6F4ECC; color: #FFFFFF; box-shadow: 0 4px 14px rgba(111,78,204,.4); }
  .mvradio { display: flex; gap: 9px; align-items: flex-start; padding: 12px 14px; background: rgba(255,255,255,.55);
    border: 1px solid rgba(115,86,214,.25); border-radius: 14px; cursor: pointer; font-size: .83em; transition: all .15s; }
  .mvradio:hover { background: #FFFFFF; }
  .mvradio input { margin-top: 3px; accent-color: #6F4ECC; }
  .mvradio small { display: block; color: #6B5CA5; font-size: .82em; }
  .mvnotify-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(190px,1fr)); gap: 10px; }
  .mvnotify { display: block; padding: 12px 14px; background: #fff; border: 1px solid rgba(115,86,214,.18);
    border-radius: 12px; cursor: pointer; transition: all .15s; }
  .mvnotify:hover { background: #FFFFFF; box-shadow: 0 2px 10px rgba(111,78,204,.15); }
  .mvnotify.sel { border-color: #6F4ECC; box-shadow: 0 0 0 1px #6F4ECC, 0 4px 14px rgba(111,78,204,.28); background: #F6F1FF; }
  .mvnotify input { accent-color: #6F4ECC; margin-right: 7px; }
  .mvnotify strong { font-size: .88em; color: #241651; }
  .mvnotify small { display: block; color: #6B5CA5; font-size: .78em; margin-top: 3px; }
  input.mvtoggle { appearance: none; -webkit-appearance: none; width: 40px; height: 22px; border-radius: 999px;
    background: rgba(115,86,214,.28); border: 1px solid rgba(115,86,214,.35); position: relative; cursor: pointer;
    outline: none; transition: background .18s; flex-shrink: 0; margin: 0; vertical-align: middle; }
  input.mvtoggle:checked { background: #6F4ECC; border-color: #6F4ECC; }
  input.mvtoggle::after { content: \'\'; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
    border-radius: 50%; background: #fff; transition: left .18s; box-shadow: 0 1px 3px rgba(0,0,0,.3); }
  input.mvtoggle:checked::after { left: 20px; }
  .mvfield label { font-size: .7em; }
  .mvhint { border-left: 3px solid #6F4ECC; background: rgba(111,78,204,.07); border-radius: 0 12px 12px 0;
    padding: 10px 13px; font-size: .76em; color: #6B5CA5; margin-top: 13px; line-height: 1.6; }
  .mvadd { color: #7CF0A0; font-weight: 700; }
  .mvdel { color: #FFB0C4; font-weight: 700; }
  .mvhunk { color: #B7A6F2; }
  .mvhd { color: #FFFFFF; font-weight: 700; }
  .vendor-block { border: 1px solid rgba(111,78,204,.14); border-radius: 16px; margin-bottom: 14px; overflow: hidden; background: #fff; box-shadow: var(--shadow-card); }
  .vendor-block-head { display: flex; align-items:center; gap:10px; padding:13px 16px; cursor:pointer; user-select:none; background:#F6F2FF; transition:background .15s; }
  .vendor-block-head:hover { background:#EDE6FF; cursor:pointer; }
  .vendor-block-head .chevron { color:#6F4ECC; transition:transform .22s ease; display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:6px; background:rgba(111,78,204,.10); font-size:13px; font-weight:700; flex-shrink:0; }
  .vendor-block.collapsed .chevron { transform: rotate(-90deg); background:rgba(111,78,204,.16); }
  .vendor-block-head .vtitle { font-weight:700; font-size:.92em; letter-spacing:.3px; color:#241651; }
  .vendor-block-head .vtag { font-family:ui-monospace,monospace; font-size:.72em; padding:3px 9px; border-radius:999px; background:rgba(111,78,204,.12); color:#6B5CA5; }
  .vendor-block-head .spacer { flex:1; }
  .vendor-block.collapsed .vendor-block-body { display:none !important; }
  .vendor-block .table-scroll { margin:0; padding:0; }
  .vendor-block table { min-width:0; }
  .vendor-block th:first-child, .vendor-block td:first-child { width:34px; text-align:center; }
  .vendor-block .btn-row { display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; align-items:center; border-top:1px solid rgba(111,78,204,.10); background:#FBF8FF; }
  .count-chip { font-size:.72em; padding:3px 9px; border-radius:999px; background:#6F4ECC; color:#fff; font-weight:700; }
  input.mvchk { appearance:none; width:16px; height:16px; border:1.5px solid rgba(111,78,204,.35); border-radius:4px; background:#fff; cursor:pointer; position:relative; transition:.14s; vertical-align:middle; }
  input.mvchk:hover { border-color:#6F4ECC; }
  input.mvchk:checked { background:#6F4ECC; border-color:#6F4ECC; }
  input.mvchk:checked::after { content:""; position:absolute; left:4.5px; top:1px; width:4px; height:8px; border:solid #fff; border-width:0 2px 2px 0; transform:rotate(45deg); }


  /* Samba tidy */
  .samba-kpi { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap:14px; margin-bottom:18px; }
  .samba-kpi .kpi-mini { background:#F6F2FF; border:1px solid rgba(111,78,204,.14); border-radius:14px; padding:14px 16px; }
  html[data-theme="dark"] .samba-kpi .kpi-mini { background:#1A1633; border-color:rgba(255,255,255,.08); }
  .samba-kpi .kpi-mini .k { font-size:.68em; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); font-weight:700; }
  .samba-kpi .kpi-mini .v { font-size:1.35em; font-weight:800; margin-top:4px; }
  .samba-kpi .kpi-mini .s { font-size:.76em; color:var(--muted); margin-top:6px; }
  .usage-track { display:block; height:8px; border-radius:999px; background:rgba(111,78,204,.12); overflow:hidden; margin-top:7px; }
  .usage-fill { display:block; height:100%; border-radius:999px; background: linear-gradient(90deg,#6F4ECC,#9A7DE8); }
  html[data-theme="dark"] .usage-track { background:rgba(255,255,255,.10); }
  .net-chip { display:inline-block; padding:2px 8px; border-radius:999px; background:rgba(111,78,204,.10); color:#4A3AA0; font-size:.72em; font-weight:600; margin:2px 4px 2px 0; border:1px solid rgba(111,78,204,.18); }
  html[data-theme="dark"] .net-chip { background:rgba(111,78,204,.18); color:#D5CAFA; }
  .net-more { background:none; border:none; color:#6F4ECC; font-size:.72em; cursor:pointer; font-weight:700; }
  .share-row-path { color:var(--muted); font-size:.78em; word-break:break-all; margin-top:3px; }
  .samba-actions .btn { padding:4px 10px; }

  /* IPAM tab — DARKVEDA theme */
  .ipam-kpi { display:grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap:14px; margin-bottom:18px; }
  .ipam-kpi .kpi-mini { background:#F6F2FF; border:1px solid rgba(111,78,204,.14); border-radius:14px; padding:14px 16px; }
  html[data-theme="dark"] .ipam-kpi .kpi-mini { background:#1A1633; border-color:rgba(255,255,255,.08); }
  .ipam-kpi .kpi-mini .k { font-size:.68em; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); font-weight:700; }
  .ipam-kpi .kpi-mini .v { font-size:1.5em; font-weight:800; margin-top:4px; }
  .ipam-kpi .kpi-mini .s { font-size:.76em; color:var(--muted); margin-top:6px; }
  .util-track { display:block; height:8px; border-radius:999px; background:rgba(111,78,204,.12); overflow:hidden; margin-top:6px; }
  .util-fill { display:block; height:100%; border-radius:999px; background: linear-gradient(90deg,#6F4ECC,#9A7DE8); }
  html[data-theme="dark"] .util-track { background:rgba(255,255,255,.10); }
  .util-fill.hot { background: linear-gradient(90deg,#EF4444,#F59E0B); }
  .ip-status { display:inline-block; padding:2px 9px; border-radius:999px; font-size:.72em; font-weight:700; }
  .ip-st-active { background:rgba(34,197,94,.15); color:#16A34A; }
  html[data-theme="dark"] .ip-st-active { color:#4ADE80; }
  .ip-st-reserved { background:rgba(234,179,8,.15); color:#B45309; }
  html[data-theme="dark"] .ip-st-reserved { color:#FBBF24; }
  .ip-st-dhcp { background:rgba(59,130,246,.15); color:#1D4ED8; }
  html[data-theme="dark"] .ip-st-dhcp { color:#60A5FA; }
  .ip-st-gateway { background:rgba(139,92,246,.2); color:#6D28D9; }
  html[data-theme="dark"] .ip-st-gateway { color:#A78BFA; }
  .ip-st-off { background:rgba(239,68,68,.12); color:#B91C1C; }
  html[data-theme="dark"] .ip-st-off { color:#F87171; }
  .subnet-row { cursor:pointer; }
  .subnet-row:hover td { background:rgba(111,78,204,.06); }
  html[data-theme="dark"] .subnet-row:hover td { background:rgba(111,78,204,.10); }
  .ipam-modal { position:fixed; inset:0; background:rgba(20,10,50,.5); display:none; align-items:center; justify-content:center; z-index:200; padding:18px; }
  .ipam-modal.open { display:flex; }
  .ipam-dialog { background:#fff; color:#241651; border-radius:18px; padding:22px; width:100%; max-width:520px; box-shadow:0 24px 60px rgba(40,20,100,.35); }
  html[data-theme="dark"] .ipam-dialog { background:#1A1633; color:#EDE8FF; }
  .ipam-dialog label { font-size:.72em; color:var(--muted); font-weight:700; text-transform:uppercase; letter-spacing:.8px; }
  .ipam-dialog input { width:100%; margin:4px 0 12px; }


  /* Samba 4-card grid — clean */
  .samba-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:16px; margin-top:16px; }
  @media (max-width: 880px){ .samba-grid { grid-template-columns: 1fr; } }
  .samba-card { background:#fff; border:1px solid rgba(111,78,204,.14); border-radius:16px; box-shadow:0 4px 16px rgba(95,65,180,.08); padding:18px 20px; min-height:200px; }
  .samba-card h3 { margin:0 0 12px; font-size:.78em; text-transform:uppercase; letter-spacing:.8px; color:var(--muted); font-weight:700; }
  html[data-theme="dark"] .samba-card { background:#1A1633; border-color:rgba(255,255,255,.08); }
  .samba-card .empty-card { color:var(--muted); font-size:.88em; padding:8px 2px; }
  .samba-card table { margin:0; }
  .samba-card .table-scroll { margin:0; }

  /* Setting tab — card visibility toggles */
  .set-row { display:flex; align-items:center; gap:14px; padding:14px 16px; background:#F6F2FF; border:1px solid rgba(111,78,204,.14); border-radius:14px; margin-bottom:10px; transition:all .15s; }
  .set-row:hover { background:#fff; box-shadow:0 2px 10px rgba(111,78,204,.12); }
  .set-row.hidden-card { opacity:.65; }
  html[data-theme="dark"] .set-row { background:#211D42; border-color:rgba(255,255,255,.10); }
  html[data-theme="dark"] .set-row:hover { background:#2A2452; }
  .set-ico { width:42px; height:42px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:1.25em; flex-shrink:0; background:linear-gradient(145deg,#6F4ECC,#9A7DE8); color:#fff; box-shadow:0 4px 12px rgba(95,65,180,.30); }
  .set-info { flex:1; min-width:0; }
  .set-name { font-weight:800; font-size:.95em; }
  .set-desc { font-size:.78em; color:var(--muted); margin-top:2px; }
  .set-state { font-size:.72em; font-weight:700; padding:3px 10px; border-radius:999px; }
  .set-state.on { background:rgba(34,197,94,.15); color:#16A34A; border:1px solid rgba(22,163,74,.35); }
  html[data-theme="dark"] .set-state.on { color:#4ADE80; }
  .set-state.off { background:rgba(239,68,68,.12); color:#B91C1C; border:1px solid rgba(220,38,38,.35); }
  html[data-theme="dark"] .set-state.off { color:#F87171; }

  /* ---------- mobile smooth: Samsung / iPhone ---------- */
  html { -webkit-text-size-adjust: 100%; }
  body { -webkit-tap-highlight-color: transparent; min-height: 100dvh; }
  .btn, .tab, .mvsub, .chip-btn, .copy-btn, .net-more, .vendor-block-head, input.mvchk, input.mvtoggle { touch-action: manipulation; }
  .table-scroll { overscroll-behavior-x: contain; }
  img, svg, canvas { max-width: 100%; }
  #globalSearch { min-width: 0; }
  @media (max-width: 640px) {
    .container { padding: 14px 12px calc(40px + env(safe-area-inset-bottom, 0px)); }
    .topbar { flex-direction: row; flex-wrap: wrap; align-items: center; padding: 10px 12px; gap: 10px; padding-top: calc(10px + env(safe-area-inset-top, 0px)); }
    .brand-sub { display: none; }
    .brand-title { font-size: 1em; }
    .logo { width: 34px; height: 34px; }
    .topbar-right { width: 100%; gap: 8px; }
    .topbar-right .btn.primary { flex-shrink: 0; }
    .topbar-search { flex: 1 1 100%; margin: 0; }
    #globalSearch { width: 100%; max-width: none !important; font-size: 16px; }
    .clock { display: none; }
    .tabs { padding: 0 12px; margin-top: 12px; }
    .tabs-inner { max-width: 100%; overflow-x: auto; scrollbar-width: none; -webkit-overflow-scrolling: touch; scroll-snap-type: x proximity; }
    .tabs-inner::-webkit-scrollbar { display: none; }
    .tab { flex-shrink: 0; scroll-snap-align: start; padding: 10px 16px; }
    .section { padding: 16px 14px; border-radius: 16px; }
    .status-bar { grid-template-columns: 1fr 1fr; gap: 10px; }
    .status-card { padding: 14px; border-radius: 16px; }
    .status-card .value { font-size: 1.2em; }
    td { padding: 9px 10px; font-size: .8em; }
    textarea, input[type=text], input[type=password], select { font-size: 16px; }
    .samba-actions .btn, td .btn.xs { margin: 2px 0; }
    .set-row { flex-wrap: wrap; gap: 10px; }
    .footer .kbd { display: none; }
    .toast-wrap { left: 12px; right: 12px; max-width: none; bottom: calc(12px + env(safe-area-inset-bottom, 0px)); }
    .ipam-modal { padding: 12px; padding-bottom: calc(12px + env(safe-area-inset-bottom, 0px)); }
    .ipam-dialog { max-height: calc(92dvh - env(safe-area-inset-top, 0px)); overflow-y: auto; -webkit-overflow-scrolling: touch; }
    .ipam-kpi { grid-template-columns: 1fr 1fr; gap: 10px; }
    .ipam-kpi .kpi-mini { padding: 12px 13px; border-radius: 12px; }
    .ipam-kpi .kpi-mini .v { font-size: 1.25em; }
    #ipamTab .section { overflow: hidden; }
    #ipamTab .table-scroll { margin: 0 -14px; padding: 0 14px 6px; -webkit-overflow-scrolling: touch; overscroll-behavior-x: contain; }
    #ipamTab table { min-width: 560px; }
    #ipamFullBtn { flex: 1 1 100%; text-align: center; min-height: 42px; }
    .topbar-right .meta { display: none; }
    #peerEndpoint { font-size: .85em !important; overflow-wrap: anywhere; }
    #peerEndpoint .copy-btn { display: none; }
    #traffic { font-size: .95em !important; overflow-wrap: anywhere; }
    .vendor-block-head { padding: 12px 13px; }
    .vendor-block-head .vtitle { font-size: .86em; }
    th { padding: 8px 10px; }
    #shareForm .btn.success, #userForm .btn { flex: 1 1 100%; min-height: 44px; }
    .status-card .detail { overflow-wrap: anywhere; }
  }
  /* ---------- tablet: iPad / Android TAB portrait + small landscape ---------- */
  @media (max-width: 1024px) {
    .container { padding: 18px 18px 40px; }
    .tabs { padding: 0 18px; }
    .topbar { padding: 12px 18px; flex-wrap: wrap; }
    .section { padding: 20px; }
    .status-card .value { font-size: 1.35em; }
    .status-bar { gap: 12px; }
  }
  /* ---------- landscape phones: reclaim vertical space ---------- */
  @media (max-height: 500px) and (orientation: landscape) {
    .topbar { padding: 8px 12px; gap: 8px; }
    .logo { width: 30px; height: 30px; }
    .brand-sub, .clock, .meta#uptime { display: none; }
    .status-bar { grid-template-columns: repeat(4, 1fr); gap: 10px; }
    .status-card { padding: 10px 14px; }
    .status-card .value { font-size: 1.1em; }
    #peerEndpoint { font-size: .78em !important; }
    #traffic { font-size: .85em !important; }
    .section { padding: 14px 16px; margin-bottom: 12px; }
    #trafficSpark { display: none; }
  }
  @media (max-width: 380px) {
    .status-bar { grid-template-columns: 1fr; }
    .meta#uptime { display: none; }
  }
  @media (pointer: coarse) {
    .btn { min-height: 40px; }
    .btn.xs { min-height: 34px; padding: 6px 12px; }
    .tab { min-height: 42px; }
    .chip-btn { min-height: 36px; display: inline-flex; align-items: center; }
    .copy-btn { min-width: 34px; min-height: 34px; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
  }

</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <div class="logo">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
        <path d="M12 2l7 4v6c0 5-3.2 8.5-7 10-3.8-1.5-7-5-7-10V6l7-4z" stroke="#fff" stroke-width="1.7" stroke-linejoin="round"/>
        <path d="M9 12l2 2 4-4.5" stroke="#fff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <div>
      <div class="brand-title">DARKVEDA <span>LAB</span></div>
      <div class="brand-sub">Infrastructure Control Center</div>
    </div>
  </div>
  <div class="topbar-search">
    <input type="text" id="globalSearch" oninput="gsFetch()" placeholder="Search (/) — peers, shares, backups, logs" autocomplete="off" style="width:100%;">
    <div id="globalSearchResults" style="display:none; position:absolute; top:calc(100% + 8px); left:0; right:0; z-index:200; max-height:420px; overflow:auto; background:#fff; border:1px solid rgba(111,78,204,.25); border-radius:14px; box-shadow:0 12px 30px rgba(95,65,180,.28);"></div>
  </div>
  <div class="topbar-right">
    <div style="display:flex; gap:8px; align-items:center; flex-shrink:0;">
      <button id="themeToggle" class="chip-btn" onclick="toggleTheme()" title="Toggle theme">☾</button>
      <button class="btn primary" onclick="refreshCurrent()">&#10227; Refresh</button>
    </div>
    <span class="clock" id="liveClock">--:--:--</span>
    <span class="meta" id="uptime"></span>
    <a class="chip-btn" href="/password">&#x1F511; Password</a>
    <a class="chip-btn danger" href="/logout">Logout</a>
  </div>
</header>

<nav class="tabs"><div class="tabs-inner">
  <button id="tabBtnWg" class="tab active" onclick="showTab(\'wg\')">&#9889; WireGuard</button>
  <button id="tabBtnMvnbc" class="tab" onclick="showTab(\'mvnbc\')">&#128190; MVNBC</button>
  <button id="tabBtnSmb" class="tab" onclick="showTab(\'smb\')">&#128193; Samba</button>
  <button id="tabBtnIpam" class="tab" onclick="showTab(\'ipam\')">&#127760; IPAM</button>
  <button id="tabBtnBackup" class="tab" onclick="showTab(\'backup\')">&#128230; Backups</button>
  <button id="tabBtnLogViewer" class="tab" onclick="showTab(\'logviewer\')">&#128196; Logs</button>
  <button id="tabBtnSetting" class="tab" onclick="showTab(\'setting\')">&#9881; Setting</button>
  <span class="tab-glider" id="tabGlider"></span>
</div></nav>

<main class="container">

<div id="wgTab">
  <div class="status-bar">
    <div class="status-card" style="--accent: rgba(124,240,160,.7);">
      <div class="sc-head"><span class="label">Tunnel Status</span><span class="sc-ico">&#9889;</span></div>
      <div class="value" id="tunnelStatus">...</div>
      <div class="detail" id="tunnelDetail"></div>
    </div>
    <div class="status-card" style="--accent: rgba(255,176,196,.7);">
      <div class="sc-head"><span class="label">Peer Endpoint</span><span class="sc-ico">&#128279;</span></div>
      <div class="value mono" id="peerEndpoint" style="font-size: 1.02em;">...</div>
      <div class="detail" id="peerHandshake"></div>
    </div>
    <div class="status-card" style="--accent: rgba(255,255,255,.75);">
      <div class="sc-head"><span class="label">Traffic RX / TX</span><span class="sc-ico">&#8645;</span></div>
      <div class="value mono" id="traffic" style="font-size: 1.05em;">...</div>
      <canvas id="trafficSpark"></canvas>
    </div>
    <div class="status-card" style="--accent: rgba(255,214,120,.7);">
      <div class="sc-head"><span class="label">BGP Peers</span><span class="sc-ico">&#127760;</span></div>
      <div class="value" id="bgpStatus">...</div>
      <div class="detail" id="bgpDetail"></div>
    </div>
  </div>

  <div class="section">
    <h2>WireGuard Interfaces</h2>
    <div class="table-scroll"><table>
      <thead><tr><th>Interface</th><th>State</th><th>Listen Port</th><th>IP Addresses</th><th>Peers</th></tr></thead>
      <tbody id="ifaceTable"></tbody>
    </table></div>
  </div>

  <div class="section vendor-block collapsed" id="block-connpeers">
    <div class="vendor-block-head" data-vid="connpeers" onclick="toggleSec(\'connPeers\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Connected Peers</span>
    </div>
    <div class="vendor-block-body"><div class="table-scroll"><table>
      <thead><tr><th>Status</th><th>Endpoint</th><th>Allowed IPs</th><th>Handshake</th><th>Received</th><th>Sent</th><th>History</th></tr></thead>
      <tbody id="peerTable"></tbody>
    </table></div></div>
  </div>

  <div class="section vendor-block collapsed" id="block-wgpeers">
    <div class="vendor-block-head" data-vid="wgpeers" onclick="toggleSec(\'wgPeers\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">WireGuard Peers (add / remove road-warriors)</span>
    </div>
    <div class="vendor-block-body">
    <div class="sub-label">Managed peers</div>
    <div class="table-scroll"><table>
      <thead><tr><th>Name</th><th>IP</th><th>Status</th><th>Traffic</th><th style="text-align:right;">Actions</th></tr></thead>
      <tbody id="wgPeersTable"></tbody>
    </table></div>
    <div class="form-panel" style="margin-top:14px;">
      <div class="form-title">Add peer</div>
      <div class="grid-2" style="gap:12px;">
        <div>
          <label class="flabel">Name</label>
          <input type="text" id="wpName" placeholder="field-laptop">
        </div>
        <div>
          <label class="flabel">IP (10.99.0.0/24)</label>
          <input type="text" id="wpIp" placeholder="auto">
        </div>
        <div>
          <label class="flabel">Endpoint (server public IP:port)</label>
          <input type="text" id="wpEndpoint" placeholder="203.0.113.10:51820">
        </div>
        <div>
          <label class="flabel">DNS (optional)</label>
          <input type="text" id="wpDns" placeholder="">
        </div>
      </div>
      <div style="margin-top:14px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="saveWgPeer()">&#128190; Add peer + show QR</button>
        <button class="btn" onclick="loadWgPeers()">&#8635; Reload</button>
        <span id="wgPeerFormMsg" class="msg-line"></span>
      </div>
    </div>
    <div id="wgPeerResult" style="display:none; margin-top:14px;" class="form-panel">
      <div class="form-title" id="wgPeerResultTitle">Peer added</div>
      <div style="display:grid; gap:12px; justify-items:center;">
        <img id="wgPeerQr" alt="WireGuard QR" style="width:220px; height:220px; background:#fff; border-radius:12px; padding:8px;">
        <textarea id="wgPeerConf" rows="12" readonly style="width:100%;"></textarea>
        <div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:center;">
          <button class="btn" id="wgPeerDlBtn">&#128229; Download .conf</button>
          <button class="btn" onclick="document.getElementById(\'wgPeerResult\').style.display=\'none\'">Close</button>
        </div>
      </div>
    </div>
    </div>
  </div>

  <div class="section vendor-block collapsed" id="block-wgroutes">
    <div class="vendor-block-head" data-vid="wgroutes" onclick="toggleSec(\'wgRoutes\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">WG Routes</span>
    </div>
    <div class="vendor-block-body"><div class="route-list" id="routeList"></div></div>
  </div>

  <div class="section vendor-block collapsed" id="block-wgconf">
    <div class="vendor-block-head" data-vid="wgconf" onclick="toggleSec(\'wgConf\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">WireGuard Configuration (wg0.conf)</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
      <div class="dim mono" style="font-size:.78em;">File: /etc/wireguard/wg0.conf — full edit incl. PrivateKey / PublicKey / AllowedIPs</div>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="loadWGConf()">&#8635; Reload</button>
        <button class="btn" onclick="copyText(document.getElementById(\'wgConfBox\').value,\'wg0.conf\')">&#128203; Copy</button>
        <button class="btn success" onclick="saveWGConf()">&#128190; Save Full Config</button>
        <button class="btn warn" onclick="restartWG()">&#8635; Restart WG</button>
      </div>
    </div>
    <textarea id="wgConfBox" rows="18" spellcheck="false" placeholder="[Interface]&#10;Address = 10.99.0.1/24&#10;ListenPort = 51820&#10;PrivateKey = ...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;AllowedIPs = ..."></textarea>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px; flex-wrap:wrap; gap:8px;">
      <div class="dim" style="font-size:.76em;">Full-file edit. Validated (keys/CIDRs/ports) + backed up before overwrite. Save restarts the tunnel (&lt;10s drop).</div>
      <div id="wgConfMsg" class="msg-line"></div>
    </div>
    <div id="restartConfirm" style="display:none; margin-top:12px; background:rgba(210,153,34,.06); border:1px solid rgba(210,153,34,.35); border-radius:12px; padding:16px;">
      <div style="color:#B45309; font-weight:700; margin-bottom:7px;">&#9888; Restart WireGuard tunnel?</div>
      <div class="dim" style="font-size:.83em; margin-bottom:11px;">Tunnel akan drop sekejap &lt; 10s. BGP session mungkin re-establish. Pastikan ada akses alternatif jika tunnel ni satu-satunya connectivity.</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <input type="text" id="restartConfirmInput" placeholder="Taip \'restart\' untuk confirm" style="width:270px;">
        <button class="btn danger" onclick="doRestartWG()">Confirm Restart</button>
        <button class="btn" onclick="document.getElementById(\'restartConfirm\').style.display=\'none\'">Cancel</button>
      </div>
    </div>
    </div>
  </div>

  <div class="section vendor-block collapsed" id="block-bgpsummary">
    <div class="vendor-block-head" data-vid="bgpsummary" onclick="toggleSec(\'bgpSummary\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">BGP Summary</span>
    </div>
    <div class="vendor-block-body"><div class="route-list" id="bgpList"></div></div>
  </div>

  <div class="section vendor-block collapsed" id="block-bgpctl">
    <div class="vendor-block-head" data-vid="bgpctl" onclick="toggleSec(\'bgpCtl\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">BGP Control (announce / reset)</span>
      <span class="badge stale" id="bgpOriginBadge">…</span>
    </div>
    <div class="vendor-block-body">
    <div class="dim" style="font-size:.83em; margin-bottom:12px;">Locally originated prefix: <span class="mono bright">192.168.10.0/24</span> → neighbour 10.99.0.2 (AS65002).</div>
    <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
      <button class="btn success" id="bgpAnnounceBtn" onclick="bgpAnnounce()">Announce</button>
      <button class="btn warn" onclick="document.getElementById(\'bgpResetConfirm\').style.display=\'block\'">&#8635; Soft reset BGP</button>
      <button class="btn" onclick="loadBgpCtl()">&#8635; Reload</button>
      <span id="bgpCtlMsg" class="msg-line"></span>
    </div>
    <div id="bgpResetConfirm" style="display:none; margin-top:12px; background:rgba(210,153,34,.06); border:1px solid rgba(210,153,34,.35); border-radius:12px; padding:16px;">
      <div style="color:#B45309; font-weight:700; margin-bottom:7px;">&#9888; Send BGP soft reset to 10.99.0.2?</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <input type="text" id="bgpResetInput" placeholder="Taip \'reset\' untuk confirm" style="width:270px;">
        <button class="btn danger" onclick="doBgpReset()">Confirm Reset</button>
        <button class="btn" onclick="document.getElementById(\'bgpResetConfirm\').style.display=\'none\'">Cancel</button>
      </div>
    </div>
    </div>
  </div>

  <div class="section vendor-block collapsed" id="block-bgpcorr" style="display:none;">
    <div class="vendor-block-head" data-vid="bgpcorr" onclick="toggleSec(\'bgpCorr\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">BGP ↔ WG Correlation</span>
      <span class="dim mono" id="bgpCorrHead" style="font-size:.76em;"></span>
    </div>
    <div class="vendor-block-body"><div class="table-scroll"><table>
      <thead><tr><th>Prefix</th><th>Nexthop</th><th>WG peer</th><th>Kernel</th><th>Status</th></tr></thead>
      <tbody id="bgpCorrTable"></tbody>
    </table></div></div>
  </div>
</div>

<div id="sambaTab" style="display:none;">
  <div class="samba-kpi" id="sambaKpi" style="display:none;">
    <div class="kpi-mini"><div class="k">Storage</div><div class="v" id="kpiStorage">—</div><div class="s" id="kpiStorageSub">/DATA/labshare</div><div class="usage-track"><span class="usage-fill" id="kpiStorageFill" style="width:0%"></span></div></div>
    <div class="kpi-mini"><div class="k">Sessions</div><div class="v" id="kpiSessions">—</div><div class="s" id="kpiSessionsSub">active connections</div></div>
  </div>
  <div class="section vendor-block collapsed" id="block-samba">
    <div class="vendor-block-head" data-vid="samba" onclick="toggleSec(\'samba\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Samba / File Sharing</span>
      <span id="smbSvcBadge" class="badge disconnected">...</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <div class="dim mono" style="font-size:.78em;">
        <span class="dim mono" id="smbQuotaSummary" style="font-size:.76em;"></span>
        <span id="smbVer" style="margin-left:6px;"></span> &#183; <span id="smbConfPath" class="dim"></span>
      </div>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="loadSmb()">&#8635; Reload</button>
        <button class="btn success" onclick="toggleShareForm(\'add\')">&#43; Add Share</button>
        <button class="btn primary" onclick="toggleUserForm()">&#43; Add User</button>
        <button class="btn warn" onclick="restartSmb()">&#8635; Restart Samba</button>
      </div>
    </div>

    <div id="smbRestartConfirm" style="display:none; margin-bottom:14px; background:rgba(210,153,34,.06); border:1px solid rgba(210,153,34,.35); border-radius:12px; padding:16px;">
      <div style="color:#B45309; font-weight:700; margin-bottom:7px;">&#9888; Restart Samba services?</div>
      <div class="dim" style="font-size:.83em; margin-bottom:11px;">Active SMB sessions will drop briefly. Config is validated with testparm before restart.</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <input type="text" id="smbRestartConfirmInput" placeholder="Taip \'restart\' untuk confirm" style="width:270px;">
        <button class="btn danger" onclick="doRestartSmb()">Confirm Restart</button>
        <button class="btn" onclick="document.getElementById(\'smbRestartConfirm\').style.display=\'none\'">Cancel</button>
        <span id="smbRestartMsg" class="msg-line"></span>
      </div>
    </div>

    <div id="shareForm" class="form-panel" style="display:none;">
      <div class="form-title" id="shareFormTitle">Add Share</div>
      <div class="grid-2" style="gap:12px;">
        <div>
          <label class="flabel">Share name (auto-lowercased)</label>
          <input type="text" id="sfName" placeholder="lab" autocapitalize="none" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label class="flabel">Folder path (server side)</label>
          <input type="text" id="sfPath" placeholder="/DATA/labshare" autocapitalize="none" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label class="flabel">Valid users (space separated)</label>
          <input type="text" id="sfUsers" placeholder="labuser" autocapitalize="none" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label class="flabel">Comment</label>
          <input type="text" id="sfComment" placeholder="DARKVEDA LAB share">
        </div>
        <div>
          <label class="flabel">Hosts allow (CIDRs, space separated)</label>
          <input type="text" id="sfHosts" placeholder="192.168.10.0/24 172.16.30.0/24 172.16.3.0/24 172.16.20.0/24">
        </div>
        <div>
          <label class="flabel">Writable</label>
          <select id="sfWritable">
            <option value="1">Yes &#8212; read &amp; write</option>
            <option value="0">No &#8212; read only</option>
          </select>
        </div>
        <div>
          <label class="flabel">Folder</label>
          <label style="display:flex; gap:8px; align-items:center; font-size:.85em; cursor:pointer;">
            <input type="checkbox" id="sfMkdir"> Create folder if missing (root:root 2770, access via ACLs)
          </label>
        </div>
      </div>
      <div style="margin-top:14px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="saveShare()">&#128190; Save &amp; Apply</button>
        <button class="btn" onclick="document.getElementById(\'shareForm\').style.display=\'none\'">Cancel</button>
        <span id="shareFormMsg" class="msg-line"></span>
      </div>
    </div>

    <div id="userForm" class="form-panel" style="display:none;">
      <div class="form-title">Add / Update Samba User</div>
      <div class="grid-2" style="gap:12px;">
        <div>
          <label class="flabel">Username</label>
          <input type="text" id="ufUser" placeholder="labuser" autocapitalize="none" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label class="flabel">Password (min 8, letters + numbers)</label>
          <input type="password" id="ufPass" autocomplete="new-password">
        </div>
      </div>
      <div id="ufAccessWrap" style="margin-top:12px;">
        <label class="flabel">Share access for this new user (filesystem ACLs included)</label>
        <div id="ufAccess" class="dim" style="font-size:.83em;">loading shares…</div>
      </div>
      <div style="margin-top:14px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="saveUser(\'add\')">&#128190; Add User</button>
        <button class="btn primary" onclick="saveUser(\'passwd\')">&#128273; Update Password</button>
        <button class="btn" onclick="document.getElementById(\'userForm\').style.display=\'none\'">Cancel</button>
        <span id="userFormMsg" class="msg-line"></span>
      </div>
    </div>

    <div id="accessForm" class="form-panel" style="display:none;">
      <div class="form-title">Share Access per User (Samba + folder ACLs)</div>
      <div style="display:grid; gap:12px;">
        <div>
          <label class="flabel">User</label>
          <select id="afUser"></select>
        </div>
        <div id="afShares"></div>
      </div>
      <div style="margin-top:14px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="saveAccess()">&#128190; Save Access</button>
        <button class="btn" onclick="document.getElementById(\'accessForm\').style.display=\'none\'">Cancel</button>
        <span id="accessFormMsg" class="msg-line"></span>
      </div>
    </div>

    <div class="samba-grid">
      <div class="samba-card">
        <h3>Current Shares</h3>
        <div class="table-scroll"><table>
          <thead><tr><th>Share</th><th>Users</th><th>Allowed</th><th style="text-align:right;">Actions</th></tr></thead>
          <tbody id="smbSharesTable"></tbody>
        </table></div>
      </div>
      <div class="samba-card">
        <h3>Usage</h3>
        <div class="mono dim" id="smbUsageBar" style="font-size:.82em;"></div>
        <div id="smbUsageEmpty" class="empty-card" style="display:none;">No usage data</div>
      </div>
      <div class="samba-card">
        <h3>Samba Users</h3>
        <div class="table-scroll"><table>
          <thead><tr><th>User</th><th>UID</th><th style="text-align:right;">Actions</th></tr></thead>
          <tbody id="smbUsersTable"></tbody>
        </table></div>
      </div>
      <div class="samba-card">
        <h3>Active Connections</h3>
        <div class="route-list" id="smbConnsList"></div>
      </div>
    </div>

    <div id="smbBrowser" style="display:none; margin-top:18px; background:#F3EEFF; border:1px solid rgba(111,78,204,.20); border-radius:16px; padding:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:9px;">
        <div style="color:var(--blue); font-weight:700;">Browse: <span id="sbShare"></span></div>
        <div style="display:flex; gap:7px;">
          <button class="btn" id="sbUpBtn" onclick="sbNav(\'..\')">&#8593; Up</button>
          <button class="btn" onclick="document.getElementById(\'smbBrowser\').style.display=\'none\'">Close</button>
        </div>
      </div>
      <div class="dim mono" id="sbPath" style="font-size:.78em; margin-bottom:8px;"></div>
      <table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr></thead>
      <tbody id="sbFiles"></tbody></table>
    </div>
    </div>
  </div>

    <div class="section vendor-block collapsed" id="block-smbconf" style="margin-top:18px;">
      <div class="vendor-block-head" data-vid="smbconf" onclick="toggleSec(\'smbConf\',event)">
        <span class="chevron">&#9654;</span>
        <span class="vtitle">Samba Configuration (smb.conf)</span>
      </div>
      <div class="vendor-block-body">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
        <div class="dim mono" style="font-size:.78em;">File: /etc/samba/smb.conf — validated with testparm before apply</div>
        <div style="display:flex; gap:7px; flex-wrap:wrap;">
          <button class="btn" onclick="loadSmbConf()">&#8635; Reload</button>
          <button class="btn" onclick="copyText(document.getElementById(\'smbConfBox\').value,\'smb.conf\')">&#128203; Copy</button>
          <button class="btn success" onclick="saveSmbConf()">&#128190; Save &amp; Apply</button>
        </div>
      </div>
      <textarea id="smbConfBox" rows="16" spellcheck="false" placeholder="[global]&#10;   workgroup = WORKGROUP&#10;..."></textarea>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px; flex-wrap:wrap; gap:8px;">
        <div class="dim" style="font-size:.76em;">Saved config is backed up. Invalid configs are rejected &amp; rolled back; smbd restarts on apply.</div>
        <div id="smbConfMsg" class="msg-line"></div>
      </div>
      </div>
    </div>
</div>

<div id="mvnbcTab" style="display:none;">
  <div id="jsErr" style="display:none; padding:12px 15px; background:#3A1215; color:#FFD7DC; border:1px solid #FF6B7A; border-radius:14px; font-size:.8em; margin-bottom:14px; white-space:pre-wrap;"></div>
  <div class="status-bar">
    <div class="status-card" style="--accent: rgba(124,240,160,.7);">
      <div class="sc-head"><span class="label">Devices</span><span class="sc-ico">&#128187;</span></div>
      <div class="value" id="mvTotal">-</div>
      <div class="detail">monitored in devices.conf</div>
    </div>
    <div class="status-card" style="--accent: rgba(124,240,160,.7);">
      <div class="sc-head"><span class="label">Reachable</span><span class="sc-ico">&#10004;</span></div>
      <div class="value up" id="mvOk">-</div>
      <div class="detail">latest backup validated</div>
    </div>
    <div class="status-card" style="--accent: rgba(255,176,196,.7);">
      <div class="sc-head"><span class="label">Failing</span><span class="sc-ico">&#10060;</span></div>
      <div class="value down" id="mvFail">-</div>
      <div class="detail">need attention</div>
    </div>
    <div class="status-card" style="--accent: rgba(255,255,255,.75);">
      <div class="sc-head"><span class="label">Backup Files</span><span class="sc-ico">&#128190;</span></div>
      <div class="value" id="mvFiles">-</div>
      <div class="detail" id="mvFilesSub">-</div>
      <div class="detail">newest: <span id="mvNewest">-</span></div>
    </div>
  </div>
  <div class="mvsubnav" id="mvSubNav">
    <button class="mvsub active" data-s="ov" onclick="mvSection(\'ov\')">&#128202; Overview</button>
    <button class="mvsub" data-s="cmp" onclick="mvSection(\'cmp\')">&#8644; Compare</button>
    <button class="mvsub" data-s="dev" onclick="mvSection(\'dev\')">&#128421; Devices</button>
    <button class="mvsub" data-s="cfg" onclick="mvSection(\'cfg\')">&#128276; Alerts & Schedule</button>
    <button class="mvsub" data-s="tmpl" onclick="mvSection(\'tmpl\')">&#129518; Device Templates</button>
    <button class="mvsub" data-s="sh" onclick="mvSection(\'sh\')">&#128196; MVNBC.sh</button>
  </div>

  
  <div class="section">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <h2 style="margin-bottom:0;">Devices</h2>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="loadMvnbc()">&#8635; Reload</button>
        <button class="btn success" id="mvRunBtn" onclick="mvRun()">&#9654; Run Backup Now</button>
      </div>
    </div>
    <div class="table-scroll"><table>
      <thead><tr><th>Status</th><th>Vendor</th><th>Device</th><th>Account</th><th>Last Backup</th><th>Age</th></tr></thead>
      <tbody id="mvDevTable"></tbody>
    </table></div>
  </div>

    <div class="section">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
      <h2 style="margin-bottom:0;">Backup Files</h2>
      <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <span class="count-chip" id="mvFilesCount">0 files</span>
        <button class="btn xs primary" id="mvDlAllBtn" onclick="mvDlAll()">Download all (.zip)</button>
      </div>
    </div>
    <input type="text" id="mvSearchBox" placeholder="Search vendor / IP / filename..." oninput="mvSearch(this.value)" style="width:100%; max-width:360px; margin-bottom:12px;">
    <div id="mvFilesWrap"></div>
  </div>


  <div class="section vendor-block collapsed" id="block-mvlogs">
    <div class="vendor-block-head" data-vid="mvlogs">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Run logs</span>
      <span id="mvLogsCount" class="dim mono" style="font-size:.72em;"></span>
    </div>
    <div class="vendor-block-body">
    <div class="table-scroll"><table>
      <thead><tr><th style="width:34px;"><input type="checkbox" class="mvchk" onclick="mvToggleLogsAll(this)"></th><th>Name</th><th>Size</th><th>Modified</th><th style="text-align:right;">Action</th></tr></thead>
      <tbody id="mvLogsTable"></tbody>
    </table></div>
    <div class="btn-row" style="display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; align-items:center; border-top:1px solid rgba(111,78,204,.10); background:#FBF8FF;">
      <button class="btn xs" onclick="mvDlLogsZip()">Download log zip</button>
      <span style="flex:1;"></span>
      <button class="btn xs" onclick="mvLogsSelectAll()">Select all</button>
      <button class="btn xs" onclick="mvLogsClear()">Clear</button>
      <button class="btn xs danger" onclick="mvLogsBulkDel()">Delete selected</button>
    </div>
    </div>
  </div>

  <div class="section mvsec" data-mvs="cmp">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <h2 style="margin-bottom:0;">Compare Backups</h2>
      <button class="btn success" onclick="mvCompareRun()">&#8644; Compare</button>
    </div>
    <p class="dim" style="font-size:.78em; margin-bottom:12px;">Diff an older snapshot against a newer one to see exactly what changed on the device config.</p>
    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; margin-bottom:12px;">
      <div>
        <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Older (baseline)</label>
        <select id="mvCmpA" style="width:100%;"></select>
      </div>
      <div>
        <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Newer (target)</label>
        <select id="mvCmpB" style="width:100%;"></select>
      </div>
    </div>
    <div id="mvCmpStat" class="dim mono" style="font-size:.76em; margin-bottom:8px;"></div>
    <pre id="mvCmpOut" style="display:none; max-height:460px; overflow:auto; background:#2A1B5E; color:#D5CAFA; padding:15px 17px; border-radius:14px; font-size:.8em; line-height:1.55; white-space:pre-wrap; word-break:break-word;"></pre>
  </div>

  <div class="section mvsec" data-mvs="dev">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <h2 style="margin-bottom:0;">Device Inventory</h2>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="mvDevForm()">&#65291; Add Device</button>
        <button class="btn" onclick="mvLoadDevices()">&#8635; Reload</button>
      </div>
    </div>
    <div class="table-scroll"><table>
      <thead><tr><th>Vendor</th><th>IP Address</th><th>Account</th><th>Password</th><th style="text-align:right;">Action</th></tr></thead>
      <tbody id="mvInvTable"></tbody>
    </table></div>
    <div id="mvDevEdit" style="display:none; margin-top:16px; padding:16px; background:rgba(255,255,255,.55); border:1px solid rgba(115,86,214,.25); border-radius:16px;">
      <div class="sub-label" id="mvDevEditTitle" style="margin-bottom:12px;">Add Device</div>
      <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:11px;">
        <div>
          <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Vendor</label>
          <select id="mvDevVendor" style="width:100%;"></select>
        </div>
        <div>
          <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">IP Address</label>
          <input type="text" id="mvDevIp" placeholder="192.168.1.10" style="width:100%;">
        </div>
        <div>
          <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Username</label>
          <input type="text" id="mvDevUser" placeholder="admin" style="width:100%;">
        </div>
        <div>
          <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Password</label>
          <input type="password" id="mvDevPass" placeholder="leave blank to keep current" style="width:100%;">
        </div>
      </div>
      <div style="display:flex; gap:8px; margin-top:14px; flex-wrap:wrap;">
        <button class="btn success" id="mvDevSaveBtn" onclick="mvDevSave()">&#128190; Save Device</button>
        <button class="btn" onclick="mvDevFormClose()">Cancel</button>
      </div>
    </div>
  </div>
  <div class="section vendor-block collapsed mvsec" data-mvs="cfg" id="block-mvcfgpolicy">
    <div class="vendor-block-head" data-vid="mvcfgpolicy">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Alerts</span>
    </div>
    <div class="vendor-block-body">
    <p class="dim" style="font-size:.78em; margin-bottom:14px;">Email and Telegram notifications for backup runs.</p>
    <div style="padding:15px; background:rgba(255,255,255,.55); border:1px solid rgba(115,86,214,.25); border-radius:16px;">
      <div class="sub-label" style="margin-bottom:12px;">When to notify</div>
      <div class="mvnotify-grid">
        <label class="mvnotify" id="mvNotifyCard-failure">
          <span><input type="radio" name="mvNotifyOn" value="failure" id="mvNotifyFailure"><strong>On failure</strong><small>Alert only when one or more backups fail</small></span>
        </label>
        <label class="mvnotify" id="mvNotifyCard-always">
          <span><input type="radio" name="mvNotifyOn" value="always" id="mvNotifyAlways"><strong>Every run</strong><small>Send a summary after each backup run</small></span>
        </label>
        <label class="mvnotify" id="mvNotifyCard-never">
          <span><input type="radio" name="mvNotifyOn" value="never" id="mvNotifyNever"><strong>Never</strong><small>Disable automatic alerts</small></span>
        </label>
      </div>
      <select id="mvAltWhen" style="display:none;"><option value="failure">failure</option><option value="always">always</option><option value="never">never</option></select>
    </div>
    </div>
  </div>
  <div class="section vendor-block collapsed mvsec" data-mvs="cfg" id="block-mvcfgalerts">
    <div class="vendor-block-head" data-vid="mvcfgalerts">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Alerts &amp; Notifications</span>
      <span class="badge disconnected" id="mvAltState">-</span>
    </div>
    <div class="vendor-block-body">
    <p class="dim" style="font-size:.78em; margin-bottom:14px;">Email and Telegram notifications for backup runs. Notifiers fire automatically after every backup run.</p>

    <div style="padding:15px; background:rgba(255,255,255,.55); border:1px solid rgba(115,86,214,.25); border-radius:16px; margin-bottom:16px;">
      <div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
        <span class="sub-label" style="margin:0;">&#9993; Email (SMTP)</span>
        <label style="display:flex; gap:8px; align-items:center; font-size:.8em; margin-left:auto; cursor:pointer;">
          <input type="checkbox" id="mvEmOn" class="mvtoggle"><span class="dim">Enabled</span>
        </label>
      </div>
      <div class="mvfield" style="display:grid; gap:9px;">
        <div><label class="dim">SMTP host</label><input type="text" id="mvEmHost" placeholder="smtp.gmail.com" style="width:100%;"></div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:9px;">
          <div><label class="dim">Port</label><input type="text" id="mvEmPort" placeholder="587" style="width:100%;"></div>
          <div><label class="dim">Encryption</label>
            <select id="mvEmSec" style="width:100%;"><option value="tls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option><option value="none">None</option></select>
          </div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:9px;">
          <div><label class="dim">Username</label><input type="text" id="mvEmUser" placeholder="you@gmail.com" style="width:100%;"></div>
          <div><label class="dim">Password <span class="dim" style="text-transform:none; letter-spacing:0;">(saved — leave blank to keep)</span></label><input type="password" id="mvEmPass" placeholder="••••••" style="width:100%;"></div>
        </div>
        <div><label class="dim">From address</label><input type="text" id="mvEmFrom" placeholder="alerts@example.com" style="width:100%;"></div>
        <div><label class="dim">Recipients <span class="dim" style="text-transform:none; letter-spacing:0;">(comma separated)</span></label><input type="text" id="mvEmTo" placeholder="you@example.com" style="width:100%;"></div>
      </div>
      <div style="margin-top:13px; display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="mvAlertsSave()">&#128190; Save settings</button>
        <button class="btn" onclick="mvAlertTest(\'email\')">&#9889; Send test email</button>
      </div>
    </div>

    <div class="dim mono" id="mvAltHint" style="font-size:.76em; margin-top:11px;"></div>
    </div>
  </div>

  <div class="section vendor-block collapsed mvsec" data-mvs="cfg" id="block-mvtelegram">
    <div class="vendor-block-head" data-vid="mvtelegram">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">&#9993; Telegram</span>
    </div>
    <div class="vendor-block-body">
    <div style="padding:15px; background:rgba(255,255,255,.55); border:1px solid rgba(115,86,214,.25); border-radius:16px;">
      <div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
        <span class="sub-label" style="margin:0;">Telegram Bot</span>
        <label style="display:flex; gap:8px; align-items:center; font-size:.8em; margin-left:auto; cursor:pointer;">
          <input type="checkbox" id="mvTgOn" class="mvtoggle"><span class="dim">Enabled</span>
        </label>
      </div>
      <div class="mvfield" style="display:grid; gap:9px;">
        <div><label class="dim">Bot token <span class="dim" style="text-transform:none; letter-spacing:0;">(saved — leave blank to keep)</span></label><input type="password" id="mvTgToken" placeholder="••••••" style="width:100%;"></div>
        <div><label class="dim">Chat ID</label><input type="text" id="mvTgChat" placeholder="123456789" style="width:100%;"></div>
      </div>
      <div style="margin-top:13px; display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn success" onclick="mvAlertsSave()">&#128190; Save settings</button>
        <button class="btn" onclick="mvAlertTest(\'telegram\')">&#9889; Send test message</button>
      </div>
      <div class="mvhint">Create a bot with <b>@BotFather</b> to get a token. To find your chat ID, message the bot, then check
        <span class="mono">https://api.telegram.org/bot&lt;token&gt;/getUpdates</span>. Credentials are stored in
        <span class="mono">config/settings.json</span> (chmod 600).</div>
    </div>
    </div>
  </div>

  <div class="section vendor-block collapsed mvsec" data-mvs="cfg" id="block-mvcfgschedule">
    <div class="vendor-block-head" data-vid="mvcfgschedule">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Backup Schedule</span>
      <span class="badge disconnected" id="mvSchState">-</span>
    </div>
    <div class="vendor-block-body">
    <p class="dim" style="font-size:.78em; margin-bottom:14px;">Auto-run MVNBC.sh via root crontab. Manual <b>Run Backup Now</b> stays available on Overview.</p>
    <div id="mvSchCurrent" class="mono" style="display:none; padding:12px 15px; background:#2A1B5E; color:#D5CAFA; border-radius:14px; font-size:.78em; margin-bottom:10px; white-space:pre-wrap;"></div>
    <div id="mvSchTz" class="mono dim" style="font-size:.76em; margin-bottom:14px;">timezone: Asia/Kuala_Lumpur (MYT)</div>
    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-bottom:13px;">
      <label class="mvradio"><input type="radio" name="mvSch" value="0 2 * * *" checked> <span><strong>Daily</strong><small>Every day 02:00</small></span></label>
      <label class="mvradio"><input type="radio" name="mvSch" value="0 2 * * 0"> <span><strong>Weekly</strong><small>Sundays 02:00</small></span></label>
      <label class="mvradio"><input type="radio" name="mvSch" value="0 * * * *"> <span><strong>Hourly</strong><small>Every hour :00</small></span></label>
      <label class="mvradio"><input type="radio" name="mvSch" value="__custom__"> <span><strong>Custom</strong><small>Your cron line</small></span></label>
    </div>
    <div id="mvSchCustomWrap" style="display:none; max-width:340px; margin-bottom:13px;">
      <label class="dim" style="font-size:.72em; letter-spacing:.6px; text-transform:uppercase;">Cron expression (5 fields)</label>
      <input type="text" id="mvSchCustom" placeholder="*/30 * * * *" style="width:100%;">
      <div class="dim" style="font-size:.72em; margin-top:5px;">minute hour day month weekday</div>
    </div>
    <div style="display:flex; gap:8px; flex-wrap:wrap;">
      <button class="btn success" onclick="mvScheduleSave()">&#128190; Save Schedule</button>
      <button class="btn danger" onclick="mvScheduleRemove()">&#128465; Remove Schedule</button>
    </div>
    <div class="dim mono" id="mvSchHint" style="font-size:.74em; margin-top:11px;"></div>
    </div>
  </div>
  <div class="section vendor-block collapsed mvsec" data-mvs="cfg" id="block-mvretention">
    <div class="vendor-block-head" data-vid="mvretention">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Retention &amp; Prune</span>
      <span class="badge stale" id="mvRetState">-</span>
    </div>
    <div class="vendor-block-body">
    <p class="dim" style="font-size:.78em; margin-bottom:14px;">Keep last N per vendor + run logs. Auto-prune deletes older than max age after each run. Audit/delete logs are never touched.</p>
    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:11px; margin-bottom:13px;">
      <div><label class="dim" style="font-size:.7em;">Keep backups (per vendor)</label><input type="number" id="mvRetBackups" min="1" max="1000" value="50" style="width:100%;"></div>
      <div><label class="dim" style="font-size:.7em;">Keep run logs</label><input type="number" id="mvRetLogs" min="1" max="1000" value="30" style="width:100%;"></div>
      <div><label class="dim" style="font-size:.7em;">Max age (days)</label><input type="number" id="mvRetAge" min="1" max="365" value="30" style="width:100%;"></div>
    </div>
    <label style="display:flex; gap:8px; align-items:center; font-size:.82em; margin-bottom:13px;">
      <input type="checkbox" id="mvRetAuto"> Auto-prune older than max age after each run
    </label>
    <div class="dim mono" id="mvRetCounts" style="font-size:.76em; margin-bottom:11px;">-</div>
    <div id="mvRetPreview" class="mono" style="display:none; padding:12px 15px; background:#2A1B5E; color:#D5CAFA; border-radius:14px; font-size:.76em; margin-bottom:13px; white-space:pre-wrap; max-height:200px; overflow:auto;"></div>
    <div style="display:flex; gap:8px; flex-wrap:wrap;">
      <button class="btn success" onclick="mvRetentionSave()">&#128190; Save Retention</button>
      <button class="btn" onclick="mvRetentionPreview()">Preview</button>
      <button class="btn danger" onclick="mvRetentionPrune()">Prune now</button>
    </div>
    <div class="dim mono" id="mvRetHint" style="font-size:.74em; margin-top:11px;"></div>
    </div>
  </div>
  <div class="section vendor-block collapsed mvsec" data-mvs="tmpl" id="block-mvtmpl">
    <div class="vendor-block-head" data-vid="mvtmpl">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Device Templates</span>
      <span class="dim mono" style="font-size:.72em;" id="mvTmplCount"></span>
    </div>
    <div class="vendor-block-body">
  <div class="section" id="mvTmplSection" style="box-shadow:none;border:none;margin:0;padding:0;background:transparent;">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <h2 style="display:none;">Device Templates <span class="dim" style="font-size:.68em; font-weight:400;">templates/*.exp</span></h2>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="mvTmplLoad()">&#8635; Reload</button>
        <button class="btn success" onclick="mvTmplNew()">+ New Template</button>
      </div>
    </div>
    <p class="dim" style="font-size:.78em; margin-bottom:12px;">Builtin vendors are <b>locked</b>. New custom templates (e.g. <b>huawei</b>) auto-appear in the vendor list + MVNBC.sh case branch. Custom vendors validate by non-empty file.</p>
    <div class="table-scroll"><table>
      <thead><tr><th>Template</th><th>Vendor</th><th>Size</th><th>Modified</th><th style="text-align:right;">Action</th></tr></thead>
      <tbody id="mvTmplTable"></tbody>
    </table></div>
    <div id="mvTmplEdit" style="display:none; margin-top:16px; padding:16px; background:rgba(255,255,255,.55); border:1px solid rgba(115,86,214,.25); border-radius:16px;">
      <div class="sub-label" id="mvTmplTitle" style="margin-bottom:12px;">New Template</div>
      <div style="display:grid; grid-template-columns:200px 1fr; gap:11px; margin-bottom:11px;">
        <div><label class="dim" style="font-size:.72em; text-transform:uppercase;">Vendor slug</label><input type="text" id="mvTmplVendor" placeholder="huawei" style="width:100%;"></div>
        <div><label class="dim" style="font-size:.72em; text-transform:uppercase;">From existing (prefill)</label><select id="mvTmplFrom" style="width:100%;"></select></div>
      </div>
      <label class="dim" style="font-size:.72em; text-transform:uppercase;">Expect script (*.exp)</label>
      <textarea id="mvTmplBody" rows="16" spellcheck="false" placeholder="#!/usr/bin/expect -f&#10;set ip [lindex $argv 0] ..." style="width:100%; font-family:ui-monospace,monospace; font-size:.8em;"></textarea>
      <div style="display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; align-items:center;">
        <button class="btn success" onclick="mvTmplSave()">&#128190; Save Template</button>
        <button class="btn" onclick="document.getElementById('mvTmplEdit').style.display='none'">Cancel</button>
        <span id="mvTmplMsg" class="msg-line"></span>
      </div>
    </div>
  </div>

    </div>
  </div>
  <div class="section vendor-block collapsed mvsec" data-mvs="sh" id="block-mvscript">
    <div class="vendor-block-head" data-vid="mvscript">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">MVNBC.sh</span>
      <span class="dim mono" style="font-size:.72em;">manual view / edit / save</span>
    </div>
    <div class="vendor-block-body">
  <div class="section" id="mvScriptSection" style="box-shadow:none;border:none;margin:0;padding:0;background:transparent;">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <h2 style="display:none;">MVNBC.sh <span class="dim" style="font-size:.68em; font-weight:400;">manual view / edit / save</span></h2>
      <div style="display:flex; gap:7px; flex-wrap:wrap;">
        <button class="btn" onclick="mvScriptLoad()">&#8635; Load</button>
        <button class="btn success" onclick="mvScriptSave()">&#128190; Save</button>
      </div>
    </div>
    <p class="dim" style="font-size:.78em; margin-bottom:12px;">Full runner script. A <b>.bak.&lt;epoch&gt;</b> copy is kept on every save. Must start with <span class="mono">#!/bin/bash</span> — syntax-checked on template sync.</p>
    <textarea id="mvScriptBody" rows="20" spellcheck="false" style="width:100%; font-family:ui-monospace,monospace; font-size:.8em;" placeholder="click Load to fetch MVNBC.sh …"></textarea>
    <div style="display:flex; gap:8px; margin-top:10px; align-items:center; flex-wrap:wrap;">
      <span id="mvScriptMsg" class="msg-line"></span>
    </div>
    </div>
    </div>
  </div>
  <div class="section" id="mvViewer" style="display:none;">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:11px;">
      <div class="sub-label" style="margin:0;">Viewer: <span id="mvViewName" class="bright mono" style="text-transform:none; letter-spacing:0;"></span></div>
      <div style="display:flex; gap:7px;">
        <a class="btn" id="mvViewDl" href="#" download>&#8681; Download</a>
        <button class="btn" onclick="document.getElementById(\'mvViewer\').style.display=\'none\'">Close</button>
      </div>
    </div>
    <pre id="mvViewBody" style="max-height:440px; overflow:auto; background:#2A1B5E; color:#D5CAFA; padding:15px 17px; border-radius:14px; font-size:.8em; line-height:1.55; white-space:pre-wrap; word-break:break-word;"></pre>
  </div>
<div class="section vendor-block collapsed" id="block-mvjob">
    <div class="vendor-block-head" data-vid="mvjob">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Backup Job</span>
      <span id="mvJobBadge2" class="dim mono" style="font-size:.72em;"></span>
    </div>
    <div class="vendor-block-body">
  <div style="padding:4px 2px 2px;">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
      <h2 style="display:none;">Backup Job</h2>
      <div style="display:flex; gap:9px; flex-wrap:wrap; align-items:center;">
        <span id="mvJobBadge" class="badge disconnected">-</span>
        <span id="mvRunStat" class="dim mono" style="font-size:.76em;"></span>
      </div>
    </div>
    <div class="dim mono" id="mvCron" style="font-size:.76em; margin-bottom:4px;">-</div>
    <div class="dim mono" id="mvNextRun" style="font-size:.76em; margin-bottom:10px; color:#6F4ECC; font-weight:600;">-</div>
    <div id="mvRunFeed" class="mono" style="display:none; background:#2A1B5E; color:#D5CAFA; padding:12px 15px; border-radius:14px; font-size:.78em; max-height:220px; overflow:auto; white-space:pre-wrap; line-height:1.65; margin-bottom:16px;"></div>
  </div>
    </div>
  </div>
</div>


<div id="ipamTab" style="display:none;">
  <div class="ipam-kpi" id="ipamKpi" style="display:none;">
    <div class="kpi-mini"><div class="k">Subnets</div><div class="v" id="ipamKSub">—</div><div class="s">tracked prefixes</div></div>
    <div class="kpi-mini"><div class="k">IPs Used</div><div class="v" id="ipamKUsed">—</div><div class="s" id="ipamKUsedSub">assigned</div></div>
    <div class="kpi-mini"><div class="k">VLANs</div><div class="v" id="ipamKVlan">—</div><div class="s">defined</div></div>
    <div class="kpi-mini"><div class="k">Devices</div><div class="v" id="ipamKDev">—</div><div class="s">in inventory</div></div>
    <div class="kpi-mini"><div class="k">Conflicts</div><div class="v" id="ipamKConf">—</div><div class="s">unresolved</div></div>
  </div>
  <div class="section vendor-block collapsed" id="block-ipamsubs">
    <div class="vendor-block-head" data-vid="ipamsubs" onclick="toggleSec(\'ipamsubs\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">IPAM · Subnets & IPs</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; gap:7px; flex-wrap:wrap; margin-bottom:12px;">
      <button class="btn" onclick="loadIpam()">&#8635; Reload</button>
      <button class="btn success" onclick="ipamOpenAdd()">+ Add Subnet</button>
        <a class="btn" id="ipamFullBtn" href="http://127.0.0.1:8091/?page=dashboard" target="_blank" rel="noopener" title="Full IPAM (VLANs, devices, discovery, topology)">&#8599; Full IPAM</a>
    </div>
    <div class="dim" style="font-size:.78em; margin-bottom:12px;">Click a row to expand IP list. Full manager (VLANs · devices · discovery · topology · docs) via <b>Full IPAM</b> → same data, port 8091.</div>
    <div class="table-scroll"><table>
      <thead><tr><th>Subnet</th><th>Site / VLAN</th><th>Gateway</th><th>Usage</th><th style="text-align:right;">Open</th></tr></thead>
      <tbody id="ipamSubTable"><tr><td colspan="4" class="dim">loading…</td></tr></tbody>
    </table></div>
    </div>
  </div>
  <div class="section" id="ipamDetailSec" style="display:none;">
    <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:12px; flex-wrap:wrap;">
      <h2 style="margin:0;" id="ipamDetailTitle">Subnet IPs</h2>
      <button class="btn" onclick="document.getElementById('ipamDetailSec').style.display='none'">Close</button>
    </div>
    <div class="table-scroll"><table>
      <thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th><th>Last seen</th></tr></thead>
      <tbody id="ipamIpTable"></tbody>
    </table></div>
  </div>
</div>

<div id="backupTab" style="display:none;">
  <div class="section vendor-block collapsed" id="block-netbackup">
    <div class="vendor-block-head" data-vid="netbackup" onclick="toggleSec(\'netBackup\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Configuration Backups</span>
    </div>
    <div class="vendor-block-body">
    <div class="dim" style="font-size:.83em; margin-bottom:12px;">Snapshots: interfaces, wg0.conf, frr.conf, iptables v4/v6, smb.conf, ns10.service. Restore re-applies services (network interfaces file needs reboot).</div>
    <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:12px;">
      <button class="btn success" onclick="createBackup()">&#128190; Create snapshot now</button>
      <button class="btn" onclick="loadBackups()">&#8635; Reload</button>
      <span id="backupMsg" class="msg-line"></span>
    </div>
    <div class="table-scroll"><table>
      <thead><tr><th>Name</th><th>Size</th><th>Date</th><th style="text-align:right;">Actions</th></tr></thead>
      <tbody id="backupTable"></tbody>
    </table></div>
    <div id="restoreConfirm" style="display:none; margin-top:12px; background:rgba(220,38,38,.06); border:1px solid rgba(220,38,38,.35); border-radius:12px; padding:16px;">
      <div style="color:#DC2626; font-weight:700; margin-bottom:7px;">&#9888; Restore <span id="restoreName" class="mono"></span>?</div>
      <div class="dim" style="font-size:.83em; margin-bottom:11px;">Overwrites live configs &amp; restarts wg/frr/smbd/ns10. A pre-restore snapshot is taken first.</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <input type="text" id="restoreConfirmInput" placeholder="Taip \'restore\' untuk confirm" style="width:270px;">
        <button class="btn danger" onclick="doRestore()">Confirm Restore</button>
        <button class="btn" onclick="document.getElementById(\'restoreConfirm\').style.display=\'none\'">Cancel</button>
      </div>
    </div>
    <div class="route-list" id="restoreSteps" style="margin-top:10px;"></div>
    </div>
  </div>
</div>

<div id="logviewerTab" style="display:none;">
  <div class="section vendor-block collapsed" id="block-logviewer">
    <div class="vendor-block-head" data-vid="logviewer" onclick="toggleSec(\'logviewer\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Log Viewer</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; margin-bottom:12px;">
      <div>
        <label class="flabel">Source</label>
        <select id="logSource" style="min-width:230px;"></select>
      </div>
      <div>
        <label class="flabel">Lines</label>
        <input type="text" id="logLines" value="100" style="width:90px;" inputmode="numeric">
      </div>
      <div style="display:flex; gap:8px; align-items:center; padding-bottom:10px;">
        <button class="btn" onclick="loadLogs()">&#8635; Reload</button>
        <label style="display:flex; gap:6px; align-items:center; font-size:.8em; cursor:pointer;">
          <input type="checkbox" id="logAuto" onchange="logAutoToggle()"> Auto (5s)
        </label>
      </div>
      <span id="logMsg" class="msg-line"></span>
    </div>
    <pre id="logOutput" class="log-output">Expand + Reload to view logs.</pre>
    </div>
  </div>
</div>

<div class="ipam-modal" id="ipamAddModal">
  <div class="ipam-dialog">
    <h3 style="margin:0 0 14px;">Add Subnet</h3>
    <label>CIDR *</label><input type="text" id="ipamNewCidr" placeholder="172.16.40.0/24">
    <label>Name</label><input type="text" id="ipamNewName" placeholder="Branch LAN">
    <label>Gateway</label><input type="text" id="ipamNewGw" placeholder="172.16.40.1">
    <label>Description</label><input type="text" id="ipamNewDesc" placeholder="optional">
    <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:6px;">
      <button class="btn" onclick="document.getElementById('ipamAddModal').classList.remove('open')">Cancel</button>
      <button class="btn success" onclick="ipamCreate()">Create</button>
    </div>
    <div class="msg-line" id="ipamAddMsg" style="margin-top:8px;"></div>
  </div>
</div>

<div id="settingTab" style="display:none;">
  <div class="section vendor-block collapsed" id="block-settingvis">
    <div class="vendor-block-head" data-vid="settingvis" onclick="toggleSec(\'settingvis\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Setting · Card Visibility</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; gap:7px; flex-wrap:wrap; margin-bottom:14px;">
      <button class="btn" onclick="portalTabsShowAll()">Show all</button>
      <button class="btn" onclick="portalTabsReset()">Reset</button>
    </div>
    <div class="dim" style="font-size:.80em; margin-bottom:14px;">Toggle to hide / unhide portal cards. Example: turn <b>WireGuard</b> off to hide it, turn it back on to use it again. Applies to all cards. Setting itself always stays visible.</div>
    <div id="settingList"></div>
    <div id="settingMsg" class="msg-line dim" style="margin-top:6px;"></div>
    <div class="mvhint">Visibility is saved on the server (shared for all logins) and cached in this browser. Hidden cards disappear from the top bar instantly. If your current card gets hidden, you are moved to the first visible one.</div>
    </div>
  </div>
  <div class="section vendor-block collapsed" id="block-services">
    <div class="vendor-block-head" data-vid="services" onclick="toggleSec(\'services\',event)">
      <span class="chevron">&#9654;</span>
      <span class="vtitle">Services Control</span>
    </div>
    <div class="vendor-block-body">
    <div style="display:flex; gap:7px; flex-wrap:wrap; margin-bottom:14px;">
      <button class="btn" onclick="loadServices()">&#8635; Reload</button>
    </div>
    <div class="dim" style="font-size:.80em; margin-bottom:14px;">Restart stuck services from here. <b>networking</b> is status-only — restarting it would drop this session. Only Darkveda Lab services are listed.</div>
    <div class="sub-label">Systemd units</div>
    <table>
      <thead><tr><th>Service</th><th>State</th><th style="text-align:right;">Actions</th></tr></thead>
      <tbody id="svcUnitTable"></tbody>
    </table>
    <div class="sub-label" style="margin-top:16px;">Docker containers</div>
    <table>
      <thead><tr><th>Container</th><th>Status</th><th style="text-align:right;">Actions</th></tr></thead>
      <tbody id="svcDockerTable"></tbody>
    </table>
    </div>
  </div>
</div>

<div class="footer">

  Last updated: <span id="lastUpdate">--</span> &#183; WG auto-refresh 10s &#183; Samba: manual reload only &#183; keys: <span class="kbd">/</span> search <span class="kbd">1</span> WG <span class="kbd">2</span> MVNBC <span class="kbd">3</span> Samba <span class="kbd">4</span> IPAM <span class="kbd">5</span> Backups <span class="kbd">6</span> Logs <span class="kbd">7</span> Setting <span class="kbd">R</span> refresh
</div>

</main>

<div class="toast-wrap" id="toastWrap"></div>

<script>
const CSRF = "{{ csrf }}";
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);try{localStorage.setItem('darkveda-theme',t)}catch(e){}var b=document.getElementById('themeToggle');if(b)b.textContent=t==='dark'?'☀':'☾';}
function toggleTheme(){var cur=document.documentElement.getAttribute('data-theme')||'light';applyTheme(cur==='dark'?'light':'dark');}
(function(){try{var t=document.documentElement.getAttribute('data-theme')||localStorage.getItem('darkveda-theme')||'light';applyTheme(t)}catch(e){}})();
let CURRENT_VIEW = \'wg\';

/* ---------- self-diagnostics: surface JS errors on-screen, not just console ---------- */
window.addEventListener(\'error\', e => {
  try {
    const b = document.getElementById(\'jsErr\');
    if (b && CURRENT_VIEW === \'mvnbc\') {
      b.style.display = \'block\';
      b.textContent = \'Page error: \' + (e.message || e.error || \'unknown\') + \' — screenshot this for support.\';
    }
  } catch (_) {}
});
function mvShowErr(t) {
  const b = document.getElementById(\'jsErr\');
  if (b) { b.style.display = \'block\'; b.textContent = t; }
}
/* ---------- toast ---------- */
let GS_TIMER=null, GS_IDX=-1, GS_DATA=[];
function gsFetch(){
  const box=document.getElementById('globalSearch'); if(!box) return;
  const q=box.value.trim();
  const dd=document.getElementById('globalSearchResults');
  if(q.length<2){ dd.style.display='none'; dd.innerHTML=''; GS_DATA=[]; return; }
  clearTimeout(GS_TIMER);
  GS_TIMER=setTimeout(async ()=>{
    try{
      const res=await fetch('/api/search?q='+encodeURIComponent(q));
      if(res.status===401){window.location='/login';return;}
      const d=await res.json();
      GS_DATA=d.results||[]; GS_IDX=-1;
      if(!GS_DATA.length){ dd.innerHTML='<div class="gs-kind">No matches</div>'; dd.style.display='block'; return; }
      const groups={}; for(const r of GS_DATA){ (groups[r.kind]=groups[r.kind]||[]).push(r); }
      const names={wg_peer:'WireGuard peers',wg_iface:'Interfaces',bgp:'BGP',route:'Routes',samba_share:'Samba shares',mvnbc_file:'Backup files',log:'Run logs'};
      let h='';
      for(const k of Object.keys(groups)){ h+='<div class="gs-kind">'+(names[k]||k)+'</div>'; groups[k].forEach((r,i)=>{ h+='<div class="gs-item" data-gi="'+GS_DATA.indexOf(r)+'"><div class="gs-label">'+esc(r.label)+'</div><div class="gs-sub">'+esc(r.sub||'')+'</div></div>'; }); }
      dd.innerHTML=h; dd.style.display='block';
      dd.querySelectorAll('.gs-item').forEach(el=>{ el.addEventListener('click',()=>gsGo(parseInt(el.getAttribute('data-gi')))); });
    }catch(e){}
  },300);
}
function gsGo(i){
  const r=GS_DATA[i]; if(!r) return;
  const dd=document.getElementById('globalSearchResults'); dd.style.display='none';
  const a=r.action||'';
  if(a.startsWith('tab:')){ showTab(a.slice(4)); return; }
  if(a.startsWith('mvnbc:log:')){ showTab('mvnbc'); mvSection('ov'); setTimeout(()=>{document.getElementById('mvLogsTable')?.scrollIntoView({behavior:'smooth'});},300); return; }
  if(a.startsWith('mvnbc:')){ const p=a.slice(6); showTab('mvnbc'); mvSection('ov'); window.mvFilesQ=p.split('/')[0]; const sb=document.getElementById('mvSearchBox'); if(sb){sb.value=window.mvFilesQ;} loadMvnbcFiles(); return; }
}
document.addEventListener('keydown',e=>{
  const tag=(e.target.tagName||'').toUpperCase();
  if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(tag)){ e.preventDefault(); const b=document.getElementById('globalSearch'); if(b){b.focus();} return; }
  const dd=document.getElementById('globalSearchResults');
  if(dd&&dd.style.display!=='none'){
    if(e.key==='Escape'){ dd.style.display='none'; return; }
    if(e.key==='ArrowDown'||e.key==='ArrowUp'){ e.preventDefault(); const items=[...dd.querySelectorAll('.gs-item')]; if(!items.length)return; GS_IDX=e.key==='ArrowDown'?(GS_IDX+1)%items.length:(GS_IDX-1+items.length)%items.length; items.forEach((el,j)=>el.classList.toggle('active',j===GS_IDX)); items[GS_IDX].scrollIntoView({block:'nearest'}); return; }
    if(e.key==='Enter'&&GS_IDX>=0){ e.preventDefault(); gsGo(GS_IDX); return; }
  }
});
document.addEventListener('click',e=>{ const dd=document.getElementById('globalSearchResults'); const box=document.getElementById('globalSearch'); if(dd&&box&&!dd.contains(e.target)&&e.target!==box){ dd.style.display='none'; } });

function toast(msg, type) {
  const w = document.getElementById(\'toastWrap\');
  const t = document.createElement(\'div\');
  t.className = \'toast \' + (type || \'info\');
  t.textContent = msg;
  w.appendChild(t);
  setTimeout(() => t.classList.add(\'show\'), 15);
  setTimeout(() => { t.classList.remove(\'show\'); setTimeout(() => t.remove(), 350); }, 3600);
}
function copyText(txt, label) {
  if (!txt) { toast(\'Nothing to copy\', \'warn\'); return; }
  navigator.clipboard.writeText(txt).then(
    () => toast((label || \'Value\') + \' copied\', \'ok\'),
    () => toast(\'Copy failed\', \'err\')
  );
}

/* ---------- clock ---------- */
function tick() {
  const d = new Date(), p = n => String(n).padStart(2, \'0\');
  const el = document.getElementById(\'liveClock\');
  if (el) el.textContent = p(d.getHours()) + \':\' + p(d.getMinutes()) + \':\' + p(d.getSeconds());
}
setInterval(tick, 1000); tick();
// WG-only auto-refresh every 10s (data only; config box is manual-reload to avoid clobbering edits)
setInterval(() => { if (CURRENT_VIEW === 'wg') { loadData(); } }, 10000);

/* ---------- tabs ---------- */
function updateGlider() {
  const g = document.getElementById(\'tabGlider\');
  const act = document.querySelector(\'.tab.active\');
  if (act && g) { g.style.left = act.offsetLeft + \'px\'; g.style.width = act.offsetWidth + \'px\'; g.style.opacity = \'1\'; }
}
/* ---------- Setting: card visibility (hide/unhide) ---------- */
const PORTAL_TABS_META = [
  {id: \'wg\', name: \'WireGuard\', icon: \'\\u26A1\', desc: \'Tunnel status, peers, routes & wg0.conf\'},
  {id: \'mvnbc\', name: \'MVNBC\', icon: \'\\uD83D\\uDCBE\', desc: \'Multi-vendor config backups, devices & schedules\'},
  {id: \'smb\', name: \'Samba\', icon: \'\\uD83D\\uDCC1\', desc: \'File shares, users & active sessions\'},
  {id: \'ipam\', name: \'IPAM\', icon: \'\\uD83C\\uDF10\', desc: \'Subnets, IPs, VLANs & devices\'},
  {id: \'backup\', name: \'Configuration Backups\', icon: \'\\uD83D\\uDCE6\', desc: \'Snapshots, download & restore of network configs\'},
  {id: \'logviewer\', name: \'Log Viewer\', icon: \'\\uD83D\\uDCC4\', desc: \'Journal logs for lab services & containers\'},
];
let PORTAL_TABS = {wg: true, mvnbc: true, smb: true, ipam: true, backup: true, logviewer: true};
function portalTabsReadLocal() {
  try {
    const raw = localStorage.getItem(\'darkveda-tabs\');
    if (!raw) return null;
    const got = JSON.parse(raw);
    if (got && typeof got === \'object\') return got;
  } catch (e) {}
  return null;
}
function portalTabsStoreLocal() {
  try { localStorage.setItem(\'darkveda-tabs\', JSON.stringify(PORTAL_TABS)); } catch (e) {}
}
function portalTabsFirstVisible() {
  for (const m of PORTAL_TABS_META) { if (m.type !== \'card\' && PORTAL_TABS[m.id] !== false) return m.id; }
  return \'setting\';
}
function portalTabsApplyButtons() {
  const map = {wg: \'tabBtnWg\', mvnbc: \'tabBtnMvnbc\', smb: \'tabBtnSmb\', ipam: \'tabBtnIpam\', backup: \'tabBtnBackup\', logviewer: \'tabBtnLogViewer\'};
  for (const m of PORTAL_TABS_META) {
    if (m.type === \'card\' && m.target) {
      const el = document.getElementById(m.target);
      if (el) el.style.display = (PORTAL_TABS[m.id] === false) ? \'none\' : \'\';
      continue;
    }
    const btn = document.getElementById(map[m.id]);
    if (btn) btn.style.display = (PORTAL_TABS[m.id] === false) ? \'none\' : \'\';
  }
  if (CURRENT_VIEW !== \'setting\' && PORTAL_TABS[CURRENT_VIEW] === false) {
    CURRENT_VIEW = portalTabsFirstVisible();
  }
}
function portalTabsRender() {
  const box = document.getElementById(\'settingList\');
  if (!box) return;
  box.innerHTML = \'\';
  for (const m of PORTAL_TABS_META) {
    const on = PORTAL_TABS[m.id] !== false;
    const row = document.createElement(\'div\');
    row.className = \'set-row\' + (on ? \'\' : \' hidden-card\');
    row.innerHTML = \'<div class="set-ico">\' + m.icon + \'</div>\' +
      \'<div class="set-info"><div class="set-name">\' + esc(m.name) + \'</div>\' +
      \'<div class="set-desc">\' + esc(m.desc) + \'</div></div>\' +
      \'<span class="set-state \' + (on ? \'on\' : \'off\') + \'">\' + (on ? \'VISIBLE\' : \'HIDDEN\') + \'</span>\' +
      \'<input type="checkbox" class="mvtoggle" \' + (on ? \'checked\' : \'\') + \' title="Show/hide \' + esc(m.name) + \'" aria-label="Show/hide \' + esc(m.name) + \'">\';
    const tgl = row.querySelector(\'input\');
    tgl.addEventListener(\'change\', () => portalTabsToggle(m.id, tgl.checked));
    box.appendChild(row);
  }
  const msg = document.getElementById(\'settingMsg\');
  if (msg) {
    const hidden = PORTAL_TABS_META.filter(m => PORTAL_TABS[m.id] === false).map(m => m.name);
    msg.textContent = hidden.length ? (\'Hidden: \' + hidden.join(\', \')) : \'All cards visible\';
  }
}
async function portalTabsPush() {
  try {
    await fetch(\'/api/portal/tabs/save\', {method: \'POST\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF}, body: JSON.stringify({tabs: PORTAL_TABS})});
  } catch (e) {}
}
function portalTabsToggle(id, on) {
  PORTAL_TABS[id] = !!on;
  portalTabsStoreLocal();
  portalTabsApplyButtons();
  portalTabsRender();
  applyView();
  portalTabsPush();
  const m = PORTAL_TABS_META.find(x => x.id === id);
  toast((m ? m.name : id) + (on ? \' shown\' : \' hidden\'), on ? \'ok\' : \'warn\');
}
function portalTabsShowAll() {
  for (const m of PORTAL_TABS_META) PORTAL_TABS[m.id] = true;
  portalTabsStoreLocal(); portalTabsApplyButtons(); portalTabsRender(); applyView(); portalTabsPush();
  toast(\'All cards visible\', \'ok\');
}
function portalTabsReset() { portalTabsShowAll(); }
async function portalTabsLoad() {
  const local = portalTabsReadLocal();
  if (local) { for (const m of PORTAL_TABS_META) { if (typeof local[m.id] === \'boolean\') PORTAL_TABS[m.id] = local[m.id]; } }
  try {
    const res = await fetch(\'/api/portal/tabs\');
    if (res.ok) {
      const d = await res.json();
      if (d && d.ok && d.tabs) {
        for (const m of PORTAL_TABS_META) { if (typeof d.tabs[m.id] === \'boolean\') PORTAL_TABS[m.id] = d.tabs[m.id]; }
        portalTabsStoreLocal();
      }
    }
  } catch (e) {}
  portalTabsApplyButtons();
  portalTabsRender();
  applyView();
}
function applyView() {
  portalTabsApplyButtons();
  document.getElementById(\'wgTab\').style.display = CURRENT_VIEW === \'wg\' ? \'\' : \'none\';
  document.getElementById(\'sambaTab\').style.display = CURRENT_VIEW === \'smb\' ? \'\' : \'none\';
  document.getElementById(\'tabBtnWg\').classList.toggle(\'active\', CURRENT_VIEW === \'wg\');
  document.getElementById(\'tabBtnSmb\').classList.toggle(\'active\', CURRENT_VIEW === \'smb\');
  document.getElementById('mvnbcTab').style.display = CURRENT_VIEW === \'mvnbc\' ? \'\' : \'none\';
  document.getElementById('tabBtnMvnbc').classList.toggle(\'active\', CURRENT_VIEW === \'mvnbc\');
  document.getElementById('ipamTab').style.display = CURRENT_VIEW === \'ipam\' ? \'\' : \'none\';
  document.getElementById('tabBtnIpam').classList.toggle(\'active\', CURRENT_VIEW === \'ipam\');
  document.getElementById('backupTab').style.display = CURRENT_VIEW === \'backup\' ? \'\' : \'none\';
  document.getElementById('tabBtnBackup').classList.toggle(\'active\', CURRENT_VIEW === \'backup\');
  document.getElementById('logviewerTab').style.display = CURRENT_VIEW === \'logviewer\' ? \'\' : \'none\';
  document.getElementById('tabBtnLogViewer').classList.toggle(\'active\', CURRENT_VIEW === \'logviewer\');
  document.getElementById('settingTab').style.display = CURRENT_VIEW === \'setting\' ? \'\' : \'none\';
  document.getElementById('tabBtnSetting').classList.toggle(\'active\', CURRENT_VIEW === \'setting\');
  updateGlider();
}
let ipamLoaded=false;
(function(){try{var b=document.getElementById('ipamFullBtn');if(b){var h=window.location.hostname||'';if(h)b.href=window.location.protocol+'//'+h+':8091/?page=dashboard';}}catch(e){}})();
function showTab(v) {
  if (v !== \'setting\' && PORTAL_TABS[v] === false) {
    const m = PORTAL_TABS_META.find(x => x.id === v);
    toast((m ? m.name : v) + \' is hidden — enable it in Setting\', \'warn\');
    v = \'setting\';
  }
  CURRENT_VIEW = v; applyView();
  if (v === \'setting\') { portalTabsRender(); loadServices(); }
  if (v === \'smb\' && !smbLoaded) { loadSmb(); smbLoaded = true; } if (v === \'mvnbc\' && !mvLoaded) { loadMvnbc(); mvLoaded = true; } if (v === \'ipam\' && !ipamLoaded) { loadIpam(); ipamLoaded = true; } if (v === \'backup\') { loadBackups(); }
}
window.addEventListener(\'resize\', updateGlider);
setTimeout(updateGlider, 50);

/* ---------- IPAM ---------- */
let IPAM_DATA=[];
async function loadIpam(){
  const tb=document.getElementById('ipamSubTable');
  try{
    const res=await fetch('/api/ipam/summary');
    if(res.status===401){window.location='/login';return;}
    const d=await res.json();
    if(!d.ok){ tb.innerHTML='<tr><td colspan="4" class="dim">IPAM error: '+esc(d.error||'db down')+' — is darkveda-ipam-db running?</td></tr>'; return; }
    IPAM_DATA=d.subnets||[];
    const c=d.counts||{};
    const kpi=document.getElementById('ipamKpi'); if(kpi) kpi.style.display='grid';
    document.getElementById('ipamKSub').textContent=c.subnets??IPAM_DATA.length;
    const used=IPAM_DATA.reduce((a,s)=>a+(s.used||0),0), tot=IPAM_DATA.reduce((a,s)=>a+(s.total||0),0);
    document.getElementById('ipamKUsed').textContent=used;
    document.getElementById('ipamKUsedSub').textContent='of '+tot+' usable';
    document.getElementById('ipamKVlan').textContent=c.vlans??'—';
    document.getElementById('ipamKDev').textContent=c.devices??'—';
    const kc=document.getElementById('ipamKConf');
    kc.textContent=c.conflicts??0;
    kc.style.color=(c.conflicts>0)?'#EF4444':'';
    if(!IPAM_DATA.length){ tb.innerHTML='<tr><td colspan="4" class="dim">no subnets — click + Add Subnet</td></tr>'; return; }
    tb.innerHTML='';
    for(const s of IPAM_DATA){
      const hot=(s.pct||0)>=90;
      const tr=document.createElement('tr'); tr.className='subnet-row';
      tr.innerHTML='<td><div class="bright mono">'+esc(s.cidr)+'</div><div class="dim" style="font-size:.76em;">'+esc(s.name||'')+'</div></td>'+
        '<td class="dim" style="font-size:.82em;">'+esc(s.site||'—')+(s.vlan?' · <span class="net-chip">'+esc(s.vlan)+'</span>':'')+'</td>'+
        '<td class="mono dim">'+esc(s.gateway||'—')+'</td>'+
        '<td><div class="mono" style="font-size:.8em;">'+s.used+' / '+s.total+' ('+s.pct+'%)</div><span class="util-track" style="width:130px;"><span class="util-fill'+(hot?' hot':'')+'" style="width:'+Math.min(100,s.pct||0)+'%"></span></span></td>'+
        '<td style="text-align:right;"><button class="btn xs">IPs</button></td>';
      tr.addEventListener('click',()=>ipamDetail(s.id));
      tb.appendChild(tr);
    }
  }catch(e){ tb.innerHTML='<tr><td colspan="5" class="dim">IPAM unreachable</td></tr>'; }
}
async function ipamDetail(sid){
  const sec=document.getElementById('ipamDetailSec'), body=document.getElementById('ipamIpTable');
  body.innerHTML='<tr><td colspan="5" class="dim">loading…</td></tr>'; sec.style.display='block';
  try{
    const res=await fetch('/api/ipam/subnet/'+sid+'/ips');
    const d=await res.json();
    document.getElementById('ipamDetailTitle').textContent=(d.cidr||'')+' · '+(d.name||'IPs');
    if(!d.ok||!d.ips.length){ body.innerHTML='<tr><td colspan="5" class="dim">no IPs recorded — run Discovery in Full IPAM</td></tr>'; return; }
    body.innerHTML='';
    for(const ip of d.ips){
      const v=(ip.status||'').toLowerCase();
      const cls=v==='active'?'ip-st-active':v==='reserved'?'ip-st-reserved':v==='dhcp'?'ip-st-dhcp':v==='gateway'?'ip-st-gateway':'ip-st-off';
      const tr=document.createElement('tr');
      tr.innerHTML='<td class="mono bright">'+esc(ip.address)+'</td><td><span class="ip-status '+cls+'">'+esc(ip.status||'—')+'</span></td><td class="dim">'+esc(ip.hostname||'—')+'</td><td class="mono dim" style="font-size:.8em;">'+esc(ip.mac||'—')+'</td><td class="dim" style="font-size:.8em;">'+esc(ip.last_seen||'—')+'</td>';
      body.appendChild(tr);
    }
    sec.scrollIntoView({behavior:'smooth',block:'nearest'});
  }catch(e){ body.innerHTML='<tr><td colspan="5" class="dim">fetch failed</td></tr>'; }
}
function ipamOpenAdd(){ document.getElementById('ipamAddModal').classList.add('open'); document.getElementById('ipamAddMsg').textContent=''; setTimeout(()=>document.getElementById('ipamNewCidr').focus(),50); }
async function ipamCreate(){
  const msg=document.getElementById('ipamAddMsg'); msg.textContent='creating…';
  try{
    const res=await fetch('/api/ipam/subnet',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({cidr:document.getElementById('ipamNewCidr').value,name:document.getElementById('ipamNewName').value,gateway:document.getElementById('ipamNewGw').value,description:document.getElementById('ipamNewDesc').value})});
    const d=await res.json();
    if(d.ok){ msg.textContent='created ✓'; document.getElementById('ipamAddModal').classList.remove('open'); ipamLoaded=true; loadIpam(); toast('Subnet added','ok'); }
    else msg.textContent=d.error||'failed';
  }catch(e){ msg.textContent='request failed'; }
}

/* ---------- keyboard shortcuts ---------- */

document.addEventListener(\'keydown\', e => {
  if ([\'INPUT\',\'TEXTAREA\',\'SELECT\'].includes(e.target.tagName)) return;
  if (e.key === \'1\') showTab(\'wg\');
  else if (e.key === \'2\') showTab(\'mvnbc\');
  else if (e.key === \'3\') showTab(\'smb\');
  else if (e.key === \'4\') showTab(\'ipam\');
  else if (e.key === \'5\') showTab(\'backup\');
  else if (e.key === \'6\') showTab(\'logviewer\');
  else if (e.key === \'7\') showTab(\'setting\');
  else if (e.key === \'r\' || e.key === \'R\') refreshCurrent();
});

/* ---------- data load / render ---------- */
async function loadData() {
  try {
    const res = await fetch(\'/api/status\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    render(await res.json());
  } catch(e) { console.error(e); }
}

/* Refresh button: refresh CURRENT tab, not just WireGuard.
   Previously onclick="loadData()" only reloaded WG, so on Samba/IPAM/MVNBC
   tabs the button appeared dead (WG tab hidden, no visible change). */
function refreshCurrent() {
  try { document.getElementById(\'lastUpdate\').textContent = new Date().toLocaleTimeString(); } catch (_) {}
  if (CURRENT_VIEW === \'smb\') { smbLoaded = true; loadSmb(); toast(\'Samba reloaded\', \'ok\'); }
  else if (CURRENT_VIEW === \'ipam\') { ipamLoaded = true; loadIpam(); toast(\'IPAM reloaded\', \'ok\'); }
  else if (CURRENT_VIEW === \'mvnbc\') { mvLoaded = true; loadMvnbc(); toast(\'MVNBC reloaded\', \'ok\'); }
  else if (CURRENT_VIEW === \'setting\') { portalTabsRender(); loadServices(); toast(\'Settings reloaded\', \'ok\'); }
  else if (CURRENT_VIEW === \'backup\') { loadBackups(); toast(\'Backups reloaded\', \'ok\'); }
  else if (CURRENT_VIEW === \'logviewer\') { if (logSourcesLoaded) loadLogs(); toast(\'Logs reloaded\', \'ok\'); }
  else { loadData(); loadWgPeers(); loadBgpCtl(); loadBackups(); }
}

let SPARK = [], __lastKey;
function drawSpark() {
  const cv = document.getElementById(\'trafficSpark\');
  if (!cv) return;
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  if (!w || !h) return;
  cv.width = w * dpr; cv.height = h * dpr;
  const ctx = cv.getContext(\'2d\');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  if (SPARK.length < 2) return;
  const max = Math.max(...SPARK) || 1;
  const step = w / (SPARK.length - 1);
  const y = v => h - (v / max) * (h - 4) - 1;
  ctx.beginPath(); ctx.moveTo(0, h);
  SPARK.forEach((v, i) => ctx.lineTo(i * step, y(v)));
  ctx.lineTo(w, h); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, \'rgba(255,176,196,.55)\');
  grad.addColorStop(1, \'rgba(255,176,196,0)\');
  ctx.fillStyle = grad; ctx.fill();
  ctx.beginPath();
  SPARK.forEach((v, i) => { const X = i * step, Y = y(v); i ? ctx.lineTo(X, Y) : ctx.moveTo(X, Y); });
  ctx.strokeStyle = \'#FFB0C4\'; ctx.lineWidth = 1.6; ctx.stroke();
}

const PEER_HIST_CACHE = {};
async function drawPeerSpark(cv, pub) {
  try {
    if (typeof CURRENT_VIEW !== 'undefined' && CURRENT_VIEW !== 'wg') return;
    const now = Date.now();
    const hit = PEER_HIST_CACHE[pub];
    let pts = null;
    if (hit && (now - hit.t) < 60000) { pts = hit.pts; }
    else {
      const res = await fetch(\'/api/wg/traffic/history?peer=\' + encodeURIComponent(pub) + \'&window=24h\');
      if (res.status === 401) { window.location = \'/login\'; return; }
      const d = await res.json();
      if (!d.ok) return;
      pts = d.points || [];
      PEER_HIST_CACHE[pub] = { t: now, pts: pts };
    }
    if (!pts || pts.length < 2) return;
    const vals = pts.map(function(r){ return (r[1]||0) + (r[2]||0); });
    const w = cv.clientWidth || 120, h = cv.clientHeight || 28;
    const dpr = window.devicePixelRatio || 1;
    cv.width = w * dpr; cv.height = h * dpr;
    const ctx = cv.getContext(\'2d\');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const max = Math.max.apply(null, vals) || 1;
    const step = w / (vals.length - 1);
    const y = function(v){ return h - (v / max) * (h - 4) - 1; };
    ctx.beginPath(); ctx.moveTo(0, h);
    vals.forEach(function(v, i){ ctx.lineTo(i * step, y(v)); });
    ctx.lineTo(w, h); ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, \'rgba(88,166,255,.55)\');
    grad.addColorStop(1, \'rgba(88,166,255,0)\');
    ctx.fillStyle = grad; ctx.fill();
    ctx.beginPath();
    vals.forEach(function(v, i){ const X = i * step, Y = y(v); i ? ctx.lineTo(X, Y) : ctx.moveTo(X, Y); });
    ctx.strokeStyle = \'#58a6ff\'; ctx.lineWidth = 1.4; ctx.stroke();
  } catch (e) {}
}

function render(data) {
  document.getElementById(\'lastUpdate\').textContent = new Date().toLocaleTimeString();
  document.getElementById(\'uptime\').textContent = data.uptime || \'\';
  applyView();

  const ifaces = data.wg.interfaces || [];
  const wgIface = ifaces.find(i => i.name.startsWith(\'wg\')) || ifaces[0];

  if (wgIface) {
    const peers = wgIface.peers || [];
    const connected = peers.filter(p => p.connected);

    const ts = document.getElementById(\'tunnelStatus\');
    if (connected.length > 0) {
      ts.innerHTML = \'<span class="dot"></span>UP\';
      ts.className = \'value up\';
      document.getElementById(\'tunnelDetail\').textContent = connected.length + \'/\' + peers.length + \' peers connected\';
    } else {
      ts.innerHTML = \'<span class="dot"></span>DOWN\';
      ts.className = \'value down\';
      document.getElementById(\'tunnelDetail\').textContent = \'no active peers\';
    }

    if (peers.length > 0) {
      const p = peers[0];
      document.getElementById(\'peerEndpoint\').innerHTML =
        (p.endpoint || \'N/A\') + \' <button class="copy-btn" title="Copy endpoint" onclick="copyText(\\\'\' + (p.endpoint || \'\').replace(/\'/g, \'\') + \'\\\',\\\'Endpoint\\\')">&#128203;</button>\';
      const ph = document.getElementById(\'peerHandshake\');
      ph.textContent = \'handshake: \' + p.handshake_human;
      ph.style.color = p.connected ? \'#15803d\' : \'#B45309\';
      const totalRx = peers.reduce((s, p) => s + p.transfer_rx, 0);
      const totalTx = peers.reduce((s, p) => s + p.transfer_tx, 0);
      document.getElementById(\'traffic\').textContent = fmtBytes(totalRx) + \' / \' + fmtBytes(totalTx);
      const key = totalRx + totalTx;
      if (__lastKey !== undefined) {
        SPARK.push(Math.max(0, key - __lastKey));
        if (SPARK.length > 60) SPARK.shift();
        drawSpark();
      }
      __lastKey = key;
    }

    const ifaceTb = document.getElementById(\'ifaceTable\');
    ifaceTb.innerHTML = \'\';
    for (const iface of ifaces) {
      const ips = (iface.ip_info || {}).ips || [];
      const st = iface.effective_state || \'UNKNOWN\';
      const stCls = st === \'UP\' ? \'connected\' : (st === \'DOWN\' ? \'disconnected\' : \'stale\');
      ifaceTb.innerHTML += \'<tr>\' +
        \'<td class="bright mono">\' + iface.name + \'</td>\' +
        \'<td><span class="badge \' + stCls + \'" title="kernel operstate: \' + (iface.kernel_state || \'n/a\') + \'">\' + st +
        \'<span style="opacity:.6; font-weight:400; font-size:.85em;"> (\' + (iface.kernel_state || \'?\').toLowerCase() + \')</span></span></td>\' +
        \'<td class="mono">\' + iface.listen_port + \'</td>\' +
        \'<td class="mono dim">\' + (ips.join(\', \') || \'none\') + \'</td>\' +
        \'<td class="mono">\' + (iface.peers || []).length + \'</td></tr>\';
    }

    const peerTb = document.getElementById(\'peerTable\');
    peerTb.innerHTML = \'\';
    for (const p of peers) {
      const cls = p.connected ? \'connected\' : (p.handshake_ago && p.handshake_ago < 300 ? \'stale\' : \'disconnected\');
      peerTb.innerHTML += \'<tr>\' +
        \'<td><span class="badge \' + cls + \'">\' + (p.connected ? \'ACTIVE\' : \'STALE\') + \'</span></td>\' +
        \'<td class="mono dim" title="\' + esc(p.public_key||\'\') + \'">\' + (p.endpoint || \'N/A\') + \'</td>\' +
        \'<td class="mono">\' + p.allowed_ips + \'</td>\' +
        \'<td class="mono" style="color:\' + (p.connected ? \'#15803d\' : \'#B45309\') + \'">\' + p.handshake_human + \'</td>\' +
        \'<td class="mono">\' + p.rx_human + \'</td>\' +
        \'<td class="mono">\' + p.tx_human + \'</td><td><canvas class="peer-spark" data-pub="\' + esc(p.public_key||\'\') + \'" width="120" height="28" title="RX/TX 24h"></canvas></td></tr>\';
    }
    for (const p of peers) {
      const cv = document.querySelector(\'canvas.peer-spark[data-pub="\' + CSS.escape(p.public_key||\'\') + \'"]\');
      if (cv) drawPeerSpark(cv, p.public_key);
    }
  }

  const rl = document.getElementById(\'routeList\');
  rl.innerHTML = (data.routes || []).map(r => \'<div>\' + r + \'</div>\').join(\'\') || \'<div class="dim">no WG routes</div>\';

  const bl = document.getElementById(\'bgpList\');
  const bgpPeers = data.bgp.peers || [];
  if (bgpPeers.length > 0) {
    bl.innerHTML = bgpPeers.map(p =>
      \'<div>\' + p.neighbor + \' <span class="dim">AS\' + p.remote_as + \'</span> <span class="badge \' +
      (p.state === \'Established\' ? \'connected\' : \'disconnected\') + \'" style="margin-left:8px">\' +
      (p.state === \'Established\' ? p.pfx_rcd + \' pfx\' : p.state) + \'</span> <span class="dim" style="margin-left:8px">\' + p.up_time + \'</span></div>\'
    ).join(\'\');
    const up = bgpPeers.filter(p => p.state === \'Established\').length;
    const bs = document.getElementById(\'bgpStatus\');
    bs.textContent = up + \'/\' + bgpPeers.length;
    bs.className = \'value \' + (up > 0 ? \'up\' : \'down\');
    document.getElementById(\'bgpDetail\').textContent = up > 0 ? \'established\' : \'down\';
  } else {
    bl.innerHTML = \'<div class="dim">no BGP peers or FRR not running</div>\';
    const bs = document.getElementById(\'bgpStatus\');
    bs.textContent = \'N/A\';
    bs.className = \'value warn\';
    document.getElementById(\'bgpDetail\').textContent = \'FRR not found\';
  }
  renderBgpCorr(data.bgp_corr);
}

function renderBgpCorr(c) {
  const sec = document.getElementById(\'block-bgpcorr\');
  if (!sec || !c) { if (sec) sec.style.display = \'none\'; return; }
  const rows = c.rows || [];
  if (!rows.length) { sec.style.display = \'none\'; return; }
  sec.style.display = \'\';
  const head = \'AS\' + (c.local_as || \'?\') + \' (RID \' + (c.router_id || \'?\') + \') \u2194 AS\' + (c.remote_as || \'?\') +
    \' \u00b7 \' + (c.received_count||0) + \' received / \' + (c.advertised_count||0) + \' advertised\';
  document.getElementById(\'bgpCorrHead\').textContent = head;
  const tb = document.getElementById(\'bgpCorrTable\');
  tb.innerHTML = \'\';
  const clsFor = (s) => s === \'OK\' ? \'connected\' : (s === \'ADVERTISED\' ? \'stale\' : \'disconnected\');
  for (const r of rows) {
    tb.innerHTML += \'<tr>\' +
      \'<td class="mono bright">\' + esc(r.prefix) + (r.dir === \'wg-only\' ? \' <span class="dim">(wg-only)</span>\' : \'\') + \'</td>\' +
      \'<td class="mono dim">\' + esc(r.nexthop || \'-\') + \'</td>\' +
      \'<td class="mono dim">\' + esc((r.wg_peers || []).join(\', \') || \'-\') + \'</td>\' +
      \'<td class="mono dim">\' + (r.in_kernel ? \'yes\' : \'no\') + \'</td>\' +
      \'<td><span class="badge \' + clsFor(r.status) + \'">\' + esc(r.status) + \'</span></td></tr>\';
  }
}

function fmtBytes(b) {
  if (b < 1024) return b + \' B\';
  if (b < 1048576) return (b/1024).toFixed(1) + \' KB\';
  if (b < 1073741824) return (b/1048576).toFixed(1) + \' MB\';
  return (b/1073741824).toFixed(1) + \' GB\';
}

/* ---------- Collapsible cards, Run Logs pattern (vendor-block + chevron). WG cards always start collapsed. ---------- */
function toggleSec(id, event) {
  try { if (event && event.target && event.target.closest && event.target.closest(\'input,textarea,select,button\')) return; } catch (e) {}
  const el = document.getElementById(\'block-\' + id.toLowerCase());
  if (el) el.classList.toggle(\'collapsed\');
  if (id === \'smbConf\' && el && !el.classList.contains(\'collapsed\')) { try { if (!smbConfLoaded) loadSmbConf(); } catch (e) {} }
  if (id === \'logviewer\' && el && !el.classList.contains(\'collapsed\')) { try { if (!logSourcesLoaded) loadLogSources(); } catch (e) {} }
}
function applySecState() {
  for (const id of [\'wgRoutes\', \'bgpSummary\', \'bgpCorr\', \'wgConf\', \'connPeers\', \'smbConf\', \'wgPeers\', \'bgpCtl\', \'netBackup\', \'logviewer\']) {
    const el = document.getElementById(\'block-\' + id.toLowerCase());
    if (el) el.classList.add(\'collapsed\');
  }
  for (const bid of [\'block-mvcfgpolicy\', \'block-mvcfgalerts\', \'block-mvtelegram\', \'block-mvcfgschedule\', \'block-mvretention\', \'block-samba\', \'block-ipamsubs\', \'block-settingvis\', \'block-services\']) {
    const el = document.getElementById(bid);
    if (el) el.classList.add(\'collapsed\');
  }
}

/* ---------- WireGuard full config (wg0.conf) ---------- */
function wgConfMsg(text, color) {
  const el = document.getElementById(\'wgConfMsg\');
  el.textContent = text || \'\';
  el.style.color = color || \'#6B5CA5\';
}
async function loadWGConf() {
  try {
    const res = await fetch(\'/api/wg-conf\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    if (d.error) { wgConfMsg(\'Error: \' + d.error, \'#DC2626\'); return; }
    document.getElementById(\'wgConfBox\').value = d.raw || \'\';
    wgConfMsg(\'Loaded \' + (d.raw || \'\').split(/\\n/).length + \' lines\', \'#15803d\');
  } catch(e) { wgConfMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
async function saveWGConf() {
  const box = document.getElementById(\'wgConfBox\');
  const val = box.value;
  if (!val || !val.trim()) { wgConfMsg(\'Empty config — nothing to save\', \'#B45309\'); return; }
  if (!confirm(\'Overwrite /etc/wireguard/wg0.conf and RESTART the tunnel? Tunnel drops <10s.\')) return;
  wgConfMsg(\'Validating & saving...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/wg-conf\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({wg_conf: val})
    });
    const d = await res.json();
    if (d.ok) {
      wgConfMsg(\'✓ \' + d.message, \'#15803d\');
      toast(\'wg0.conf saved & applied\', \'ok\');
      setTimeout(loadData, 3000);
    } else {
      wgConfMsg(\'✗ \' + (d.error || \'save failed\'), \'#DC2626\');
      toast(\'Save failed: \' + (d.error || \'\'), \'err\');
    }
  } catch(e) { wgConfMsg(\'Save failed: \' + e, \'#DC2626\'); toast(\'Save failed\', \'err\'); }
}
/* Legacy AllowedIPs-only wrappers (kept for compat; route to full editor) */
async function loadAllowedIPs() { return loadWGConf(); }
async function saveAllowedIPs() { return saveWGConf(); }
function aipMsg(text, color) { return wgConfMsg(text, color); }
function restartWG() {
  document.getElementById(\'restartConfirm\').style.display = \'block\';
  document.getElementById(\'restartConfirmInput\').focus();
}
async function doRestartWG() {
  const input = document.getElementById(\'restartConfirmInput\');
  const val = input.value.trim().toLowerCase();
  if (val !== \'restart\') { input.style.borderColor = \'#DC2626\'; input.focus(); toast(\'Type "restart" to confirm\', \'warn\'); return; }
  input.style.borderColor = \'\';
  const btn = event.target;
  btn.textContent = \'Restarting...\'; btn.disabled = true;
  try {
    const res = await fetch(\'/api/restart-wg\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({confirm: val})
    });
    const d = await res.json();
    document.getElementById(\'restartConfirm\').style.display = \'none\';
    input.value = \'\';
    if (d.ok) {
      aipMsg(\'✓ \' + d.message, \'#15803d\');
      toast(\'WireGuard restarted\', \'ok\');
      setTimeout(loadData, 3000);
    } else {
      aipMsg(\'✗ \' + (d.error || \'restart failed\'), \'#DC2626\');
      toast(\'Restart failed: \' + (d.error || \'\'), \'err\');
    }
  } catch(e) { aipMsg(\'Restart failed: \' + e, \'#DC2626\'); toast(\'Restart failed\', \'err\'); }
  btn.textContent = \'Confirm Restart\'; btn.disabled = false;
}

/* ---------- WireGuard peers ---------- */
function wgPeerMsg(text, color) {
  const el = document.getElementById(\'wgPeerFormMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
async function loadWgPeers() {
  try {
    const res = await fetch(\'/api/wg/peers\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    if (!d.ok) { wgPeerMsg(\'✗ \' + (d.error || \'load failed\'), \'#DC2626\'); return; }
    if (d.suggest_ip && !document.getElementById(\'wpIp\').value) document.getElementById(\'wpIp\').value = d.suggest_ip;
    if (d.endpoint_default && !document.getElementById(\'wpEndpoint\').value) document.getElementById(\'wpEndpoint\').value = d.endpoint_default;
    const tb = document.getElementById(\'wgPeersTable\');
    tb.innerHTML = \'\';
    for (const p of (d.peers || [])) {
      const cls = p.connected ? \'connected\' : \'disconnected\';
      let acts = \'<span class="dim">site peer</span>\';
      if (p.deletable) {
        const files = p.has_client
          ? \'<a class="btn xs" href="/api/wg/peers/qr?pub=\' + encodeURIComponent(p.public_key) + \'" target="_blank">QR</a> \' +
            \'<a class="btn xs" href="/api/wg/peers/conf?pub=\' + encodeURIComponent(p.public_key) + \'">Conf</a> \' : \'\';
        acts = files + \'<button class="btn xs danger" onclick="delWgPeer(\\\'\' + p.public_key + \'\\\')">Del</button>\';
      }
      tb.innerHTML += \'<tr><td class="bright mono">\' + esc(p.name || p.public_short) + \'</td>\' +
        \'<td class="mono dim">\' + esc((p.allowed_ips || []).join(\', \')) + \'</td>\' +
        \'<td><span class="badge \' + cls + \'">\' + (p.connected ? \'ACTIVE\' : \'STALE\') + \'</span></td>\' +
        \'<td class="mono dim">\' + esc((p.rx || \'-\') + \' / \' + (p.tx || \'-\')) + \'</td>\' +
        \'<td style="text-align:right; white-space:nowrap;">\' + acts + \'</td></tr>\';
    }
    if (!(d.peers || []).length) tb.innerHTML = \'<tr><td colspan="5" class="dim">no peers</td></tr>\';
  } catch(e) { wgPeerMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
async function saveWgPeer() {
  const body = {
    name: document.getElementById(\'wpName\').value.trim(),
    ip: document.getElementById(\'wpIp\').value.trim(),
    endpoint: document.getElementById(\'wpEndpoint\').value.trim(),
    dns: document.getElementById(\'wpDns\').value.trim()
  };
  if (!body.name) { wgPeerMsg(\'Name required\', \'#B45309\'); return; }
  wgPeerMsg(\'Adding peer...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/wg/peers\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify(body)
    });
    const d = await res.json();
    if (d.ok) {
      wgPeerMsg(\'✓ \' + d.message, \'#15803d\');
      toast(\'Peer added\', \'ok\');
      document.getElementById(\'wpName\').value = \'\';
      document.getElementById(\'wpIp\').value = \'\';
      const rp = document.getElementById(\'wgPeerResult\');
      rp.style.display = \'block\';
      document.getElementById(\'wgPeerResultTitle\').textContent = \'Peer \' + d.name + \' (\' + d.ip + \') — scan or download\';
      if (d.qr) document.getElementById(\'wgPeerQr\').src = d.qr;
      document.getElementById(\'wgPeerConf\').value = d.client_conf || \'\';
      document.getElementById(\'wgPeerDlBtn\').onclick = () => { window.location = \'/api/wg/peers/conf?pub=\' + encodeURIComponent(d.public_key); };
      loadWgPeers(); setTimeout(loadData, 3000);
    } else {
      wgPeerMsg(\'✗ \' + (d.error || \'add failed\'), \'#DC2626\');
      toast(\'Add failed: \' + (d.error || \'\'), \'err\');
    }
  } catch(e) { wgPeerMsg(\'Add failed: \' + e, \'#DC2626\'); toast(\'Add failed\', \'err\'); }
}
async function delWgPeer(pub) {
  if (!confirm(\'Remove peer \' + pub.slice(0, 12) + \'…? Its tunnel drops immediately.\')) return;
  try {
    const res = await fetch(\'/api/wg/peers\', {
      method: \'DELETE\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({public_key: pub})
    });
    const d = await res.json();
    if (d.ok) { toast(\'Peer removed\', \'ok\'); loadWgPeers(); setTimeout(loadData, 3000); }
    else { toast(\'Delete failed: \' + (d.error || \'\'), \'err\'); }
  } catch(e) { toast(\'Delete failed: \' + e, \'err\'); }
}

/* ---------- BGP control ---------- */
function bgpCtlMsg(text, color) {
  const el = document.getElementById(\'bgpCtlMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
let bgpAnnounced = null;
async function loadBgpCtl() {
  try {
    const res = await fetch(\'/api/bgp/origin\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const badge = document.getElementById(\'bgpOriginBadge\');
    const btn = document.getElementById(\'bgpAnnounceBtn\');
    if (d.ok) {
      bgpAnnounced = !!d.announced;
      badge.textContent = bgpAnnounced ? \'ANNOUNCED\' : \'WITHDRAWN\';
      badge.className = \'badge \' + (bgpAnnounced ? \'connected\' : \'disconnected\');
      btn.textContent = bgpAnnounced ? \'Withdraw\' : \'Announce\';
      btn.className = \'btn \' + (bgpAnnounced ? \'danger\' : \'success\');
    } else {
      badge.textContent = \'UNKNOWN\'; badge.className = \'badge stale\';
    }
  } catch(e) { bgpCtlMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
async function bgpAnnounce() {
  const action = bgpAnnounced ? \'withdraw\' : \'announce\';
  if (!confirm(action === \'announce\' ? \'Announce 192.168.10.0/24 to AS65002?\' : \'Withdraw 192.168.10.0/24 (home loses this route)?\')) return;
  bgpCtlMsg(action + \'ing...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/bgp/announce\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({action: action})
    });
    const d = await res.json();
    if (d.ok) { bgpCtlMsg(\'✓ \' + d.message, \'#15803d\'); toast(\'BGP updated\', \'ok\'); loadBgpCtl(); setTimeout(loadData, 4000); }
    else { bgpCtlMsg(\'✗ \' + (d.error || \'failed\'), \'#DC2626\'); toast(d.error || \'Failed\', \'err\'); }
  } catch(e) { bgpCtlMsg(\'Failed: \' + e, \'#DC2626\'); }
}
async function doBgpReset() {
  const input = document.getElementById(\'bgpResetInput\');
  const val = input.value.trim().toLowerCase();
  if (val !== \'reset\') { input.style.borderColor = \'#DC2626\'; input.focus(); toast(\'Type "reset" to confirm\', \'warn\'); return; }
  input.style.borderColor = \'\';
  try {
    const res = await fetch(\'/api/bgp/reset\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({confirm: val})
    });
    const d = await res.json();
    document.getElementById(\'bgpResetConfirm\').style.display = \'none\';
    input.value = \'\';
    if (d.ok) { bgpCtlMsg(\'✓ \' + d.message, \'#15803d\'); toast(\'BGP reset sent\', \'ok\'); setTimeout(loadData, 4000); }
    else { bgpCtlMsg(\'✗ \' + (d.error || \'failed\'), \'#DC2626\'); }
  } catch(e) { bgpCtlMsg(\'Failed: \' + e, \'#DC2626\'); }
}

/* ---------- Config backups ---------- */
function backupMsg(text, color) {
  const el = document.getElementById(\'backupMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
async function loadBackups() {
  try {
    const res = await fetch(\'/api/backups\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const tb = document.getElementById(\'backupTable\');
    tb.innerHTML = \'\';
    for (const b of (d.backups || [])) {
      tb.innerHTML += \'<tr><td class="bright mono">\' + esc(b.name) + \'</td>\' +
        \'<td class="mono dim">\' + fmtBytes(b.size) + \'</td>\' +
        \'<td class="mono dim">\' + esc(b.date) + \'</td>\' +
        \'<td style="text-align:right; white-space:nowrap;">\' +
          \'<a class="btn xs" href="/api/backups/download?name=\' + encodeURIComponent(b.name) + \'">Get</a> \' +
          \'<button class="btn xs primary" onclick="askRestore(\\\'\' + esc(b.name) + \'\\\')">Restore</button> \' +
          \'<button class="btn xs danger" onclick="delBackup(\\\'\' + esc(b.name) + \'\\\')">Del</button>\' +
        \'</td></tr>\';
    }
    if (!(d.backups || []).length) tb.innerHTML = \'<tr><td colspan="4" class="dim">no snapshots yet</td></tr>\';
  } catch(e) { backupMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
async function createBackup() {
  backupMsg(\'Snapshotting...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/backups\', {
      method: \'POST\', headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF}, body: \'{}\'
    });
    const d = await res.json();
    if (d.ok) { backupMsg(\'✓ \' + d.message, \'#15803d\'); toast(\'Snapshot created\', \'ok\'); loadBackups(); }
    else { backupMsg(\'✗ \' + (d.error || \'failed\'), \'#DC2626\'); }
  } catch(e) { backupMsg(\'Failed: \' + e, \'#DC2626\'); }
}
async function delBackup(name) {
  if (!confirm(\'Delete snapshot \' + name + \'?\')) return;
  try {
    const res = await fetch(\'/api/backups\', {
      method: \'DELETE\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({name: name})
    });
    const d = await res.json();
    if (d.ok) { toast(\'Snapshot deleted\', \'ok\'); loadBackups(); }
    else toast(d.error || \'Delete failed\', \'err\');
  } catch(e) { toast(\'Delete failed: \' + e, \'err\'); }
}
let restoreTarget = \'\';
function askRestore(name) {
  restoreTarget = name;
  document.getElementById(\'restoreName\').textContent = name;
  document.getElementById(\'restoreSteps\').innerHTML = \'\';
  document.getElementById(\'restoreConfirm\').style.display = \'block\';
}
async function doRestore() {
  const input = document.getElementById(\'restoreConfirmInput\');
  const val = input.value.trim().toLowerCase();
  if (val !== \'restore\') { input.style.borderColor = \'#DC2626\'; input.focus(); toast(\'Type "restore" to confirm\', \'warn\'); return; }
  input.style.borderColor = \'\';
  backupMsg(\'Restoring...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/backups/restore\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({name: restoreTarget, confirm: val})
    });
    const d = await res.json();
    document.getElementById(\'restoreConfirm\').style.display = \'none\';
    input.value = \'\';
    const box = document.getElementById(\'restoreSteps\');
    if (d.steps) box.innerHTML = d.steps.map(s => \'<div>\' + esc(s) + \'</div>\').join(\'\');
    if (d.ok) { backupMsg(\'✓ \' + d.message, \'#15803d\'); toast(\'Restore applied\', \'ok\'); setTimeout(loadData, 4000); }
    else { backupMsg(\'✗ \' + (d.error || \'restore failed\'), \'#DC2626\'); }
  } catch(e) { backupMsg(\'Restore failed: \' + e, \'#DC2626\'); }
}

/* ---------- Log viewer (Backups tab) ---------- */
let logSourcesLoaded = false, logTimer = null;
function logMsg(text, color) {
  const el = document.getElementById(\'logMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
async function loadLogSources() {
  try {
    const res = await fetch(\'/api/services\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const sel = document.getElementById(\'logSource\');
    sel.innerHTML = \'\';
    const add = (kind, value, label) => {
      const o = document.createElement(\'option\');
      o.value = kind + \'|\' + value; o.textContent = label;
      sel.appendChild(o);
    };
    for (const u of (d.units || [])) add(\'systemd\', u.unit, \'⚙ \' + u.label);
    for (const c of (d.containers || [])) add(\'docker\', c.unit, \'🐳 \' + c.unit);
    logSourcesLoaded = true;
    loadLogs();
  } catch(e) { logMsg(\'Sources failed: \' + e, \'#DC2626\'); }
}
async function loadLogs() {
  const sel = document.getElementById(\'logSource\');
  if (!sel || !sel.value) { logMsg(\'Pick a source first\', \'#B45309\'); return; }
  const [kind, unit] = sel.value.split(\'|\');
  let n = parseInt((document.getElementById(\'logLines\').value || \'100\').trim(), 10);
  if (!n || n < 10) n = 10; if (n > 500) n = 500;
  logMsg(\'Loading...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/logs?kind=\' + encodeURIComponent(kind) + \'&unit=\' + encodeURIComponent(unit) + \'&lines=\' + n);
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const box = document.getElementById(\'logOutput\');
    if (d.ok) {
      box.textContent = d.output || \'(empty)\';
      box.scrollTop = box.scrollHeight;
      logMsg(\'✓ \' + unit + \' · \' + d.lines + \' lines\', \'#15803d\');
    } else {
      box.textContent = \'Error: \' + (d.error || \'fetch failed\');
      logMsg(\'✗ \' + (d.error || \'fetch failed\'), \'#DC2626\');
    }
  } catch(e) { logMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
function logAutoToggle() {
  const on = document.getElementById(\'logAuto\').checked;
  if (logTimer) { clearInterval(logTimer); logTimer = null; }
  if (on) { loadLogs(); logTimer = setInterval(loadLogs, 5000); }
}

/* ---------- Services control (Setting tab) ---------- */
async function loadServices() {
  try {
    const res = await fetch(\'/api/services\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const sysCtl = (d.ctl || \'systemd\') === \'systemd\';
    const utb = document.getElementById(\'svcUnitTable\');
    if (utb) {
      utb.innerHTML = \'\';
      for (const u of (d.units || [])) {
        const on = u.active === \'active\';
        const en = String(u.enabled || \'\');
        const isEn = en.indexOf(\'enabled\') === 0;
        const enBtn = sysCtl ? \'<button class="btn xs" onclick="toggleServiceEnabled(\\\'\' + esc(u.unit) + \'\\\',\\\'\' + (isEn ? \'disable\' : \'enable\') + \'\\\')">\' + (isEn ? \'Disable\' : \'Enable\') + \'</button>\' : \'\';
        const rstBtn = u.restartable
          ? \'<button class="btn xs warn" onclick="restartService(\\\'systemd\\\',\\\'\' + esc(u.unit) + \'\\\')">Restart</button> \'
          : \'\';
        utb.innerHTML += \'<tr><td class="bright mono">\' + esc(u.label) +
          \'<div class="dim" style="font-size:.78em;">\' + esc(u.unit) + (u.enabled ? \' · \' + esc(u.enabled) : \'\') + \'</div></td>\' +
          \'<td><span class="badge \' + (on ? \'connected\' : \'disconnected\') + \'">\' + esc(String(u.active).toUpperCase()) + \'</span></td>\' +
          \'<td style="text-align:right; white-space:nowrap;">\' + rstBtn + enBtn + \'</td></tr>\';
      }
    }
    const dtb = document.getElementById(\'svcDockerTable\');
    if (dtb) {
      dtb.innerHTML = \'\';
      for (const c of (d.containers || [])) {
        dtb.innerHTML += \'<tr><td class="bright mono">\' + esc(c.unit) + \'</td>\' +
          \'<td class="mono dim" style="font-size:.8em;">\' + esc(c.active) + \'</td>\' +
          \'<td style="text-align:right;"><button class="btn xs warn" onclick="restartService(\\\'docker\\\',\\\'\' + esc(c.unit) + \'\\\')">Restart</button></td></tr>\';
      }
      if (!(d.containers || []).length) dtb.innerHTML = \'<tr><td colspan="3" class="dim">no containers (docker down?)</td></tr>\';
    }
  } catch(e) { toast(\'Services load failed: \' + e, \'err\'); }
}
async function restartService(kind, unit) {
  const warn = unit === \'darkveda-lab\'
    ? \'Restart this portal? The page will drop for a few seconds — reload it after.\'
    : \'Restart \' + unit + \'? Brief interruption possible.\';
  if (!confirm(warn)) return;
  try {
    const res = await fetch(\'/api/services/restart\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({kind: kind, unit: unit, confirm: \'restart\'})
    });
    const d = await res.json();
    if (d.ok) { toast(d.message, \'ok\'); setTimeout(loadServices, kind === \'docker\' ? 8000 : 4000); }
    else toast(d.error || \'Restart failed\', \'err\');
  } catch(e) { toast(\'Restart failed: \' + e, \'err\'); }
}
async function toggleServiceEnabled(unit, action) {
  const verb = action === \'disable\' ? \'Disable autostart for \' : \'Enable autostart for \';
  if (!confirm(verb + unit + (action === \'disable\' ? \'? It will NOT start on next boot.\' : \'? It will start on next boot.\'))) return;
  try {
    const res = await fetch(\'/api/services/enable\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({unit: unit, action: action})
    });
    const d = await res.json();
    if (d.ok) { toast(d.message, \'ok\'); loadServices(); }
    else toast(d.error || \'Failed\', \'err\');
  } catch(e) { toast(\'Failed: \' + e, \'err\'); }
}

/* ---------- Samba ---------- */
function smbMsg(id, text, color) {
  const el = document.getElementById(id);
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
function esc(s) {
  return String(s == null ? \'\' : s).replace(/[<>&"\']/g, c => ({\'<\':\'&lt;\',\'>\':\'&gt;\',\'&\':\'&amp;\',\'"\':\'&quot;\',"\'":\'&#39;\'}[c]));
}
let SMB_SHARES = [];
let SB = {share: \'\', sub: \'\'};

async function loadSmb() {
  try {
    const res = await fetch(\'/api/samba/status\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const b = document.getElementById(\'smbSvcBadge\');
    const on = d.service && d.service.active === \'active\';
    b.textContent = on ? \'RUNNING\' : (d.service ? d.service.active.toUpperCase() : \'UNKNOWN\');
    b.className = \'badge \' + (on ? \'connected\' : \'disconnected\');
    document.getElementById(\'smbVer\').textContent = (d.service && d.service.version) || \'\';
    document.getElementById(\'smbConfPath\').textContent = d.conf || \'\';
    SMB_SHARES = d.shares || [];
    const tb = document.getElementById(\'smbSharesTable\');
    tb.innerHTML = \'\';
    let totFree=0, totTotal=0, hasUsage=false;
    for (const s of SMB_SHARES) {
      const mode = s.writable ? \'<span class="badge connected">RW</span>\' : \'<span class="badge stale">RO</span>\';
      const uu = (d.usage && d.usage[s.name]) || null;
      if (uu) { hasUsage=true; totFree+=uu.free||0; totTotal+=uu.total||0; }
      const nets = String(s.hosts_allow||\'\').split(/[\s,]+/).filter(Boolean);
      const shown = nets.slice(0,3).map(n=>\'<span class="net-chip">\'+esc(n)+\'</span>\').join(\'\');
      const more = nets.length>3 ? (\' <button class="net-more" title="\'+esc(nets.slice(3).join(\', \'))+\'">+\'+(nets.length-3)+\' more</button>\') : \'\';
      const tip = uu ? (fmtBytes(uu.free) + ' free / ' + fmtBytes(uu.total) + ' (' + (uu.pct||0) + '%)') : 'no data';
      tb.innerHTML += \'<tr title="\' + esc(tip) + \'">\' +
        \'<td><div class="bright mono">\' + esc(s.name) + \'  \' + mode + \'</div><div class="share-row-path">\' + esc(s.path) + \'</div></td>\' +
        \'<td class="mono dim">\' + esc(s.valid_users || \'ALL\') + \'</td>\' +
        \'<td style="max-width:180px;">\' + shown + more + \'</td>\' +
        \'<td style="text-align:right; white-space:nowrap;" class="samba-actions">\' +
          \'<button class="btn xs" title="Browse files" onclick="sbOpen(\\\'\' + esc(s.name) + \'\\\')">Files</button> \' +
          \'<button class="btn xs" title="Edit share" onclick="shareEdit(\\\'\' + esc(s.name) + \'\\\')">Edit</button> \' +
          \'<button class="btn xs danger" title="Delete share" onclick="shareDel(\\\'\' + esc(s.name) + \'\\\')">Del</button>\' +
        \'</td></tr>\';
    }
    // KPI strip + Usage card
    const kpi = document.getElementById(\'sambaKpi\');
    const qs = document.getElementById(\'smbQuotaSummary\');
    const ub = document.getElementById(\'smbUsageBar\');
    const ubEmpty = document.getElementById(\'smbUsageEmpty\');
    if (hasUsage && totTotal>0) {
      const pct = Math.round((totTotal-totFree)*100/totTotal);
      if (kpi) kpi.style.display = \'grid\';
      document.getElementById(\'kpiStorage\').textContent = fmtBytes(totFree) + \' free\';
      document.getElementById(\'kpiStorageSub\').textContent = \'of \' + fmtBytes(totTotal) + \' \u00b7 \' + pct + \'% used\';
      document.getElementById(\'kpiStorageFill\').style.width = Math.min(100, Math.max(0, 100-pct)) + \'%\';
      if (qs) qs.textContent = fmtBytes(totFree) + \' free / \' + fmtBytes(totTotal);
      if (ub) {
        const rows = SMB_SHARES.map(s => { const u=d.usage&&d.usage[s.name]; return u ? \'<div style="display:flex; justify-content:space-between; font-size:.82em; padding:5px 0; border-bottom:1px solid var(--line);"><span>\' + esc(s.name) + \'</span><span class="mono">\' + fmtBytes(u.free) + \' / \' + fmtBytes(u.total) + \'</span></div>\' + \'<span class="usage-track"><span class="usage-fill" style="width:\' + (u.pct||0) + \'%"></span></span>\' : \'\'; }).filter(Boolean).join(\'\');
        ub.innerHTML = \'<div style="font-size:.8em; margin-bottom:8px; font-weight:700;"><span class="mono">\' + fmtBytes(totFree) + \' free</span> of <span class="mono">\' + fmtBytes(totTotal) + \'</span> · \' + pct + \'% used</div><span class="usage-track" style="margin-bottom:12px;"><span class="usage-fill" style="width:\' + (100-pct) + \'%"></span></span>\' + rows;
        if (ubEmpty) ubEmpty.style.display=\'none\';
      }
    } else {
      if (kpi) kpi.style.display = \'none\';
      if (qs) qs.textContent = \'\';
      if (ub) ub.innerHTML = \'\';
      if (ubEmpty) ubEmpty.style.display = \'block\';
    }
    if (!SMB_SHARES.length) tb.innerHTML = \'<tr><td colspan="5" class="dim">no shares</td></tr>\';

    const utb = document.getElementById(\'smbUsersTable\');
    utb.innerHTML = \'\';
    for (const u of (d.users || [])) {
      utb.innerHTML += \'<tr><td class="bright mono">\' + esc(u.username) + \'</td><td class="mono dim">\' + esc(u.uid) + \'</td>\' +
        \'<td style="text-align:right; white-space:nowrap;">\' +
          \'<button class="btn xs" onclick="openAccessForm(\\\'\' + esc(u.username) + \'\\\')">Access</button> \' +
          \'<button class="btn xs" onclick="userPass(\\\'\' + esc(u.username) + \'\\\')">Pass</button> \' +
          \'<button class="btn xs danger" onclick="userDel(\\\'\' + esc(u.username) + \'\\\')">Del</button>\' +
        \'</td></tr>\';
    }
    if (!(d.users || []).length) utb.innerHTML = \'<tr><td colspan="3" class="dim">no samba users</td></tr>\';

    const cl = document.getElementById(\'smbConnsList\');
    const cr = (d.conn_rows || []);
    const ks = document.getElementById(\'kpiSessions\');
    const kss = document.getElementById(\'kpiSessionsSub\');
    if (ks) ks.textContent = cr.length ? cr.length : \'0\';
    if (kss) kss.textContent = cr.length === 1 ? \'1 active connection\' : cr.length + \' active connections\';
    const kpi2 = document.getElementById(\'sambaKpi\');
    if (kpi2 && (cr.length || document.getElementById(\'kpiStorage\'))) kpi2.style.display = \'grid\';
    if (cr.length) {
      const tbl = document.createElement(\'table\');
      cl.innerHTML = \'\';
      cl.appendChild(tbl);
      tbl.innerHTML = \'<thead><tr><th>Client</th><th>Share</th><th style="text-align:right;">Action</th></tr></thead><tbody id="smbConnBody"></tbody>\';
      const bd = document.getElementById(\'smbConnBody\');
      for (const c of cr) {
        bd.innerHTML += \'<tr><td><div class="bright mono">\' + esc(c.user) + \'</div><div class="dim mono" style="font-size:.74em;">\' + esc(c.ip) + \' \u00b7 pid \' + esc(c.pid) + \'</div></td><td><span class="badge connected">\' + esc(c.service) + \'</span></td><td style="text-align:right;"><button class="btn xs danger" title="Terminate session" onclick="smbKill(\\\'\' + esc(c.pid) + \'\\\',\\\'\' + esc(c.service) + \'\\\',\\\'\' + esc(c.ip) + \'\\\')">Kill</button></td></tr>\';
      }
    } else {
      const rows = (d.connections || []).filter(l => !/^-{5,}/.test(l) && !/^PID[ ]/.test(l));
      cl.innerHTML = rows.map(l => \'<div style="font-size:.78em;">\' + esc(l) + \'</div>\').join(\'\') || \'<div class="dim">No active sessions — clients appear here on connect.</div>\';
    }
    // quota bar — now rendered in the Usage card above; legacy path removed
  } catch(e) { console.error(e); }
}

async function smbKill(pid, share, ip) {
  if (!confirm(\'Terminate session pid \' + pid + (share && share !== \'-\' ? \' (\' + share + \')\' : \'') + \'? Client will reconnect.\')) return;
  try {
    const res = await fetch(\'/api/samba/sessions/kill\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ pid: pid, share: share, ip: ip }) });
    const dj = await res.json();
    if (!dj.ok) { toast(dj.error || \'kill failed\', \'err\'); return; }
    toast(dj.message || \'killed\', \'ok\');
    loadSmb();
  } catch(e) { toast(\'kill failed: \' + e, \'err\'); }
}

function toggleShareForm(mode, name) {
  const f = document.getElementById(\'shareForm\');
  const show = f.style.display === \'none\';
  f.style.display = show ? \'block\' : \'none\';
  if (show) {
    smbMsg(\'shareFormMsg\', \'\');
    document.getElementById(\'shareFormTitle\').textContent = mode === \'edit\' ? \'Edit Share: \' + name : \'Add Share\';
    if (mode !== \'edit\') {
      for (const id of [\'sfName\',\'sfPath\',\'sfComment\',\'sfUsers\']) document.getElementById(id).value = \'\';
      document.getElementById(\'sfName\').disabled = false;
      document.getElementById(\'sfHosts\').value = \'192.168.10.0/24 172.16.30.0/24 172.16.3.0/24 172.16.20.0/24\';
      document.getElementById(\'sfWritable\').value = \'1\';
      document.getElementById(\'sfMkdir\').checked = false;
    }
  }
}

function shareEdit(name) {
  const s = SMB_SHARES.find(x => x.name === name);
  if (!s) return;
  const f = document.getElementById(\'shareForm\');
  f.style.display = \'block\';
  document.getElementById(\'shareFormTitle\').textContent = \'Edit Share: \' + name;
  document.getElementById(\'sfName\').value = s.name;
  document.getElementById(\'sfName\').disabled = true;
  document.getElementById(\'sfPath\').value = s.path;
  document.getElementById(\'sfComment\').value = s.comment || \'\';
  document.getElementById(\'sfUsers\').value = s.valid_users || \'\';
  document.getElementById(\'sfHosts\').value = s.hosts_allow === \'ALL\' ? \'ALL\' : s.hosts_allow;
  document.getElementById(\'sfWritable\').value = s.writable ? \'1\' : \'0\';
  smbMsg(\'shareFormMsg\', \'\');
}

async function saveShare() {
  const editing = document.getElementById(\'sfName\').disabled;
  const body = {
    name: document.getElementById(\'sfName\').value.trim(),
    path: document.getElementById(\'sfPath\').value.trim(),
    comment: document.getElementById(\'sfComment\').value.trim(),
    valid_users: document.getElementById(\'sfUsers\').value.trim(),
    hosts_allow: document.getElementById(\'sfHosts\').value.trim(),
    writable: document.getElementById(\'sfWritable\').value === \'1\',
    create_folder: document.getElementById(\'sfMkdir\').checked
  };
  smbMsg(\'shareFormMsg\', \'Saving...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/shares\', {
      method: editing ? \'PUT\' : \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify(body)
    });
    const d = await res.json();
    if (d.ok) {
      smbMsg(\'shareFormMsg\', \'✓ \' + d.message, \'#15803d\');
      document.getElementById(\'shareForm\').style.display = \'none\';
      toast(\'Share \' + (editing ? \'updated\' : \'created\'), \'ok\');
      ACCESS_CACHE = null;
      loadSmb();
    } else { smbMsg(\'shareFormMsg\', \'✗ \' + (d.error || \'failed\'), \'#DC2626\'); toast(d.error || \'Save failed\', \'err\'); }
  } catch(e) { smbMsg(\'shareFormMsg\', \'✗ \' + e, \'#DC2626\'); toast(\'Save failed\', \'err\'); }
}

async function shareDel(name) {
  if (!confirm(\'Delete share [\' + name + \']? (folder on disk is NOT deleted)\')) return;
  try {
    const res = await fetch(\'/api/samba/shares\', {
      method: \'DELETE\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({name: name})
    });
    const d = await res.json();
    if (!d.ok) { alert(\'Delete failed: \' + (d.error || \'\')); return; }
    toast(\'Share deleted\', \'ok\');
    ACCESS_CACHE = null;
    loadSmb();
  } catch(e) { alert(\'Delete failed: \' + e); }
}

function toggleUserForm() {
  const f = document.getElementById(\'userForm\');
  const show = f.style.display === \'none\';
  f.style.display = show ? \'block\' : \'none\';
  if (show) {
    smbMsg(\'userFormMsg\', \'\');
    document.getElementById(\'ufUser\').value = \'\';
    document.getElementById(\'ufPass\').value = \'\';
    document.getElementById(\'ufAccessWrap\').style.display = \'\';
    fillUserAccess(\'\');
  }
}

function userPass(username) {
  const f = document.getElementById(\'userForm\');
  f.style.display = \'block\';
  smbMsg(\'userFormMsg\', \'\');
  document.getElementById(\'ufUser\').value = username;
  document.getElementById(\'ufPass\').value = \'\';
  document.getElementById(\'ufAccessWrap\').style.display = \'none\';
  document.getElementById(\'ufPass\').focus();
}

let ACCESS_CACHE = null;
async function loadAccessMatrix() {
  try {
    const res = await fetch(\'/api/samba/access\');
    if (res.status === 401) { window.location = \'/login\'; return null; }
    const d = await res.json();
    if (!d.ok) return null;
    ACCESS_CACHE = d;
    return d;
  } catch(e) { return null; }
}
function accessRadios(containerId, user, matrix) {
  const box = document.getElementById(containerId);
  box.innerHTML = \'\';
  const shares = (matrix && matrix.shares) || [];
  for (const s of shares) {
    const cur = (((matrix.access || {})[user] || {})[s.name]) || \'none\';
    const row = document.createElement(\'div\');
    row.style.cssText = \'display:flex; gap:10px; align-items:center; padding:7px 0; border-bottom:1px solid rgba(148,163,184,.07); flex-wrap:wrap;\';
    row.innerHTML = \'<span class="mono bright" style="min-width:130px;">\' + esc(s.name) + \'</span> \' +
      \'<span class="dim" style="font-size:.75em;">\' + esc(s.path) + \'</span> \' +
      [[\'none\',\'No access\'],[\'ro\',\'Read\'],[\'rw\',\'Read+Write\']].map(([lv, lb]) =>
        \'<label style="display:flex; gap:5px; align-items:center; font-size:.82em; cursor:pointer;">\' +
        \'<input type="radio" name="\' + containerId + \'__\' + esc(s.name) + \'" value="\' + lv + \'"\' + (cur === lv ? \' checked\' : \'\') + \'> \' + lb + \'</label>\'
      ).join(\'\');
    box.appendChild(row);
  }
  if (!shares.length) box.innerHTML = \'<div class="dim">no shares</div>\';
}
function readAccessRadios(containerId, shares) {
  const out = {};
  for (const s of (shares || [])) {
    const sel = document.querySelector(\'input[name="\' + containerId + \'__\' + s.name + \'"]:checked\');
    out[s.name] = sel ? sel.value : \'none\';
  }
  return out;
}
async function fillUserAccess(user) {
  const box = document.getElementById(\'ufAccess\');
  box.innerHTML = \'<div class="dim">loading shares…</div>\';
  const m = ACCESS_CACHE || await loadAccessMatrix();
  if (!m) { box.innerHTML = \'<div class="dim">failed to load shares</div>\'; return; }
  accessRadios(\'ufAccess\', user, m);
}
async function openAccessForm(username) {
  const f = document.getElementById(\'accessForm\');
  f.style.display = \'block\';
  smbMsg(\'accessFormMsg\', \'\');
  const m = ACCESS_CACHE || await loadAccessMatrix();
  if (!m) { smbMsg(\'accessFormMsg\', \'✗ failed to load shares/users\', \'#DC2626\'); return; }
  const sel = document.getElementById(\'afUser\');
  sel.innerHTML = \'\';
  const users = Object.keys(m.access || {});
  for (const u of users) {
    const o = document.createElement(\'option\');
    o.value = u; o.textContent = u;
    sel.appendChild(o);
  }
  if (username && users.includes(username)) sel.value = username;
  accessRadios(\'afShares\', sel.value, m);
  sel.onchange = () => accessRadios(\'afShares\', sel.value, ACCESS_CACHE);
}
async function saveAccess() {
  const u = document.getElementById(\'afUser\').value;
  if (!u) { smbMsg(\'accessFormMsg\', \'✗ pick a user\', \'#DC2626\'); return; }
  const body = {username: u, access: readAccessRadios(\'afShares\', ((ACCESS_CACHE || {}).shares || []))};
  smbMsg(\'accessFormMsg\', \'Saving...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/access\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify(body)
    });
    const d = await res.json();
    if (d.ok) {
      smbMsg(\'accessFormMsg\', \'✓ \' + d.message, \'#15803d\');
      toast(\'Access updated\', \'ok\');
      ACCESS_CACHE = null;
      loadSmb();
    } else { smbMsg(\'accessFormMsg\', \'✗ \' + (d.error || \'failed\'), \'#DC2626\'); toast(d.error || \'Failed\', \'err\'); }
  } catch(e) { smbMsg(\'accessFormMsg\', \'✗ \' + e, \'#DC2626\'); toast(\'Failed\', \'err\'); }
}

async function saveUser(mode) {
  const u = document.getElementById(\'ufUser\').value.trim();
  const p = document.getElementById(\'ufPass\').value;
  if (!u || !p) { smbMsg(\'userFormMsg\', \'✗ username & password required\', \'#DC2626\'); return; }
  const body = {username: u, password: p};
  if (mode === \'add\' && ACCESS_CACHE && (ACCESS_CACHE.shares || []).length) {
    body.access = readAccessRadios(\'ufAccess\', ACCESS_CACHE.shares);
  }
  smbMsg(\'userFormMsg\', \'Saving...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/users\', {
      method: mode === \'add\' ? \'POST\' : \'PUT\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify(body)
    });
    const d = await res.json();
    if (d.ok) {
      smbMsg(\'userFormMsg\', \'✓ \' + d.message, \'#15803d\');
      document.getElementById(\'ufPass\').value = \'\';
      toast(\'User \' + (mode === \'add\' ? \'added\' : \'password updated\'), \'ok\');
      ACCESS_CACHE = null;
      loadSmb();
    } else { smbMsg(\'userFormMsg\', \'✗ \' + (d.error || \'failed\'), \'#DC2626\'); toast(d.error || \'Failed\', \'err\'); }
  } catch(e) { smbMsg(\'userFormMsg\', \'✗ \' + e, \'#DC2626\'); toast(\'Failed\', \'err\'); }
}

async function userDel(username) {
  if (!confirm(\'Remove Samba access for "\' + username + \'"? (system user kept)\')) return;
  try {
    const res = await fetch(\'/api/samba/users\', {
      method: \'DELETE\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({username: username})
    });
    const d = await res.json();
    if (!d.ok) { alert(\'Delete failed: \' + (d.error || \'\')); return; }
    toast(\'User removed from Samba\', \'ok\');
    ACCESS_CACHE = null;
    loadSmb();
  } catch(e) { alert(\'Delete failed: \' + e); }
}

function restartSmb() {
  document.getElementById(\'smbRestartConfirm\').style.display = \'block\';
  document.getElementById(\'smbRestartConfirmInput\').focus();
}
function smbRestartMsg(text, color) {
  const el = document.getElementById(\'smbRestartMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
async function doRestartSmb() {
  const input = document.getElementById(\'smbRestartConfirmInput\');
  const val = input.value.trim().toLowerCase();
  if (val !== \'restart\') { input.style.borderColor = \'#DC2626\'; input.focus(); toast(\'Type "restart" to confirm\', \'warn\'); return; }
  input.style.borderColor = \'\';
  const btn = event.target;
  btn.textContent = \'Restarting...\'; btn.disabled = true;
  smbRestartMsg(\'Restarting...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/restart\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({confirm: val})
    });
    const d = await res.json();
    document.getElementById(\'smbRestartConfirm\').style.display = \'none\';
    input.value = \'\';
    if (d.ok) {
      smbRestartMsg(\'✓ \' + d.message, \'#15803d\');
      toast(\'Samba restarted\', \'ok\');
      loadSmb();
    } else {
      smbRestartMsg(\'✗ \' + (d.error || \'restart failed\'), \'#DC2626\');
      toast(\'Restart failed: \' + (d.error || \'\'), \'err\');
    }
  } catch(e) { smbRestartMsg(\'Restart failed: \' + e, \'#DC2626\'); toast(\'Restart failed\', \'err\'); }
  btn.textContent = \'Confirm Restart\'; btn.disabled = false;
}

async function sbOpen(share) { SB = {share: share, sub: \'\'}; await sbFetch(); }

/* ---------- Samba raw config (smb.conf) ---------- */
let smbConfLoaded = false;
function smbConfMsg(text, color) {
  const el = document.getElementById(\'smbConfMsg\');
  if (el) { el.textContent = text || \'\'; el.style.color = color || \'#6B5CA5\'; }
}
async function loadSmbConf() {
  smbConfMsg(\'Loading...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/conf\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    if (!d.ok && d.error) { smbConfMsg(\'✗ \' + d.error, \'#DC2626\'); return; }
    document.getElementById(\'smbConfBox\').value = d.raw || \'\';
    smbConfLoaded = true;
    smbConfMsg(\'✓ Loaded \' + (d.raw || \'\').split(/\\n/).length + \' lines\', \'#15803d\');
  } catch(e) { smbConfMsg(\'Load failed: \' + e, \'#DC2626\'); }
}
async function saveSmbConf() {
  const box = document.getElementById(\'smbConfBox\');
  const val = box.value;
  if (!val || !val.trim()) { smbConfMsg(\'Empty config — nothing to save\', \'#B45309\'); return; }
  if (!confirm(\'Overwrite /etc/samba/smb.conf and restart smbd? Active SMB sessions will drop briefly.\')) return;
  smbConfMsg(\'Validating & saving...\', \'#B45309\');
  try {
    const res = await fetch(\'/api/samba/conf\', {
      method: \'POST\',
      headers: {\'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF},
      body: JSON.stringify({smb_conf: val})
    });
    const d = await res.json();
    if (d.ok) {
      smbConfMsg(\'✓ \' + d.message, \'#15803d\');
      toast(\'smb.conf saved & applied\', \'ok\');
      loadSmb();
    } else {
      smbConfMsg(\'✗ \' + (d.error || \'save failed\'), \'#DC2626\');
      toast(\'Save failed: \' + (d.error || \'\'), \'err\');
    }
  } catch(e) { smbConfMsg(\'Save failed: \' + e, \'#DC2626\'); toast(\'Save failed\', \'err\'); }
}
async function sbNav(to) {
  if (to === \'..\') {
    if (!SB.sub) return;
    const parts = SB.sub.split(\'/\').filter(Boolean); parts.pop();
    SB.sub = parts.join(\'/\');
  } else { SB.sub = SB.sub ? SB.sub + \'/\' + to : to; }
  await sbFetch();
}
async function sbFetch() {
  const box = document.getElementById(\'smbBrowser\');
  box.style.display = \'block\';
  document.getElementById(\'sbShare\').textContent = SB.share;
  document.getElementById(\'sbFiles\').innerHTML = \'<tr><td colspan="4" class="dim">Loading...</td></tr>\';
  try {
    const res = await fetch(\'/api/samba/shares/browse?name=\' + encodeURIComponent(SB.share) + \'&sub=\' + encodeURIComponent(SB.sub));
    const d = await res.json();
    if (!d.ok) { document.getElementById(\'sbFiles\').innerHTML = \'<tr><td colspan="4" style="color:#DC2626;">\' + esc(d.error) + \'</td></tr>\'; return; }
    document.getElementById(\'sbPath\').textContent = d.path;
    document.getElementById(\'sbUpBtn\').style.display = SB.sub ? \'\' : \'none\';
    const tb = document.getElementById(\'sbFiles\');
    tb.innerHTML = \'\';
    for (const it of d.items) {
      const label = it.dir
        ? \'<a href="#" onclick="sbNav(\\\'\' + esc(it.name) + \'\\\'); return false;" style="color:#6F4ECC;">\' + esc(it.name) + \'/</a>\'
        : esc(it.name);
      tb.innerHTML += \'<tr><td class="mono">\' + label + \'</td>\' +
        \'<td class="dim">\' + (it.dir ? \'dir\' : \'file\') + \'</td>\' +
        \'<td class="mono dim">\' + (it.dir ? \'-\' : fmtBytes(it.size)) + \'</td>\' +
        \'<td class="mono dim" style="font-size:.85em;">\' + esc(it.mtime) + \'</td></tr>\';
    }
    if (!d.items.length) tb.innerHTML = \'<tr><td colspan="4" class="dim">empty</td></tr>\';
  } catch(e) { document.getElementById(\'sbFiles\').innerHTML = \'<tr><td colspan="4" style="color:#DC2626;">\' + esc(e) + \'</td></tr>\'; }
}

/* ---------- MVNBC ---------- */
let mvLoaded = false, mvPollTimer = null, mvSearchTimer = null;
function fmtAge(s) {
  if (s == null) return \'-\';
  if (s < 60) return s + \'s\';
  if (s < 3600) return Math.floor(s / 60) + \'m\';
  if (s < 86400) return Math.floor(s / 3600) + \'h\';
  return Math.floor(s / 86400) + \'d\';
}
function mvJobRender(r) {
  const b = document.getElementById(\'mvJobBadge\');
  let cls, txt;
  if (r.running) { cls = \'stale\'; txt = \'RUNNING\'; }
  else if (r.done && r.fail > 0) { cls = \'disconnected\'; txt = \'ISSUES\'; }
  else if (r.done) { cls = \'connected\'; txt = \'OK\'; }
  else { cls = \'disconnected\'; txt = \'IDLE\'; }
  b.className = \'badge \' + cls;
  b.textContent = txt;
  document.getElementById(\'mvRunStat\').textContent = r.log
    ? (\'ok \' + r.ok + \' / fail \' + r.fail + \' / \' + r.log) : \'no runs on this host yet\';
  const feed = document.getElementById(\'mvRunFeed\');
  const show = r.running || (r.lines && r.lines.length);
  feed.style.display = show ? \'block\' : \'none\';
  feed.textContent = (r.running ? \'[running...]\\n\' : (r.log ? \'[\' + r.log + \']\\n\' : \'\')) + (r.lines || []).join(\'\\n\');
  feed.scrollTop = feed.scrollHeight;
  document.getElementById(\'mvRunBtn\').disabled = !!r.running;
  document.getElementById(\'mvRunBtn\').textContent = r.running ? \'Running...\' : \'\\u25B6 Run Backup Now\';
}
function mvRenderLogs(logs) {
  const tb = document.getElementById(\'mvLogsTable\');
  tb.innerHTML = \'\';
  for (const l of (logs || [])) {
    tb.innerHTML += \'<tr>\' +
      \'<td><input type="checkbox" class="mvchk mvlogchk" value="\' + esc(l.name) + \'"></td>\' +
      \'<td class="mono bright">\' + esc(l.name) + \'</td>\' +
      \'<td class="mono dim">\' + l.size + \' KB</td>\' +
      \'<td class="mono dim">\' + esc(l.date) + \'</td>\' +
      \'<td style="text-align:right; white-space:nowrap;">\' +
        \'<button class="btn xs" data-act="view" data-k="l" data-p="\' + esc(l.name) + \'">View</button> \' +
        \'<button class="btn xs" data-act="dl" data-k="l" data-p="\' + esc(l.name) + \'">Get</button> \' +
        \'<button class="btn xs danger" data-act="del" data-k="l" data-p="\' + esc(l.name) + \'">Del</button>\' +
      \'</td></tr>\';
  }
  if (!tb.innerHTML) tb.innerHTML = \'<tr><td colspan="5" class="dim">no run logs yet</td></tr>\';
  const _blk = document.getElementById(\'block-mvlogs\'); if (_blk) _blk.classList.add(\'collapsed\');
  const _lc = document.getElementById(\'mvLogsCount\');
  if (_lc) _lc.textContent = (logs || []).length + \' log(s)\';
}
function mvToggleLogsAll(master) {
  document.querySelectorAll(\'#mvLogsTable .mvlogchk\').forEach(function(cb){ cb.checked = master.checked; });
}
function mvLogsSelectAll() {
  document.querySelectorAll(\'#mvLogsTable .mvlogchk\').forEach(function(cb){ cb.checked = true; });
  const h = document.querySelector(\'#mvLogsTable\');
}
function mvLogsClear() {
  document.querySelectorAll(\'#mvLogsTable .mvlogchk\').forEach(function(cb){ cb.checked = false; });
  const head = document.querySelector(\'thead input[onclick*="mvToggleLogsAll"]\');
  if (head) head.checked = false;
}
function mvLogsSelected() {
  const out = [];
  document.querySelectorAll(\'#mvLogsTable .mvlogchk:checked\').forEach(function(cb){ out.push({k:\'l\', p:cb.value}); });
  return out;
}
async function mvLogsBulkDl(sel) {
  let files = sel;
  if (!files) {
    files = mvLogsSelected();
    if (!files.length) { toast(\'tick/select at least one log first\', \'warn\'); return; }
  }
  try {
    const res = await fetch(\'/api/mvnbc/download-zip\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ files: files }) });
    if (!res.ok) {
      let m = \'download failed\';
      try { const j = await res.json(); m = j.error || m; } catch(e) {}
      toast(m, \'err\'); return;
    }
    const blob = await res.blob();
    const a = document.createElement(\'a\');
    a.href = URL.createObjectURL(blob);
    a.download = \'mvnbc_run_logs_\' + new Date().toISOString().slice(0,10) + \'.zip\';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ URL.revokeObjectURL(a.href); }, 4000);
    toast(files.length + \' log(s) downloaded\', \'ok\');
  } catch (e) { toast(\'download failed: \' + e, \'err\'); }
}
function mvDlLogsZip() {
  const files = mvLogsSelected();
  if (!files.length) { toast(\'tick/select at least one log first\', \'warn\'); return; }
  mvLogsBulkDl(files);
}
async function mvLogsBulkDel() {
  const files = mvLogsSelected();
  if (!files.length) { toast(\'tick/select at least one log first\', \'warn\'); return; }
  if (!confirm(\'Delete \' + files.length + \' selected log(s)?\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/bulk-delete\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ files: files }) });
    const d = await res.json();
    if (!d.ok && !d.deleted) { toast(d.error || \'delete failed\', \'err\'); return; }
    toast(d.message || \'Deleted\', (d.failed ? \'warn\' : \'ok\'));
    loadMvnbc();
  } catch (e) { toast(\'delete failed: \' + e, \'err\'); }
}
async function loadMvnbcFiles() {
  try {
    const res = await fetch(\'/api/mvnbc/files?q=\' + encodeURIComponent(window.mvFilesQ || \'\'));
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const wrap = document.getElementById(\'mvFilesWrap\');
    wrap.innerHTML = \'\';
    let total = d.total || 0;
    document.getElementById(\'mvFilesCount\').textContent = total + \' file\' + (total === 1 ? \'\' : \'s\');
    const allBtn = document.getElementById(\'mvDlAllBtn\');
    if (allBtn) allBtn.style.display = (d.groups && d.groups.length) ? \'\' : \'none\';
    for (const g of (d.groups || [])) {
      const vendor = g.vendor;
      const vid = String(vendor).replace(/[^a-z0-9_]/gi, \'\');
      const files = g.files || [];
      const okCount = files.filter(function(f){ return f.status === \'OK\'; }).length;
      const pillCls = (okCount === files.length && files.length) ? \'connected\' : (okCount === 0 ? \'disconnected\' : \'stale\');
      let rows = \'\';
      for (const f of files) {
        const cls = f.status === \'OK\' ? \'connected\' : \'disconnected\';
        const p = vendor + \'/\' + f.name;
        rows += \'<tr class="row-\' + vid + \'">\' +
          \'<td><input type="checkbox" class="mvchk" data-vendor="\' + vid + \'" value="\' + esc(p) + \'"></td>\' +
          \'<td class="mono">\' + esc(f.name) + \'</td>\' +
          \'<td class="mono dim">\' + esc(f.ip) + \'</td>\' +
          \'<td class="mono dim">\' + f.size + \' KB</td>\' +
          \'<td class="mono dim">\' + esc(f.date) + \'</td>\' +
          \'<td><span class="badge \' + cls + \'">\' + f.status + \'</span></td>\' +
          \'<td style="text-align:right; white-space:nowrap;">\' +
            \'<button class="btn xs" data-act="view" data-k="b" data-p="\' + esc(p) + \'">View</button> \' +
            \'<button class="btn xs" data-act="dl" data-k="b" data-p="\' + esc(p) + \'">Get</button>\' +
          \'</td></tr>\';
      }
      if (!rows) rows = \'<tr><td colspan="7" class="dim">no files</td></tr>\';
      wrap.innerHTML += \'<div class="vendor-block collapsed" id="block-\' + vid + \'">\' +
        \'<div class="vendor-block-head" data-vid="\' + vid + \'">\' +
          \'<span class="chevron">&#9654;</span>\' +
          \'<span class="vtitle">\' + esc(String(vendor).toUpperCase()) + \'</span>\' +
          \'<span class="vtag">\' + files.length + \' &middot; \' + okCount + \' ok</span>\' +
          \'<span class="spacer"></span>\' +
          \'<span class="badge \' + pillCls + \'">\' + okCount + \'/\' + files.length + \' valid</span>\' +
        \'</div>\' +
        \'<div class="vendor-block-body">\' +
          \'<div class="table-scroll"><table>\' +
            \'<thead><tr><th style="width:34px;"><input type="checkbox" class="mvchk" onclick="toggleVendorAll(this, \\'\' + vid + \'\\')"></th><th>File</th><th>IP Address</th><th>Size</th><th>Captured</th><th>Status</th><th style="text-align:right;">Action</th></tr></thead>\' +
            \'<tbody>\' + rows + \'</tbody>\' +
          \'</table></div>\' +
          \'<div class="btn-row">\' +
            \'<button class="btn xs" onclick="mvDlVendor(\\'\' + esc(vendor) + \'\\')">Download \' + esc(String(vendor).toUpperCase()) + \' (.zip)</button>\' +
            \'<span style="flex:1;"></span>\' +
            \'<button class="btn xs" onclick="selectVendorAll(\\'\' + vid + \'\\')">Select all</button>\' +
            \'<button class="btn xs" onclick="unselectVendorAll(\\'\' + vid + \'\\')">Clear</button>\' +
            \'<button class="btn xs danger" onclick="mvBulkDeleteVendor(\\'\' + vid + \'\\')">Delete selected</button>\' +
          \'</div>\' +
        \'</div>\' +
      \'</div>\';
    }
    if (!wrap.innerHTML) wrap.innerHTML = \'<div class="dim">no backup files match</div>\';
  } catch (e) { console.error(e); }
}
function toggleBlock(vid, event) {
  try { if (event && event.target && event.target.closest && event.target.closest(\'input\')) return; } catch(e) {}
  const el = document.getElementById(\'block-\' + vid);
  if (el) el.classList.toggle(\'collapsed\');
}
// delegated expand/collapse for vendor blocks (survives innerHTML rebuilds)
document.addEventListener(\'click\', function(e){
  const head = e.target.closest && e.target.closest(\'.vendor-block-head\');
  if (!head) return;
  if (!head.closest(\'#mvnbcTab\')) return;
  if (e.target.closest && e.target.closest(\'input\')) return;
  const vid = head.getAttribute(\'data-vid\');
  if (!vid) return;
  const el = document.getElementById(\'block-\' + vid);
  if (el) el.classList.toggle(\'collapsed\');
});
function toggleVendorAll(master, vid) {
  document.querySelectorAll(\'.row-\' + vid + \' input[type=checkbox]\').forEach(function(cb){ cb.checked = master.checked; });
}
function selectVendorAll(vid) {
  document.querySelectorAll(\'.row-\' + vid + \' input[type=checkbox]\').forEach(function(cb){ cb.checked = true; });
}
function unselectVendorAll(vid) {
  document.querySelectorAll(\'.row-\' + vid + \' input[type=checkbox]\').forEach(function(cb){ cb.checked = false; });
  const head = document.querySelector(\'#block-\' + vid + \' thead input[type=checkbox]\');
  if (head) head.checked = false;
}
function mvSelectedPaths(vid) {
  const out = [];
  document.querySelectorAll(\'.row-\' + vid + \' input[type=checkbox]:checked\').forEach(function(cb){ out.push(cb.value); });
  return out;
}
function mvDlVendor(vendor) {
  window.location = \'/api/mvnbc/download-zip?vendor=\' + encodeURIComponent(vendor);
}
function mvDlAll() {
  window.location = \'/api/mvnbc/download-zip?vendor=__all__\';
}
async function mvBulkDeleteVendor(vid) {
  const files = mvSelectedPaths(vid);
  if (!files.length) { toast(\'tick/select at least one file first\', \'warn\'); return; }
  if (!confirm(\'Delete \' + files.length + \' selected file(s)?\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/bulk-delete\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ files: files }) });
    const d = await res.json();
    if (!d.ok && !d.deleted) { toast(d.error || \'delete failed\', \'err\'); return; }
    toast(d.message || \'Deleted\', (d.failed ? \'warn\' : \'ok\'));
    loadMvnbc();
  } catch (e) { toast(\'delete failed: \' + e, \'err\'); }
}
async function loadMvnbc() {
  try {
    const res = await fetch(\'/api/mvnbc/summary\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    document.getElementById(\'mvTotal\').textContent = d.total;
    document.getElementById(\'mvOk\').textContent = d.ok;
    document.getElementById(\'mvFail\').textContent = d.fail;
    document.getElementById(\'mvFiles\').textContent = d.files.total;
    document.getElementById(\'mvFilesSub\').textContent = d.files.ok + \' valid / \' + d.files.fail + \' invalid\';
    document.getElementById(\'mvNewest\').textContent = d.newest ? d.newest.date : \'none\';
    const tb = document.getElementById(\'mvDevTable\');
    tb.innerHTML = \'\';
    for (const r of d.devices) {
      const cls = r.status === \'OK\' ? \'connected\' : \'disconnected\';
      tb.innerHTML += \'<tr>\' +
        \'<td><span class="badge \' + cls + \'">\' + r.status + \'</span></td>\' +
        \'<td class="bright mono">\' + esc(r.vendor) + \'</td>\' +
        \'<td class="mono">\' + esc(r.ip) + \'</td>\' +
        \'<td class="mono dim">\' + esc(r.user || \'-\') + \'</td>\' +
        \'<td class="mono dim">\' + (r.date || \'no backup yet\') + \'</td>\' +
        \'<td class="mono">\' + fmtAge(r.age) + \'</td></tr>\';
    }
    if (!tb.innerHTML) tb.innerHTML = \'<tr><td colspan="6" class="dim">no devices in devices.conf</td></tr>\';
    document.getElementById(\'mvCron\').textContent = d.cron
      ? (\'schedule: \' + d.cron)
      : (d.has_script ? \'schedule: not installed - runs are manual from this portal\' : \'MVNBC.sh not found\');
    if (d.next_run && d.next_run.epoch) {
      window._mvNextEpoch = d.next_run.epoch;
      document.getElementById(\'mvNextRun\').textContent = \'Next run \u2192 \' + d.next_run.human + \' MYT (\' + fmtNextCountdown(d.next_run.epoch) + \')\';
    } else if (d.cron) {
      window._mvNextEpoch = null;
      document.getElementById(\'mvNextRun\').textContent = \'Next run: cron present but could not compute next time\';
    } else {
      window._mvNextEpoch = null;
      document.getElementById(\'mvNextRun\').textContent = \'Next run: not scheduled \u2014 manual runs only\';
    }
    mvJobRender(d.run);
    mvRenderLogs(d.run.logs || []);
    await loadMvnbcFiles();
    if (d.run.running) mvPoll();
  } catch (e) { console.error(e); }
}
function mvPoll() {
  if (mvPollTimer) clearTimeout(mvPollTimer);
  mvPollTimer = setTimeout(async () => {
    if (CURRENT_VIEW !== \'mvnbc\') return;
    try {
      const res = await fetch(\'/api/mvnbc/run-status\');
      const r = await res.json();
      mvJobRender(r);
      mvRenderLogs(r.logs || []);
      if (r.running) mvPoll();
      else loadMvnbc();
    } catch (e) { mvPoll(); }
  }, 2500);
}
async function mvRun() {
  try {
    const res = await fetch(\'/api/mvnbc/run\', { method: \'POST\', headers: { \'X-CSRF-Token\': CSRF } });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'run failed\', \'err\'); return; }
    toast(\'MVNBC backup started (pid \' + d.pid + \')\', \'ok\');
    mvJobRender({ running: true, ok: 0, fail: 0, done: false, log: null, lines: [\'[launching MVNBC.sh --auto...]\'] });
    mvPoll();
  } catch (e) { toast(\'run failed: \' + e, \'err\'); }
}
function fmtNextCountdown(epoch) {
  let s = Math.max(0, Math.floor(epoch - Date.now()/1000));
  const d = Math.floor(s/86400); s -= d*86400;
  const h = Math.floor(s/3600); s -= h*3600;
  const m = Math.floor(s/60); s -= m*60;
  if (d > 0) return \'in \' + d + \'d \' + h + \'h \' + m + \'m\';
  if (h > 0) return \'in \' + h + \'h \' + m + \'m \' + s + \'s\';
  if (m > 0) return \'in \' + m + \'m \' + s + \'s\';
  return \'in \' + s + \'s\';
}
setInterval(() => {
  if (CURRENT_VIEW !== \'mvnbc\') return;
  const el = document.getElementById(\'mvNextRun\');
  if (!el || !window._mvNextEpoch) return;
  const base = el.textContent.split(\' MYT\')[0];
  el.textContent = base + \' MYT (\' + fmtNextCountdown(window._mvNextEpoch) + \')\';
}, 1000);
function mvSearch(v) {
  window.mvFilesQ = v;
  if (mvSearchTimer) clearTimeout(mvSearchTimer);
  mvSearchTimer = setTimeout(loadMvnbcFiles, 300);
}
async function mvView(p, kind) {
  try {
    const res = await fetch(\'/api/mvnbc/file?k=\' + (kind || \'b\') + \'&p=\' + encodeURIComponent(p));
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'view failed\', \'err\'); return; }
    document.getElementById(\'mvViewName\').textContent = d.name + \' / \' + d.size + \' KB\';
    document.getElementById(\'mvViewDl\').setAttribute(\'href\', \'/api/mvnbc/download?k=\' + (kind || \'b\') + \'&p=\' + encodeURIComponent(p));
    document.getElementById(\'mvViewBody\').textContent = d.content;
    document.getElementById(\'mvViewer\').style.display = \'block\';
    document.getElementById(\'mvViewer\').scrollIntoView({ behavior: \'smooth\', block: \'start\' });
  } catch (e) { toast(\'view failed\', \'err\'); }
}
function mvDl(p, kind) {
  window.location = \'/api/mvnbc/download?k=\' + (kind || \'b\') + \'&p=\' + encodeURIComponent(p);
}
async function mvDel(p, kind) {
  if (!confirm(\'Delete \' + p + \' ? This cannot be undone.\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/delete\', {
      method: \'POST\',
      headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF },
      body: JSON.stringify({ k: kind || \'b\', p: p })
    });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'delete failed\', \'err\'); return; }
    toast(d.message || \'Deleted\', \'ok\');
    loadMvnbc();
  } catch (e) { toast(\'delete failed\', \'err\'); }
}
document.addEventListener(\'click\', e => {
  const b = e.target.closest(\'#mvFilesWrap button[data-act], #mvLogsTable button[data-act]\');
  if (!b) return;
  const p = b.getAttribute(\'data-p\'), k = b.getAttribute(\'data-k\'), act = b.getAttribute(\'data-act\');
  if (act === \'view\') mvView(p, k);
  else if (act === \'dl\') mvDl(p, k);
  else if (act === \'del\') mvDel(p, k);
});

/* ---------- MVNBC PHASE 2: compare / devices / alerts / schedule ---------- */
let mvDevMode = \'add\', mvCmpLoaded = false;
/* ---------- templates + script editor ---------- */
let MVTMPLS=[];
async function mvTmplLoad(){
  const tb=document.getElementById('mvTmplTable');
  tb.innerHTML='<tr><td colspan="5" class="dim">loading…</td></tr>';
  try{
    const res=await fetch('/api/mvnbc/templates');
    if(res.status===401){window.location='/login';return;}
    const d=await res.json();
    MVTMPLS=d.templates||[];
    try{var _tc=document.getElementById(\'mvTmplCount\');if(_tc)_tc.textContent=MVTMPLS.length+\' template(s)\';}catch(e){}
    const from=document.getElementById('mvTmplFrom');
    from.innerHTML='<option value="">blank</option>'+MVTMPLS.map(t=>'<option value="'+esc(t.vendor)+'">'+esc(t.name)+'</option>').join('');
    if(!MVTMPLS.length){ tb.innerHTML='<tr><td colspan="5" class="dim">no templates</td></tr>'; return; }
    tb.innerHTML='';
    for(const t of MVTMPLS){
      const lock=t.builtin?'<span class="badge stale">builtin</span>':'<span class="badge connected">custom</span>';
      const tr=document.createElement('tr');
      tr.innerHTML='<td class="mono bright">'+esc(t.name)+'</td><td class="mono dim">'+esc(t.vendor)+'</td><td class="mono dim">'+fmtBytes(t.size)+'</td><td class="mono dim" style="font-size:.78em;">'+esc(t.mtime_h||'')+'</td><td style="text-align:right; white-space:nowrap;">'+lock+' <button class="btn xs" data-v="'+esc(t.vendor)+'" onclick="mvTmplEdit(this.dataset.v)">Edit</button>'+(t.builtin?'':' <button class="btn xs danger" data-v="'+esc(t.vendor)+'" onclick="mvTmplDel(this.dataset.v)">Del</button>')+'</td>';
      tb.appendChild(tr);
    }
  }catch(e){ tb.innerHTML='<tr><td colspan="5" class="dim">load failed</td></tr>'; }
}
function mvTmplNew(){
  document.getElementById('mvTmplEdit').style.display='block';
  document.getElementById('mvTmplTitle').textContent='New Template';
  document.getElementById('mvTmplVendor').value='';
  document.getElementById('mvTmplVendor').disabled=false;
  document.getElementById('mvTmplBody').value='';
  document.getElementById('mvTmplMsg').textContent='';
  document.getElementById('mvTmplEdit').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function mvTmplEdit(vendor){
  const t=MVTMPLS.find(x=>x.vendor===vendor); if(!t) return;
  document.getElementById('mvTmplEdit').style.display='block';
  document.getElementById('mvTmplTitle').textContent='Edit '+t.name+(t.builtin?' (builtin — save as new name to fork)':'');
  const vin=document.getElementById('mvTmplVendor');
  vin.value=t.vendor; vin.disabled=!!t.builtin;
  document.getElementById('mvTmplBody').value=t.content||'';
  document.getElementById('mvTmplMsg').textContent=t.builtin?'builtin is locked — change slug to fork':'';
  document.getElementById('mvTmplEdit').scrollIntoView({behavior:'smooth',block:'nearest'});
}
document.addEventListener('change',e=>{
  if(e.target&&e.target.id==='mvTmplFrom'){
    const v=e.target.value;
    if(!v) return;
    const t=MVTMPLS.find(x=>x.vendor===v);
    if(t) document.getElementById('mvTmplBody').value=t.content||'';
  }
});
async function mvTmplSave(){
  const msg=document.getElementById('mvTmplMsg'); msg.textContent='saving…';
  try{
    const res=await fetch('/api/mvnbc/templates/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({vendor:document.getElementById('mvTmplVendor').value,content:document.getElementById('mvTmplBody').value})});
    const d=await res.json();
    if(d.ok){ msg.textContent='saved ✓'; toast(d.message||'saved','ok'); document.getElementById('mvTmplEdit').style.display='none'; mvTmplLoad(); mvLoadDevices(); }
    else msg.textContent=d.error||'failed';
  }catch(e){ msg.textContent='request failed'; }
}
async function mvTmplDel(vendor){
  if(!confirm('Delete template '+vendor+'.exp?')) return;
  try{
    const res=await fetch('/api/mvnbc/templates/delete',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({vendor:vendor})});
    const d=await res.json();
    if(d.ok){ toast('deleted','ok'); mvTmplLoad(); mvLoadDevices(); }
    else toast(d.error||'failed','err');
  }catch(e){ toast('failed: '+e,'err'); }
}
async function mvScriptLoad(){
  const ta=document.getElementById('mvScriptBody'), msg=document.getElementById('mvScriptMsg');
  msg.textContent='loading…';
  try{
    const res=await fetch('/api/mvnbc/script');
    const d=await res.json();
    if(d.ok){ ta.value=d.content; msg.textContent=(d.size/1024).toFixed(1)+' KB loaded'; }
    else msg.textContent=d.error||'failed';
  }catch(e){ msg.textContent='request failed'; }
}
async function mvScriptSave(){
  const msg=document.getElementById('mvScriptMsg'); msg.textContent='saving…';
  try{
    const res=await fetch('/api/mvnbc/script/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({content:document.getElementById('mvScriptBody').value})});
    const d=await res.json();
    if(d.ok){ msg.textContent='saved ✓ ('+(d.backup||'no backup')+')'; toast(d.message||'saved','ok'); }
    else msg.textContent=d.error||'failed';
  }catch(e){ msg.textContent='request failed'; }
}

function mvSection(s) {
  if (s === \'tmpl\') { try{ mvTmplLoad(); }catch(e){} }
  document.querySelectorAll(\'#mvSubNav .mvsub\').forEach(b => b.classList.toggle(\'active\', b.dataset.s === s));
  document.querySelectorAll(\'#mvnbcTab .mvsec\').forEach(d => { d.style.display = d.dataset.mvs === s ? \'block\' : \'none\'; });
  const v = document.getElementById(\'mvViewer\');
  document.querySelectorAll(\'#mvnbcTab > .section:not([data-mvs])\').forEach(d => {
    if (d.id === \'mvViewer\') return;
    d.style.display = s === \'ov\' ? \'block\' : \'none\';
  });
  if (v && s !== \'ov\') v.style.display = \'none\';
  if (s === \'cmp\') mvCmpInit();
  else if (s === \'dev\') mvLoadDevices();
  else if (s === \'cfg\') {
    // belt-and-braces: force the known panels visible even if a stale
    // cached copy of this script runs against mismatched markup.
    [\'block-mvcfgpolicy\',\'block-mvcfgalerts\',\'block-mvtelegram\',\'block-mvcfgschedule\',\'block-mvretention\'].forEach(id => {
      try { const el = document.getElementById(id); if (el) el.style.display = \'block\'; } catch (e) {}
    });
    const nCfg = document.querySelectorAll(\'#mvnbcTab .mvsec[data-mvs="cfg"]\').length;
    if (!nCfg) {
      toast(\'stale page cached — hard refresh with Ctrl+Shift+R\', \'err\');
      mvShowErr(\'ALERTS PANELS NOT FOUND in this loaded page (stale cache). Hard-refresh with Ctrl+Shift+R, or open the portal in a private/incognito window and log in again.\');
    } else {
      const v = document.getElementById(\'jsErr\');
      if (v) v.style.display = \'none\';
    }
    mvAlertsLoad(); mvScheduleLoad(); mvRetentionLoad();
  }
  else if (s === \'alt\') mvAlertsLoad();
  else if (s === \'sch\') mvScheduleLoad();
  const nav = document.getElementById(\'mvSubNav\');
  if (nav && s !== \'ov\') nav.scrollIntoView({ behavior: \'smooth\', block: \'start\' });
}
async function mvCmpInit() {
  if (mvCmpLoaded) return;
  try {
    const res = await fetch(\'/api/mvnbc/files\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const opts = [];
    for (const g of (d.groups || [])) for (const f of (g.files || [])) opts.push(g.vendor + \'/\' + f.name);
    const a = document.getElementById(\'mvCmpA\'), b = document.getElementById(\'mvCmpB\');
    a.innerHTML = \'\'; b.innerHTML = \'\';
    opts.forEach((p, i) => {
      a.innerHTML += \'<option value="\' + esc(p) + \'">\' + esc(p) + \'</option>\';
      b.innerHTML += \'<option value="\' + esc(p) + \'"\' + (i === 1 ? \' selected\' : \'\') + \'>\' + esc(p) + \'</option>\';
    });
    if (!opts.length) { a.innerHTML = \'<option value="">no backups yet</option>\'; b.innerHTML = \'<option value="">no backups yet</option>\'; }
    else if (opts.length === 1) b.selectedIndex = 0;
    mvCmpLoaded = true;
  } catch (e) { toast(\'compare init failed\', \'err\'); }
}
async function mvCompareRun() {
  const a = document.getElementById(\'mvCmpA\').value, b = document.getElementById(\'mvCmpB\').value;
  const out = document.getElementById(\'mvCmpOut\'), stat = document.getElementById(\'mvCmpStat\');
  if (!a || !b) { toast(\'pick two backups first\', \'err\'); return; }
  if (a === b) { toast(\'pick two DIFFERENT backups\', \'err\'); return; }
  stat.textContent = \'diffing...\'; out.style.display = \'none\'; out.innerHTML = \'\';
  try {
    const res = await fetch(\'/api/mvnbc/compare\', {
      method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF },
      body: JSON.stringify({ a: a, b: b })
    });
    const d = await res.json();
    if (!d.ok) { stat.textContent = \'\'; toast(d.error || \'compare failed\', \'err\'); return; }
    if (d.identical) { stat.textContent = \'identical - no differences between \' + d.a + \' and \' + d.b; return; }
    stat.textContent = d.a + \'  vs  \' + d.b + \'   (+\' + d.added + \' added / -\' + d.removed + \' removed)\' + (d.truncated ? \'  [truncated to 2000 lines]\' : \'\');
    let html = \'\';
    for (const ln of (d.lines || [])) {
      const e = esc(ln);
      if (ln.startsWith(\'+++\') || ln.startsWith(\'---\')) html += \'<span class="mvhd">\' + e + \'</span>\\n\';
      else if (ln.startsWith(\'@@\')) html += \'<span class="mvhunk">\' + e + \'</span>\\n\';
      else if (ln.startsWith(\'+\')) html += \'<span class="mvadd">\' + e + \'</span>\\n\';
      else if (ln.startsWith(\'-\')) html += \'<span class="mvdel">\' + e + \'</span>\\n\';
      else html += e + \'\\n\';
    }
    out.innerHTML = html;
    out.style.display = \'block\';
  } catch (e) { stat.textContent = \'\'; toast(\'compare failed\', \'err\'); }
}
async function mvLoadDevices() {
  try {
    const res = await fetch(\'/api/mvnbc/devices\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const tb = document.getElementById(\'mvInvTable\');
    tb.innerHTML = \'\';
    for (const r of (d.devices || [])) {
      tb.innerHTML += \'<tr>\' +
        \'<td class="bright mono">\' + esc(r.vendor) + \'</td>\' +
        \'<td class="mono">\' + esc(r.ip) + \'</td>\' +
        \'<td class="mono dim">\' + esc(r.user || \'-\') + \'</td>\' +
        \'<td class="mono dim">\' + (r.has_pass ? \'&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;\' : \'<span class="dim">not set</span>\') + \'</td>\' +
        \'<td style="text-align:right; white-space:nowrap;">\' +
          \'<button class="btn xs" data-act="devedit" data-v="\' + esc(r.vendor) + \'" data-i="\' + esc(r.ip) + \'" data-u="\' + esc(r.user || \'\') + \'">Edit</button> \' +
          \'<button class="btn xs danger" data-act="devdel" data-v="\' + esc(r.vendor) + \'" data-i="\' + esc(r.ip) + \'">Del</button>\' +
        \'</td></tr>\';
    }
    if (!tb.innerHTML) tb.innerHTML = \'<tr><td colspan="5" class="dim">no devices yet - click Add Device</td></tr>\';
    const vs = document.getElementById(\'mvDevVendor\');
    vs.innerHTML = \'\';
    for (const v of (d.vendors || [])) vs.innerHTML += \'<option value="\' + esc(v) + \'">\' + esc(v) + \'</option>\';
  } catch (e) { toast(\'devices load failed\', \'err\'); }
}
function mvDevForm() {
  mvDevMode = \'add\';
  document.getElementById(\'mvDevEditTitle\').textContent = \'Add Device\';
  document.getElementById(\'mvDevSaveBtn\').innerHTML = \'&#128190; Save Device\';
  document.getElementById(\'mvDevIp\').value = \'\';
  document.getElementById(\'mvDevUser\').value = \'\';
  document.getElementById(\'mvDevPass\').value = \'\';
  document.getElementById(\'mvDevEdit\').style.display = \'block\';
  document.getElementById(\'mvDevEdit\').scrollIntoView({ behavior: \'smooth\', block: \'nearest\' });
}
function mvDevEdit(vendor, ip, user) {
  mvDevMode = \'edit\';
  document.getElementById(\'mvDevEditTitle\').textContent = \'Edit Device \' + vendor + \' (\' + ip + \')\';
  document.getElementById(\'mvDevSaveBtn\').innerHTML = \'&#128190; Update Device\';
  document.getElementById(\'mvDevVendor\').value = vendor;
  document.getElementById(\'mvDevIp\').value = ip;
  document.getElementById(\'mvDevUser\').value = user;
  document.getElementById(\'mvDevPass\').value = \'\';
  document.getElementById(\'mvDevEdit\').style.display = \'block\';
  document.getElementById(\'mvDevEdit\').scrollIntoView({ behavior: \'smooth\', block: \'nearest\' });
}
function mvDevFormClose() { document.getElementById(\'mvDevEdit\').style.display = \'none\'; }
async function mvDevSave() {
  const body = {
    vendor: document.getElementById(\'mvDevVendor\').value,
    ip: document.getElementById(\'mvDevIp\').value.trim(),
    user: document.getElementById(\'mvDevUser\').value.trim(),
    pass: document.getElementById(\'mvDevPass\').value,
    enable: \'\'
  };
  const url = mvDevMode === \'edit\' ? \'/api/mvnbc/devices/update\' : \'/api/mvnbc/devices/add\';
  try {
    const res = await fetch(url, { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify(body) });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'save failed\', \'err\'); return; }
    toast(d.message || \'Saved\', \'ok\');
    mvDevFormClose();
    mvLoadDevices();
  } catch (e) { toast(\'save failed\', \'err\'); }
}
async function mvDevDel(vendor, ip) {
  if (!confirm(\'Remove device \' + vendor + \' (\' + ip + \') ?\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/devices/delete\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ vendor: vendor, ip: ip }) });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'delete failed\', \'err\'); return; }
    toast(d.message || \'Deleted\', \'ok\');
    mvLoadDevices();
  } catch (e) { toast(\'delete failed\', \'err\'); }
}
async function mvAlertsLoad() {
  try {
    const res = await fetch(\'/api/mvnbc/alerts\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    const e = d.email || {}, t = d.telegram || {};
    document.getElementById(\'mvEmOn\').checked = !!e.enabled;
    document.getElementById(\'mvEmHost\').value = e.smtp_host || \'\';
    document.getElementById(\'mvEmPort\').value = e.smtp_port || 587;
    document.getElementById(\'mvEmSec\').value = e.smtp_secure || \'tls\';
    document.getElementById(\'mvEmUser\').value = e.username || \'\';
    document.getElementById(\'mvEmPass\').value = \'\';
    document.getElementById(\'mvEmPass\').placeholder = e.has_pass ? \'saved (leave blank to keep)\' : \'not set yet\';
    document.getElementById(\'mvEmFrom\').value = e.from || \'\';
    document.getElementById(\'mvEmTo\').value = e.to || \'\';
    document.getElementById(\'mvTgOn\').checked = !!t.enabled;
    document.getElementById(\'mvTgToken\').value = \'\';
    document.getElementById(\'mvTgToken\').placeholder = t.has_token ? \'saved (leave blank to keep)\' : \'not set yet\';
    document.getElementById(\'mvTgChat\').value = t.chat_id || \'\';
    const _nv = d.notify_on || \'failure\';
    document.getElementById(\'mvAltWhen\').value = _nv;
    const _nr = document.querySelector(\'input[name="mvNotifyOn"][value="\' + _nv + \'"]\');
    if (_nr) _nr.checked = true;
    mvAltBadge(); mvNotifyCards();
  } catch (e) { toast(\'alerts load failed\', \'err\'); }
}
function mvAltBadge() {
  const b = document.getElementById(\'mvAltState\');
  const n = (document.getElementById(\'mvEmOn\').checked ? 1 : 0) + (document.getElementById(\'mvTgOn\').checked ? 1 : 0);
  b.className = \'badge \' + (n ? \'connected\' : \'disconnected\');
  b.textContent = n === 2 ? \'EMAIL + TELEGRAM\' : (n ? (document.getElementById(\'mvEmOn\').checked ? \'EMAIL ON\' : \'TELEGRAM ON\') : \'ALL OFF\');
}
function mvNotifyCards() {
  [\'failure\',\'always\',\'never\'].forEach(v => {
    const card = document.getElementById(\'mvNotifyCard-\' + v);
    const radio = document.querySelector(\'input[name="mvNotifyOn"][value="\' + v + \'"]\');
    if (card) card.classList.toggle(\'sel\', !!(radio && radio.checked));
  });
}
async function mvAlertsSave() {
  const _pn = document.querySelector(\'input[name="mvNotifyOn"]:checked\');
  const _pv = _pn ? _pn.value : (document.getElementById(\'mvAltWhen\').value || \'failure\');
  const body = {
    notify_on: _pv,
    email: {
      enabled: document.getElementById(\'mvEmOn\').checked,
      smtp_host: document.getElementById(\'mvEmHost\').value.trim(),
      smtp_port: document.getElementById(\'mvEmPort\').value.trim(),
      smtp_secure: document.getElementById(\'mvEmSec\').value,
      username: document.getElementById(\'mvEmUser\').value.trim(),
      password: document.getElementById(\'mvEmPass\').value,
      from: document.getElementById(\'mvEmFrom\').value.trim(),
      to: document.getElementById(\'mvEmTo\').value.trim()
    },
    telegram: {
      enabled: document.getElementById(\'mvTgOn\').checked,
      bot_token: document.getElementById(\'mvTgToken\').value,
      chat_id: document.getElementById(\'mvTgChat\').value.trim()
    }
  };
  try {
    const res = await fetch(\'/api/mvnbc/alerts/save\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify(body) });
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'save failed\', \'err\'); return; }
    toast(d.message || \'Saved\', \'ok\');
    document.getElementById(\'mvAltHint\').textContent = \'saved \' + new Date().toLocaleTimeString();
    mvAltBadge();
  } catch (e) { toast(\'save failed\', \'err\'); }
}
async function mvAlertTest(ch) {
  toast(\'sending test \' + ch + \'...\', \'ok\');
  const hint = document.getElementById(\'mvAltHint\');
  if (hint) hint.textContent = \'sending test \' + ch + \'...\';
  try {
    const res = await fetch(\'/api/mvnbc/alerts/test\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ channel: ch }) });
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    toast(d.message || (d.ok ? \'sent\' : \'failed\'), d.ok ? \'ok\' : \'err\');
    if (hint) hint.textContent = ch + \': \' + (d.message || (d.ok ? \'sent\' : \'failed\')) + \' (\' + new Date().toLocaleTimeString() + \')\';
  } catch (e) { toast(\'test failed\', \'err\'); if (hint) hint.textContent = ch + \': request failed\'; }
}
document.addEventListener(\'click\', e => {
  const b = e.target.closest(\'#mvInvTable button[data-act]\');
  if (!b) return;
  const act = b.getAttribute(\'data-act\');
  if (act === \'devedit\') mvDevEdit(b.getAttribute(\'data-v\'), b.getAttribute(\'data-i\'), b.getAttribute(\'data-u\'));
  else if (act === \'devdel\') mvDevDel(b.getAttribute(\'data-v\'), b.getAttribute(\'data-i\'));
});
document.addEventListener(\'change\', e => {
  if (e.target && (e.target.id === \'mvEmOn\' || e.target.id === \'mvTgOn\')) mvAltBadge();
  if (e.target && e.target.name === \'mvNotifyOn\') mvNotifyCards();
  if (e.target && e.target.name === \'mvSch\') {
    document.getElementById(\'mvSchCustomWrap\').style.display = (document.querySelector(\'input[name="mvSch"]:checked\').value === \'__custom__\') ? \'block\' : \'none\';
  }
});
async function mvScheduleLoad() {
  const box = document.getElementById(\'mvSchCurrent\'), st = document.getElementById(\'mvSchState\');
  const tzEl = document.getElementById(\'mvSchTz\');
  const setTz = (pinned) => { if (tzEl) tzEl.textContent = \'timezone: Asia/Kuala_Lumpur (MYT)\' + (pinned === true ? \' — pinned ✓\' : (pinned === false ? \' — NOT pinned (schedule fires in UTC!) — re-save below\' : \'\')); };
  try {
    const res = await fetch(\'/api/mvnbc/schedule\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    setTz(d.tz_pinned);
    if (!d.ok || !d.available) {
      st.className = \'badge disconnected\'; st.textContent = \'NO CRON\';
      box.style.display = \'block\'; box.textContent = \'crontab unavailable on this host - runs are manual from Overview.\';
      return;
    }
    if (d.job) {
      st.className = \'badge connected\'; st.textContent = \'SCHEDULED\';
      const nxt = d.next_run_human ? \'\\nNext run → \' + d.next_run_human + \' MYT\' + (d.next_run ? \' (\' + fmtNextCountdown(d.next_run) + \')\' : \'\') : \'\';
      box.style.display = \'block\'; box.textContent = \'current: \' + d.job + nxt;
      if (d.next_run) window._mvNextEpoch = d.next_run;
    } else {
      st.className = \'badge stale\'; st.textContent = \'NOT SET\';
      box.style.display = \'block\'; box.textContent = \'no MVNBC schedule installed - pick one below and Save.\';
    }
  } catch (e) { toast(\'schedule load failed\', \'err\'); }
}
function mvSchPicked() {
  const v = document.querySelector(\'input[name="mvSch"]:checked\').value;
  return v === \'__custom__\' ? document.getElementById(\'mvSchCustom\').value.trim() : v;
}
async function mvScheduleSave() {
  const cron = mvSchPicked();
  if (!cron) { toast(\'enter a cron expression first\', \'err\'); return; }
  try {
    const res = await fetch(\'/api/mvnbc/schedule/save\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({ cron: cron }) });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'save failed\', \'err\'); return; }
    toast(d.message || \'Saved\', \'ok\');
    document.getElementById(\'mvSchHint\').textContent = cron + \'  saved \' + new Date().toLocaleTimeString();
    mvScheduleLoad();
  } catch (e) { toast(\'save failed\', \'err\'); }
}
async function mvScheduleRemove() {
  if (!confirm(\'Remove the auto-backup schedule ? Manual runs still work.\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/schedule/remove\', { method: \'POST\', headers: { \'X-CSRF-Token\': CSRF } });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'remove failed\', \'err\'); return; }
    toast(d.message || \'Removed\', \'ok\');
    mvScheduleLoad();
  } catch (e) { toast(\'remove failed\', \'err\'); }
}
async function mvRetentionLoad() {
  try {
    const res = await fetch(\'/api/mvnbc/retention\');
    if (res.status === 401) { window.location = \'/login\'; return; }
    const d = await res.json();
    if (!d.ok) return;
    const r = d.retention || {};
    document.getElementById(\'mvRetBackups\').value = r.keep_backups || 50;
    document.getElementById(\'mvRetLogs\').value = r.keep_logs || 30;
    document.getElementById(\'mvRetAge\').value = r.max_age_days || 30;
    document.getElementById(\'mvRetAuto\').checked = !!r.auto_prune_30d;
    const c = d.counts || {};
    document.getElementById(\'mvRetCounts\').textContent = \'now: \' + (c.backups||0) + \' backup file(s) / \' + (c.logs||0) + \' run log(s)\';
    const wd = d.would_delete || {};
    const st = document.getElementById(\'mvRetState\');
    const n = (wd.backups||[]).length + (wd.logs||[]).length;
    st.className = \'badge \' + (n ? \'stale\' : \'connected\');
    st.textContent = n ? (n + \' to prune\') : \'CLEAN\';
  } catch(e) { console.error(e); }
}
async function mvRetentionSave() {
  const body = {
    keep_backups: parseInt(document.getElementById(\'mvRetBackups\').value)||50,
    keep_logs: parseInt(document.getElementById(\'mvRetLogs\').value)||30,
    max_age_days: parseInt(document.getElementById(\'mvRetAge\').value)||30,
    auto_prune_30d: document.getElementById(\'mvRetAuto\').checked
  };
  try {
    const res = await fetch(\'/api/mvnbc/retention/save\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify(body) });
    const d = await res.json();
    if (!d.ok) { toast(d.error || \'save failed\', \'err\'); return; }
    toast(d.message || \'Saved\', \'ok\');
    document.getElementById(\'mvRetHint\').textContent = \'saved \' + new Date().toLocaleTimeString();
    mvRetentionLoad();
  } catch(e) { toast(\'save failed\', \'err\'); }
}
async function mvRetentionPreview() {
  try {
    const res = await fetch(\'/api/mvnbc/retention/prune\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({dry_run: true}) });
    const d = await res.json();
    const box = document.getElementById(\'mvRetPreview\');
    const bl = (d.backups||[]), ll = (d.logs||[]);
    if (!bl.length && !ll.length) { box.style.display = \'block\'; box.textContent = \'nothing to prune - within retention limits\'; return; }
    box.style.display = \'block\';
    box.textContent = \'would delete \' + bl.length + \' backup(s) + \' + ll.length + \' log(s):\\n\' + bl.slice(0,20).join(\'\\n\') + (bl.length>20?\'\\n...+\'+(bl.length-20)+\' more\':\'\') + \'\\n\' + ll.slice(0,20).join(\'\\n\');
  } catch(e) { toast(\'preview failed\', \'err\'); }
}
async function mvRetentionPrune() {
  const box = document.getElementById(\'mvRetPreview\');
  const bl = (box.textContent || \'\');
  if (!confirm(\'Prune files beyond retention? This cannot be undone.\')) return;
  try {
    const res = await fetch(\'/api/mvnbc/retention/prune\', { method: \'POST\', headers: { \'Content-Type\': \'application/json\', \'X-CSRF-Token\': CSRF }, body: JSON.stringify({dry_run: false}) });
    const d = await res.json();
    toast((d.deleted||0) + \' deleted, \' + (d.failed||0) + \' failed\', (d.failed ? \'warn\' : \'ok\'));
    mvRetentionLoad(); loadMvnbc();
  } catch(e) { toast(\'prune failed\', \'err\'); }
}
document.querySelectorAll(\'#mvnbcTab .mvsec\').forEach(d => { d.style.display = \'none\'; });
function mvOpenCfg() { showTab(\'mvnbc\'); mvSection(\'cfg\'); const el = document.getElementById(\'block-mvcfgalerts\') || document.getElementById(\'mvSubNav\'); if (el && el.classList) el.classList.remove(\'collapsed\'); if (el) setTimeout(() => el.scrollIntoView({ behavior: \'smooth\', block: \'start\' }), 150); }
if (window.location.hash === \'#mvnbc-cfg\') { setTimeout(mvOpenCfg, 400); }
window.addEventListener(\'hashchange\', () => { if (window.location.hash === \'#mvnbc-cfg\') mvOpenCfg(); });
\
/* ---------- init ---------- */
loadData();
loadWGConf();
loadWgPeers();
loadBgpCtl();
loadBackups();
applySecState();
portalTabsLoad();
let smbLoaded = false;
</script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090, debug=False)