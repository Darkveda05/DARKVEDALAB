#!/usr/bin/env python3
"""DARKVEDA LAB Telegram ops bot (@Darkv3dabot) — full control + screenshot inbox.

Polls Telegram getUpdates (stdlib only), restricted to the managed channel/group
plus an admin allowlist for write commands. Photos/screenshots are saved to
bot_inbox/ so they can be analysed later (e.g. forwarded to OpenCode).

Commands (in the managed chat):
  /help                       this help
  /id                         show your Telegram user id + chat id (for allowlisting)
  /status                     WireGuard + backup + schedule summary
  /mvnbc                      device backup health
  /run                        run MVNBC backup now (admin, background + summary)
  /test email|telegram        send a test alert (admin)
  /schedule                   show current schedule
  /schedule set <cron5>       stage a new schedule, confirm with /yes (admin)
  /schedule remove            stage removal, confirm with /yes (admin)
  /yes | /cancel              confirm / abort a staged action
  /prune                      retention dry-run preview (admin)
  /prune_yes                  execute prune for real (admin)
  /photos                     list recent screenshots in bot_inbox
Send a photo/screenshot      saved to bot_inbox/, bot replies with filename.

Write commands require your numeric Telegram user id in bot_admins.json:
  {"admins": [123456789]}
Get your id via /id, then:  echo '{"admins":[ID]}' > bot_admins.json
If bot_admins.json is missing/empty, write commands are refused (fail-closed).
"""
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
# Container-friendly: MVNBC_DIR env (default keeps historic host path).
MVNBC_DIR = os.environ.get("MVNBC_DIR", "/root/MVNBC_Dashboard")
SETTINGS = os.path.join(MVNBC_DIR, "config", "settings.json")
ADMINS_FILE = os.path.join(BASE, "bot_admins.json")
INBOX = os.path.join(BASE, "bot_inbox")
MVNBC_SCRIPT = os.path.join(MVNBC_DIR, "MVNBC.sh")
MVNBC_LOGS = os.path.join(MVNBC_DIR, "logs")
MVNBC_BACKUPS = os.path.join(MVNBC_DIR, "backups")
MVNBC_CONF = os.path.join(MVNBC_DIR, "config", "devices.conf")
OFFSET_FILE = os.path.join(BASE, ".bot_offset")

os.makedirs(INBOX, exist_ok=True)

pending = {}  # chat_id -> (action, payload, expires_ts)


def load_settings():
    try:
        with open(SETTINGS) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def bot_conf():
    s = load_settings()
    tg = s.get("telegram", {})
    return (tg.get("bot_token") or "").strip(), (tg.get("chat_id") or "").strip()


def load_admins():
    try:
        with open(ADMINS_FILE) as fh:
            d = json.load(fh)
        ids = d.get("admins", []) if isinstance(d, dict) else []
        return {int(x) for x in ids}
    except (OSError, ValueError):
        return set()


def api(method, payload=None, timeout=30):
    token, _ = bot_conf()
    if not token:
        raise RuntimeError("bot token not configured in settings.json")
    url = "https://api.telegram.org/bot%s/%s" % (token, method)
    data = urllib.parse.urlencode(payload or {}).encode() if payload else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    # Force IPv4 for api.telegram.org (broken IPv6 hangs plain connects;
    # gai.conf also prefers IPv4, this makes it deterministic + fast).
    orig_gai = socket.getaddrinfo

    def _ipv4_only(h, p, family=0, typ=0, proto=0, flags=0):
        try:
            return orig_gai(h, p, socket.AF_INET, typ, proto, flags)
        except socket.gaierror:
            return orig_gai(h, p, family, typ, proto, flags)

    socket.getaddrinfo = _ipv4_only
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    finally:
        socket.getaddrinfo = orig_gai


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send(chat_id, text, parse_html=True):
    text = text if len(text) <= 4000 else text[:3950] + "\n…(truncated)"
    p = {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    if parse_html:
        p["parse_mode"] = "HTML"
    try:
        r = api("sendMessage", p)
        return bool(r.get("ok"))
    except Exception as ex:
        print("send failed: %s" % ex, flush=True)
        return False


def is_managed(chat_id):
    _, managed = bot_conf()
    return str(chat_id) == str(managed)


def is_admin(user_id):
    if user_id == "channel-admin":
        return True  # only channel admins can post to the channel
    try:
        return int(user_id) in load_admins()
    except (TypeError, ValueError):
        return False


def need_admin(chat_id, user_id):
    if is_admin(user_id):
        return True
    admins = load_admins()
    send(chat_id, "⛔ Admin only. Your user id is <code>%s</code>.\n"
                  "Ask the server owner to add it to <code>bot_admins.json</code>:\n"
                  "<code>{\"admins\": [%s]}</code>\n"
                  "Configured admins: %s" % (esc(user_id), esc(user_id),
                                             esc(sorted(admins) or "none yet")))
    return False


# ---------- status helpers ----------
def wg_summary():
    try:
        r = subprocess.run(["wg", "show", "all", "dump"], capture_output=True,
                           text=True, timeout=8)
        peers = [l for l in (r.stdout or "").splitlines() if l and not l.startswith("private")]
        n_peer = len([l for l in peers if l.split("\t")[0] not in ("interface",)])
    except (OSError, subprocess.TimeoutExpired):
        n_peer = -1
    return n_peer


def mvnbc_summary():
    devs = []
    try:
        with open(MVNBC_CONF) as fh:
            for line in fh.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    p = [x.strip() for x in line.split(",")]
                    if len(p) >= 2:
                        devs.append((p[0], p[1]))
    except OSError:
        pass
    ok = fail = 0
    for vendor, ip in devs:
        vdir = os.path.join(MVNBC_BACKUPS, vendor)
        latest = None
        try:
            cands = [f for f in os.listdir(vdir)
                     if f.startswith(ip + "_") and f.endswith(".log")] if os.path.isdir(vdir) else []
            if cands:
                cands.sort(key=lambda f: os.path.getmtime(os.path.join(vdir, f)), reverse=True)
                latest = os.path.join(vdir, cands[0])
        except OSError:
            pass
        if latest and os.path.getsize(latest) > 0:
            ok += 1
        else:
            fail += 1
    return devs, ok, fail


def cron_job():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            return None
        for line in (r.stdout or "").splitlines():
            if line.strip() and not line.strip().startswith("#") and MVNBC_SCRIPT in line:
                return line.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def cmd_status(chat_id):
    n_peer = wg_summary()
    devs, ok, fail = mvnbc_summary()
    job = cron_job()
    lines = ["<b>DARKVEDA LAB status</b>",
             "WireGuard peers: %s" % ("n/a" if n_peer < 0 else n_peer),
             "MVNBC devices: %d (%d ok / %d fail)" % (len(devs), ok, fail)]
    for v, ip in devs:
        lines.append("  • %s %s" % (esc(v), esc(ip)))
    lines.append("Schedule: %s" % esc(job or "not set (manual runs only)"))
    send(chat_id, "\n".join(lines))


def cmd_mvnbc(chat_id):
    devs, ok, fail = mvnbc_summary()
    if not devs:
        send(chat_id, "No devices in devices.conf")
        return
    out = ["<b>MVNBC backup health</b> — %d ok / %d fail" % (ok, fail)]
    for vendor, ip in devs:
        vdir = os.path.join(MVNBC_BACKUPS, vendor)
        try:
            cands = [f for f in os.listdir(vdir)
                     if f.startswith(ip + "_") and f.endswith(".log")] if os.path.isdir(vdir) else []
            cands.sort(key=lambda f: os.path.getmtime(os.path.join(vdir, f)), reverse=True)
            newest = cands[0] if cands else "no backup yet"
        except OSError:
            newest = "no backup yet"
        out.append("  • %s %s → %s" % (esc(vendor), esc(ip), esc(newest)))
    send(chat_id, "\n".join(out))


def _send_email_ipv4(cfg, subject, body):
    """Send email forcing IPv4 (broken IPv6 hangs plain connects).
    Returns (ok, message). Uses getaddrinfo patch so smtplib connects via
    IPv4 while TLS SNI/hostname verification still uses the real hostname."""
    import smtplib
    import ssl
    from email.message import EmailMessage
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
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "MVNBC Backup <%s>" % frm
    msg["To"] = ", ".join(rcpts)
    msg.set_content(body)
    ctx = ssl.create_default_context()
    orig_gai = socket.getaddrinfo

    def _ipv4_only(h, p, family=0, typ=0, proto=0, flags=0):
        try:
            return orig_gai(h, p, socket.AF_INET, typ, proto, flags)
        except socket.gaierror:
            return orig_gai(h, p, family, typ, proto, flags)

    socket.getaddrinfo = _ipv4_only
    try:
        if secure == "ssl":
            sv = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
        else:
            sv = smtplib.SMTP(host, port, timeout=20)
            if secure == "tls":
                sv.starttls(context=ctx)
        if user:
            sv.login(user, pw)
        sv.sendmail(frm, rcpts, msg.as_string())
        sv.quit()
        return True, "Email sent to %s." % ", ".join(rcpts)
    except Exception as ex:
        return False, "Email failed: %s" % ex
    finally:
        socket.getaddrinfo = orig_gai


def run_backup_sync(chat_id):
    send(chat_id, "▶️ Backup started… (this takes ~30s)")
    env = dict(os.environ)
    env["TZ"] = "Asia/Kuala_Lumpur"
    env["MVNBC_NOTIFY"] = "bot"  # portal/bot sends the summary, skip PHP dup
    try:
        subprocess.run(["/bin/bash", MVNBC_SCRIPT, "--auto"], cwd=MVNBC_DIR,
                       env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as ex:
        send(chat_id, "❌ Backup failed to complete: %s" % esc(ex))
        return
    try:
        cands = [n for n in os.listdir(MVNBC_LOGS)
                 if n.startswith("run_") and n.endswith(".log")]
        cands.sort(key=lambda n: os.path.getmtime(os.path.join(MVNBC_LOGS, n)), reverse=True)
        if cands:
            log_path = os.path.join(MVNBC_LOGS, cands[0])
            with open(log_path, errors="replace") as fh:
                lines = fh.read().splitlines()
            ok_l = [l for l in lines if l.startswith("[OK]")]
            fail_l = [l for l in lines if l.startswith("[FAIL]")]
            send(chat_id, "<b>Backup finished</b> — %d ok / %d failed\n%s\n<code>%s</code>"
                 % (len(ok_l), len(fail_l), esc("\n".join("✔ " + l for l in ok_l[-5]) +
                    ("\n" if ok_l and fail_l else "") + "\n".join("✘ " + l for l in fail_l[-5])),
                    esc(cands[0])))
            # Also send email summary (was missing: /run only sent Telegram).
            # Respect Alerts settings (notify_on + email.enabled) like the
            # cron PHP notifier and portal watcher do.
            try:
                s = load_settings()
                mode = (s.get("alerts") or {}).get("notify_on", "failure")
                em = s.get("email") or {}
                should_mail = bool(em.get("enabled")) and mode != "never" and not (
                    mode == "failure" and len(fail_l) == 0)
                email_res = None
                if should_mail:
                    subj = "MVNBC backup %s — %d ok, %d failed" % (
                        "SUCCESS" if not fail_l else "FAILURES", len(ok_l), len(fail_l))
                    body = ("MVNBC backup run summary (via Telegram /run)\n"
                            "Time:    %s MYT\n"
                            "Result:  %d succeeded, %d failed (of %d)\n"
                            "----------------------------------------\n" % (
                                time.strftime("%Y-%m-%d %H:%M:%S"),
                                len(ok_l), len(fail_l), len(ok_l) + len(fail_l)))
                    if fail_l:
                        body += "FAILED:\n" + "".join("  x %s\n" % l for l in fail_l) + "\n"
                    if ok_l:
                        body += "OK:\n" + "".join("  + %s\n" % l for l in ok_l)
                    body += "\nLog: %s\n" % cands[0]
                    ok, m = _send_email_ipv4(em, subj, body)
                    email_res = (ok, m)
                    # append to run log so cron/portal/bot logs look the same
                    try:
                        with open(log_path, "a") as lf:
                            lf.write("notify_run[telegram]: OK — Telegram summary sent via bot.\n")
                            lf.write("notify_run[email]: %s — %s\n" % ("OK" if ok else "ERR", m))
                    except OSError:
                        pass
                    send(chat_id, "✉️ Email %s: %s" % ("sent" if ok else "failed", esc(m)[:300]))
                else:
                    try:
                        with open(log_path, "a") as lf:
                            lf.write("notify_run[telegram]: OK — Telegram summary sent via bot.\n")
                            if not em.get("enabled"):
                                lf.write("notify_run[email]: SKIP — email alerts disabled.\n")
                            else:
                                lf.write("notify_run[email]: SKIP — notify_on=%s, no alert needed.\n" % mode)
                    except OSError:
                        pass
                    if not em.get("enabled"):
                        send(chat_id, "✉️ Email alerts are disabled in settings.")
            except Exception as ex:
                send(chat_id, "⚠️ Email dispatch failed: %s" % esc(ex)[:300])
            return
    except OSError as ex:
        pass
    send(chat_id, "⚠️ Backup process ended but no run log found.")


def valid_cron(expr):
    parts = expr.split()
    return len(parts) == 5 and all(re.match(r"^[\d*/,?\-]+$", p) for p in parts)


def cmd_schedule_show(chat_id):
    job = cron_job()
    send(chat_id, "Schedule: <code>%s</code>\nTimezone: Asia/Kuala_Lumpur (MYT)" % esc(job or "not set"))


def cmd_test(chat_id, channel):
    from urllib.parse import urlencode  # local import, cheap
    s = load_settings()
    if channel == "email":
        if not s.get("email", {}).get("enabled"):
            send(chat_id, "Email alerts are disabled in settings.")
            return
        import smtplib, ssl
        from email.message import EmailMessage
        cfg = s["email"]
        try:
            msg = EmailMessage()
            msg["Subject"] = "MVNBC test alert (via Telegram bot)"
            msg["From"] = "MVNBC Backup <%s>" % (cfg.get("from") or cfg.get("username"))
            msg["To"] = cfg.get("to")
            msg.set_content("Test triggered from Telegram. If you read this, email alerts work.")
            ctx = ssl.create_default_context()
            if (cfg.get("smtp_secure") or "tls") == "ssl":
                sv = smtplib.SMTP_SSL(cfg["smtp_host"], int(cfg.get("smtp_port") or 465), timeout=20, context=ctx)
            else:
                sv = smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port") or 587), timeout=20)
                if (cfg.get("smtp_secure") or "tls") == "tls":
                    sv.starttls(context=ctx)
            if cfg.get("username"):
                sv.login(cfg["username"], cfg.get("password") or "")
            sv.sendmail(cfg.get("from") or cfg["username"], [r.strip() for r in cfg["to"].split(",") if r.strip()], msg.as_string())
            sv.quit()
            send(chat_id, "✉️ Test email sent to %s" % esc(cfg.get("to")))
        except Exception as ex:
            send(chat_id, "❌ Email test failed: %s" % esc(ex)[:400])
    elif channel == "telegram":
        tg = s.get("telegram", {})
        try:
            token = tg.get("bot_token")
            url = "https://api.telegram.org/bot%s/sendMessage" % token
            data = urlencode({"chat_id": tg.get("chat_id"), "text": "<b>MVNBC test alert</b>\nTriggered from Telegram bot. ✅",
                              "parse_mode": "HTML"}).encode()
            urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=15).read()
            send(chat_id, "✅ Test Telegram message sent to the channel.")
        except Exception as ex:
            send(chat_id, "❌ Telegram test failed: %s" % esc(ex)[:400])
    else:
        send(chat_id, "Usage: /test email|telegram")


def cmd_prune_preview(chat_id):
    try:
        r = subprocess.run(["/root/wg-monitor/venv/bin/python", "-c",
                            "import sys; sys.path.insert(0,'/root/wg-monitor');"
                            "import app as A; import json;"
                            "print(json.dumps(A.mvnbc_prune(keep_backups=50,keep_logs=30,max_age_days=30,apply=False)))"],
                           capture_output=True, text=True, timeout=30)
        d = json.loads((r.stdout or "").strip().splitlines()[-1])
        bl, ll = d.get("backups", []), d.get("logs", [])
        if not bl and not ll:
            send(chat_id, "Retention: nothing to prune — within limits.")
            return
        send(chat_id, "Retention preview: %d backup(s) + %d log(s) would be deleted.\nConfirm with /prune_yes\n<code>%s</code>"
             % (len(bl), len(ll), esc("\n".join((bl + ll)[:15]))))
    except Exception as ex:
        send(chat_id, "Prune preview failed: %s" % esc(ex)[:300])


def cmd_prune_exec(chat_id):
    try:
        r = subprocess.run(["/root/wg-monitor/venv/bin/python", "-c",
                            "import sys; sys.path.insert(0,'/root/wg-monitor');"
                            "import app as A; import json;"
                            "print(json.dumps(A.mvnbc_prune(keep_backups=50,keep_logs=30,max_age_days=30,apply=True)))"],
                           capture_output=True, text=True, timeout=60)
        d = json.loads((r.stdout or "").strip().splitlines()[-1])
        send(chat_id, "Prune done: %d deleted, %d failed." % (d.get("deleted", 0), d.get("failed", 0)))
    except Exception as ex:
        send(chat_id, "Prune failed: %s" % esc(ex)[:300])


HELP = ("<b>DARKVEDA LAB bot</b>\n"
        "/status — WG + backup + schedule\n"
        "/mvnbc — backup health per device\n"
        "/run — run backup now (admin)\n"
        "/test email|telegram — test alerts (admin)\n"
        "/schedule — show schedule\n"
        "/schedule set <cron5> — stage + /yes (admin)\n"
        "/schedule remove — stage + /yes (admin)\n"
        "/prune — retention preview (admin)\n"
        "/prune_yes — execute prune (admin)\n"
        "/photos — recent screenshots\n"
        "/id — show your user id\n"
        "📸 Send a screenshot → saved to bot_inbox for analysis.")


def save_photo(chat_id, msg):
    photos = (msg.get("photo") or [])
    if not photos:
        return False
    best = max(photos, key=lambda p: p.get("file_size", 0))
    try:
        meta = api("getFile", {"file_id": best["file_id"]})
        fpath = meta["result"]["file_path"]
        token, _ = bot_conf()
        url = "https://api.telegram.org/file/bot%s/%s" % (token, fpath)
        ext = os.path.splitext(fpath)[1] or ".jpg"
        name = "shot_%s%s" % (time.strftime("%Y%m%d_%H%M%S"), ext)
        dest = os.path.join(INBOX, name)
        urllib.request.urlretrieve(url, dest)
        send(chat_id, "📸 Saved <code>%s</code> (%d KB) to bot_inbox.\nReply with what the issue is and I can pull it up for analysis." %
             (esc(name), os.path.getsize(dest) // 1024))
        return True
    except Exception as ex:
        send(chat_id, "❌ Could not save photo: %s" % esc(ex)[:300])
        return True


def handle_message(msg):
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    user = msg.get("from", {})
    uid = user.get("id")
    if not uid and str(msg.get("sender_chat", {}).get("id")) == str(chat_id):
        # channel post by a channel admin (only admins can post) — trust it
        uid = "channel-admin"
    text = (msg.get("text") or "").strip()
    if not chat_id or not uid:
        return
    if not is_managed(chat_id):
        return  # ignore other chats entirely
    if not text:
        save_photo(chat_id, msg)
        return
    if not text.startswith("/"):
        return
    parts = text.split()
    cmd = parts[0].split("@")[0].lower()
    arg = " ".join(parts[1:]).strip()

    if cmd == "/id":
        send(chat_id, "Your user id: <code>%s</code>\nThis chat id: <code>%s</code>" % (esc(uid), esc(chat_id)))
    elif cmd == "/help" or cmd == "/start":
        send(chat_id, HELP)
    elif cmd == "/status":
        cmd_status(chat_id)
    elif cmd == "/mvnbc":
        cmd_mvnbc(chat_id)
    elif cmd == "/photos":
        try:
            fns = sorted(os.listdir(INBOX), reverse=True)[:10]
            send(chat_id, "Recent screenshots:\n<code>%s</code>" % esc("\n".join(fns) or "inbox empty"))
        except OSError as ex:
            send(chat_id, "Inbox read failed: %s" % esc(ex))
    elif cmd == "/run":
        if need_admin(chat_id, uid):
            run_backup_sync(chat_id)
    elif cmd == "/test":
        if need_admin(chat_id, uid):
            cmd_test(chat_id, arg.lower())
    elif cmd == "/schedule" and not arg:
        cmd_schedule_show(chat_id)
    elif cmd == "/schedule" and arg.startswith("set "):
        if need_admin(chat_id, uid):
            expr = arg[4:].strip()
            if not valid_cron(expr):
                send(chat_id, "Bad cron. Example: <code>0 2 * * *</code>")
            else:
                pending[str(chat_id)] = ("schedule_set", expr, time.time() + 120)
                send(chat_id, "Stage: set schedule to <code>%s</code> (MYT)?\nConfirm with /yes or /cancel" % esc(expr))
    elif cmd == "/schedule" and arg == "remove":
        if need_admin(chat_id, uid):
            pending[str(chat_id)] = ("schedule_remove", "", time.time() + 120)
            send(chat_id, "Stage: remove schedule? Confirm with /yes or /cancel")
    elif cmd == "/schedule":
        send(chat_id, "Usage: /schedule | /schedule set <cron5> | /schedule remove")
    elif cmd == "/yes":
        item = pending.pop(str(chat_id), None)
        if not item or item[2] < time.time():
            send(chat_id, "Nothing staged (or expired).")
            return
        if not need_admin(chat_id, uid):
            return
        action, payload, _ = item
        if action == "schedule_set":
            txt = None
            try:
                r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=8)
                txt = r.stdout if r.returncode == 0 else ""
            except (OSError, subprocess.TimeoutExpired):
                pass
            if txt is None:
                send(chat_id, "crontab unavailable")
                return
            kept = [l for l in txt.splitlines()
                    if l.strip() and MVNBC_SCRIPT not in l
                    and not re.match(r"^\s*(TZ|CRON_TZ)\s*=", l)]
            kept.insert(0, "CRON_TZ=Asia/Kuala_Lumpur")
            kept.insert(0, "TZ=Asia/Kuala_Lumpur")
            kept.append("%s /bin/bash %s --auto" % (payload, MVNBC_SCRIPT))
            r = subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n",
                               capture_output=True, text=True, timeout=8)
            send(chat_id, "✅ Schedule saved: <code>%s</code> (MYT)" % esc(payload) if r.returncode == 0 else "❌ crontab write failed")
        elif action == "schedule_remove":
            try:
                r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=8)
                kept = [l for l in (r.stdout or "").splitlines() if l.strip() and MVNBC_SCRIPT not in l]
                subprocess.run(["crontab", "-"], input=("\n".join(kept) + "\n" if kept else ""),
                               capture_output=True, text=True, timeout=8)
                send(chat_id, "✅ Schedule removed. Manual runs still work.")
            except (OSError, subprocess.TimeoutExpired) as ex:
                send(chat_id, "❌ Remove failed: %s" % esc(ex))
    elif cmd == "/cancel":
        pending.pop(str(chat_id), None)
        send(chat_id, "Cancelled.")
    elif cmd == "/prune":
        if need_admin(chat_id, uid):
            cmd_prune_preview(chat_id)
    elif cmd == "/prune_yes":
        if need_admin(chat_id, uid):
            cmd_prune_exec(chat_id)
    else:
        send(chat_id, "Unknown command. /help for the list.")


def load_offset():
    try:
        return int(open(OFFSET_FILE).read().strip() or "0")
    except (OSError, ValueError):
        return 0


def save_offset(v):
    try:
        open(OFFSET_FILE, "w").write(str(v))
    except OSError:
        pass


def main():
    token, managed = bot_conf()
    if not token or not managed:
        print("telegram not configured (bot_token/chat_id empty in settings.json)", flush=True)
        time.sleep(10)
        return
    print("bot polling as managed chat %s" % managed, flush=True)
    offset = load_offset()
    backoff = 1
    while True:
        try:
            r = api("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message", "channel_post"]}, timeout=40)
            backoff = 1
        except Exception as ex:
            print("poll error: %s" % ex, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        for upd in r.get("result", []):
            offset = max(offset, upd.get("update_id", 0) + 1)
            save_offset(offset)
            msg = upd.get("message") or upd.get("channel_post") or {}
            try:
                handle_message(msg)
            except Exception as ex:
                print("handler error: %s" % ex, flush=True)


if __name__ == "__main__":
    main()
