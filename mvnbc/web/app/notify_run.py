#!/usr/bin/env python3
"""MVNBC run notifier (CLI, self-contained python3 fallback).

Usage:  notify_run.py [path-to-run-log]

Reads the latest (or given) run log, summarises OK/FAIL, and dispatches
Email/Telegram alerts per config/settings.json. Called automatically by
MVNBC.sh at the end of a run when no `php` CLI is available.

Mirrors web/app/notify_run.php (same subject/body/line format) using only
the Python standard library. NEVER exits non-zero (must not fail the run).
"""
import html
import json
import os
import re
import smtplib
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MYT = timezone(timedelta(hours=8), name="MYT")


def base_dir():
    return os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def default_settings():
    return {
        "alerts": {"notify_on": "failure"},
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_secure": "tls",
            "username": "",
            "password": "",
            "from": "",
            "to": "",
        },
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    }


def load_settings():
    cfg = default_settings()
    path = os.path.join(base_dir(), "config", "settings.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            return cfg
        data = json.loads(raw)
    except (OSError, ValueError):
        return cfg
    if not isinstance(data, dict):
        return cfg
    for section, vals in cfg.items():
        sub = data.get(section)
        if isinstance(sub, dict):
            merged = dict(vals)
            merged.update(sub)
            cfg[section] = merged
    return cfg


def latest_run_log(log_dir):
    try:
        names = [n for n in os.listdir(log_dir)
                 if n.startswith("run_") and n.endswith(".log")]
    except OSError:
        return None
    if not names:
        return None
    names.sort(key=lambda n: os.path.getmtime(os.path.join(log_dir, n)),
               reverse=True)
    return os.path.join(log_dir, names[0])


def send_telegram(token, chat_id, text_html):
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    if not token or not chat_id:
        return False, "Bot token and chat ID are required."
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    payload = urlencode({
        "chat_id": chat_id,
        "text": text_html,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = Request(url, data=payload,
                  headers={"Content-Type":
                           "application/x-www-form-urlencoded"})
    try:
        with urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
        try:
            data = json.loads(body)
        except ValueError:
            return False, "Telegram error: bad response"
        if data.get("ok"):
            return True, "Telegram message sent."
        return False, "Telegram error: %s" % data.get("description",
                                                      "unknown")
    except Exception as ex:  # noqa: BLE001 - report, never raise
        return False, "Telegram request failed: %s" % ex


def send_email(ecfg, subject, body_text):
    host = (ecfg.get("smtp_host") or "").strip()
    try:
        port = int(ecfg.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    secure = (ecfg.get("smtp_secure") or "tls").strip().lower()
    user = ecfg.get("username") or ""
    password = ecfg.get("password") or ""
    sender = (ecfg.get("from") or user or "").strip()
    to_raw = (ecfg.get("to") or "").strip()
    if not host or not sender or not to_raw:
        return False, "SMTP host, from, and to are required."
    recipients = [r.strip() for r in to_raw.split(",") if r.strip()]
    if not recipients:
        return False, "No valid recipients."
    # NOTE: unlike the PHP notifier (raw sockets, no Happy Eyeballs),
    # smtplib uses socket.create_connection which iterates all resolved
    # addresses, so broken-IPv6 hosts fall back to IPv4 on their own.
    # TLS is verified against the real hostname (SNI included).
    ctx = ssl.create_default_context()
    try:
        if secure == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
        with smtp:
            smtp.ehlo("mvnbc.local")
            if secure == "tls":
                smtp.starttls(context=ctx)
                smtp.ehlo("mvnbc.local")
            if user:
                smtp.login(user, password)
            from email.message import EmailMessage
            msg = EmailMessage()
            msg["From"] = "MVNBC Backup <%s>" % sender
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg["X-Mailer"] = "MVNBC"
            msg.set_content(body_text)
            smtp.send_message(msg, from_addr=sender, to_addrs=recipients)
        return True, "Email sent to %s." % ", ".join(recipients)
    except Exception as ex:  # noqa: BLE001 - report, never raise
        return False, "Email failed: %s" % ex


def main(argv):
    log_dir = os.path.join(base_dir(), "logs")
    log_file = argv[1] if len(argv) > 1 else ""
    if not log_file or not os.path.isfile(log_file):
        log_file = latest_run_log(log_dir)
    if not log_file or not os.path.isfile(log_file):
        sys.stderr.write("notify_run: no run log found\n")
        return 0
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return 0

    ok_list, fail_list = [], []
    for line in lines:
        m = re.match(r"^\[OK\] Backup saved: .*/([^/]+)$", line)
        if m:
            ok_list.append(m.group(1))
            continue
        m = re.match(r"^\[FAIL\] Backup validation failed: (.+)$", line)
        if m:
            fail_list.append(m.group(1).strip())

    settings = load_settings()
    mode = (settings.get("alerts") or {}).get("notify_on", "failure")
    if mode == "never":
        return 0
    if mode == "failure" and not fail_list:
        return 0

    hostname = socket.gethostname() or "server"
    when = datetime.now(MYT).strftime("%Y-%m-%d %H:%M:%S") + " MYT"
    status = "SUCCESS" if not fail_list else "FAILURES"
    subject = ("MVNBC backup %s — %d ok, %d failed"
               % (status, len(ok_list), len(fail_list)))
    body = ["MVNBC backup run summary",
            "Host:    %s" % hostname,
            "Time:    %s" % when,
            "Result:  %d succeeded, %d failed (of %d)"
            % (len(ok_list), len(fail_list),
               len(ok_list) + len(fail_list)),
            "-" * 40]
    if fail_list:
        body.append("FAILED:")
        body.extend("  X %s" % f for f in fail_list)
        body.append("")
    if ok_list:
        body.append("OK:")
        body.extend("  + %s" % o for o in ok_list)
    body.append("")
    body.append("Log: %s" % os.path.basename(log_file))
    body_text = "\n".join(body)

    results = {}
    email_cfg = settings.get("email") or {}
    if email_cfg.get("enabled"):
        results["email"] = send_email(email_cfg, subject, body_text)
    tg_cfg = settings.get("telegram") or {}
    if tg_cfg.get("enabled"):
        tg_text = ("<b>%s</b>\n\n%s"
                   % (html.escape(subject), html.escape(body_text)))
        results["telegram"] = send_telegram(tg_cfg.get("bot_token"),
                                            tg_cfg.get("chat_id"),
                                            tg_text)
    for channel, (ok, msg) in results.items():
        sys.stdout.write("notify_run[%s]: %s — %s\n"
                         % (channel, "OK" if ok else "ERR", msg))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as ex:  # noqa: BLE001 - never fail the backup run
        sys.stdout.write("notify_run[error]: ERR — %s\n" % ex)
        sys.exit(0)
