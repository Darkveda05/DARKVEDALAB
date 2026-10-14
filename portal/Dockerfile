# DARKVEDA LAB — portal (Flask control center :8090 + Samba file server)
# Build context is the repo root:  docker build -f portal/Dockerfile .
# Runs with host networking + privileges so it manages WireGuard, iptables
# and the host netns exactly like a native install. Daemons (portal, smbd)
# are supervised locally; FRR daemons live in the netstack container.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    CTL_MODE=supervisor

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables wireguard-tools bridge-utils acl \
        samba samba-common-bin supervisor dbus curl ca-certificates \
        frr expect sshpass snmp \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/portal
COPY portal/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY portal/app.py portal/telegram_bot.py ./
COPY templates/smb.conf.tmpl /opt/portal/
COPY mvnbc/ /opt/mvnbc-seed/
# systemctl compatibility shims MUST come after apt layer (never shadow build-time calls)
COPY portal/docker/systemctl /usr/local/bin/systemctl
COPY portal/docker/systemd-run /usr/local/bin/systemd-run
COPY scripts/ns10-setup.sh scripts/ns10-teardown.sh /usr/local/sbin/
COPY portal/docker/supervisord.conf /etc/supervisor/conf.d/portal.conf
COPY portal/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/systemctl /usr/local/bin/systemd-run \
             /usr/local/sbin/ns10-setup.sh /usr/local/sbin/ns10-teardown.sh \
             /entrypoint.sh \
    && mkdir -p /opt/portal/peers /opt/portal/backups /opt/portal/bot_inbox \
                 /var/lib/samba /var/log/samba /var/log/supervisor /var/run/frr

EXPOSE 8090 445 139
ENTRYPOINT ["/entrypoint.sh"]
