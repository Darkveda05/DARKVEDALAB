# DARKVEDA LAB — portal (Flask control center :8090 + Samba file server)
# Build context is the repo root:  docker build -f portal/Dockerfile .
# Runs with host networking + privileges so it manages WireGuard, iptables
# and the host netns exactly like a native install. Daemons (portal, smbd,
# cron) are supervised locally.
# Base is Ubuntu 24.04 (same as netstack) so Samba comes from Ubuntu repos,
# not Debian.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    CTL_MODE=supervisor

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        iproute2 iptables wireguard-tools bridge-utils acl \
        samba samba-common-bin smbclient supervisor dbus curl ca-certificates \
        expect openssh-client sshpass snmp cron \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

WORKDIR /opt/portal
COPY portal/requirements.txt ./
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

COPY portal/app.py portal/telegram_bot.py ./
COPY templates/smb.conf.tmpl /opt/portal/
COPY mvnbc/ /opt/mvnbc-seed/
# systemctl compatibility shims MUST come after apt layer (never shadow build-time calls)
COPY portal/docker/systemctl /usr/local/bin/systemctl
COPY portal/docker/systemd-run /usr/local/bin/systemd-run
COPY portal/docker/supervisord.conf /etc/supervisor/conf.d/portal.conf
COPY portal/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/systemctl /usr/local/bin/systemd-run \
              /entrypoint.sh \
     && mkdir -p /opt/portal/peers /opt/portal/backups /opt/portal/bot_inbox \
                  /var/lib/samba /var/log/samba /var/log/supervisor

EXPOSE 8090 445 139
ENTRYPOINT ["/entrypoint.sh"]
