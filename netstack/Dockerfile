# DARKVEDA LAB — netstack (network plane: WireGuard, FRR/BGP, iptables, br10)
# Build context is the repo root:  docker build -f netstack/Dockerfile .
# Privileged + host networking at runtime: it manages the HOST netns
# (interfaces, routes, firewall) exactly like a native install.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        frr iproute2 iptables wireguard-tools bridge-utils acl \
        supervisor curl ca-certificates gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY netstack/entrypoint.sh /entrypoint.sh
COPY netstack/supervisord.conf /etc/supervisor/conf.d/netstack.conf
COPY templates/ /templates/
COPY scripts/ns10-setup.sh scripts/ns10-teardown.sh /usr/local/sbin/
RUN chmod +x /entrypoint.sh /usr/local/sbin/ns10-setup.sh /usr/local/sbin/ns10-teardown.sh \
    && mkdir -p /var/log/supervisor /var/run/frr /etc/wireguard

ENTRYPOINT ["/entrypoint.sh"]
