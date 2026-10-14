#!/bin/bash
set -e
# wait for br10 to exist and be UP (created by ifupdown)
for i in $(seq 1 30); do
    ip link show br10 >/dev/null 2>&1 && ip link show br10 | grep -q "UP" && break
    sleep 1
done
ip netns del ns10 2>/dev/null || true
ip link del veth10-host 2>/dev/null || true
ip netns add ns10
ip link add veth10-host type veth peer name veth10-ns
ip link set veth10-ns netns ns10
ip link set veth10-host master br10
ip link set veth10-host up
ip netns exec ns10 ip link set lo up
ip netns exec ns10 ip link set veth10-ns up
ip netns exec ns10 ip addr replace 192.168.10.10/24 dev veth10-ns
# fix default route for reply traffic to Admin LAN
ip netns exec ns10 ip route replace default via 192.168.10.1 2>/dev/null || ip netns exec ns10 ip route add default via 192.168.10.1 2>/dev/null || true
