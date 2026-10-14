#!/bin/bash
ip link del veth10-host 2>/dev/null || true
ip netns del ns10 2>/dev/null || true
