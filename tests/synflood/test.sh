#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

sudo ./ward-xdp -iface veth-ward &
WARD_PID=$!
sleep 2                     # give it time to attach

sudo ip netns exec attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 2>&1 \
  | tee "$SCRIPT_DIR/synflood-600-$(date +%s).txt"

sudo kill $WARD_PID