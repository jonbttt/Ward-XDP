#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# pass args straight to ward-xdp, ex: ./test.sh -enforce -syn_max_pkts 100
sudo ./ward-xdp -iface veth-ward "$@" &
WARD_PID=$!
trap 'sudo kill $WARD_PID 2>/dev/null' EXIT
sleep 2

sudo ip netns exec attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 2>&1 \
  | tee "$SCRIPT_DIR/synflood-600-$(date +%s).txt"