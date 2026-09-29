#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

OUT="$SCRIPT_DIR/portscan-$(date +%s).txt"
WARD_LOG="$(mktemp)"

# pass args through, e.g. ./test.sh -enforce -scan_max_ports 20
sudo ./ward-xdp -iface veth-ward "$@" > "$WARD_LOG" 2>&1 &
trap 'sudo pkill -f "ward-xdp -iface veth-ward" 2>/dev/null; rm -f "$WARD_LOG"' EXIT
sleep 2

{
  echo "# args: $*"
  echo "# date: $(date -Is)"
  for scan in sS sN sF sX; do
    echo
    echo "## nmap -$scan -p 1-100"
    sudo ip netns exec attacker nmap -$scan -p 1-100 10.200.0.1
    sleep 6   # let the window roll before the next scan
  done

  sudo pkill -f "ward-xdp -iface veth-ward"
  sleep 1
  echo
  echo "## ward-xdp events"
  cat "$WARD_LOG"
} | tee "$OUT"