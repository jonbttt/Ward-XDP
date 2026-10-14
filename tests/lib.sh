#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WARD_LOG=""

fail() {
  echo "FAIL: $*" >&2
  [ -n "$WARD_LOG" ] && { echo "--- ward-xdp log ---" >&2; cat "$WARD_LOG" >&2; }
  exit 1
}
pass() { echo "PASS: $*"; }

start_ward() {
  WARD_LOG="$(mktemp)"
  sudo "$REPO_ROOT/ward-xdp" -iface veth-ward "$@" >"$WARD_LOG" 2>&1 &
  sleep 2
  grep -q "successfully attached" "$WARD_LOG" || fail "ward-xdp did not attach"
}

stop_ward() {
  sudo pkill -INT -f "ward-xdp -iface veth-ward" 2>/dev/null || true
  sleep 1
}
trap stop_ward EXIT

# pulls N out of "N packets received" (hping3) or "N received" (ping)
received() { grep -oP '\d+(?= (packets )?received)' <<<"$1" | head -1; }

# count events for reason code
events() { grep -c "reason=$1" "$WARD_LOG" || true; }

attacker() { sudo ip netns exec attacker "$@"; }