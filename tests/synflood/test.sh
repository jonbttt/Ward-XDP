#!/bin/bash
source "$(dirname "$0")/../lib.sh"

# enforcing: threshold of 500 should cut off exactly at 500
start_ward -enforce
out=$(attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 2>&1 || true)
r=$(received "$out")
[ "$r" -eq 500 ] || fail "enforce: expected 500 received, got $r"
[ "$(events 1)" -eq 1 ] || fail "enforce: expected 1 SYN flood event, got $(events 1)"
[ "$(events 2)" -eq 0 ] || fail "enforce: port scan fired on a single-port flood"
stop_ward
pass "synflood enforce"

sleep 6   # let the window roll

# alert-only: detects but passes everything
start_ward
out=$(attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 2>&1 || true)
r=$(received "$out")
[ "$r" -eq 600 ] || fail "alert-only: expected 600 received, got $r"
grep -q "reason=1 .*action=2" "$WARD_LOG" || fail "alert-only: no event with action=2"
stop_ward
pass "synflood alert-only"