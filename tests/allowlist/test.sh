#!/bin/bash
source "$(dirname "$0")/../lib.sh"

start_ward -enforce -allow 10.200.0.2
out=$(attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 2>&1 || true)
r=$(received "$out")
[ "$r" -eq 600 ] || fail "allowlisted source was dropped, got $r/600"
[ "$(events 1)" -eq 0 ] || fail "event fired for allowlisted source"
pass "allowlist"