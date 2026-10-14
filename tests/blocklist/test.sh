#!/bin/bash
source "$(dirname "$0")/../lib.sh"

start_ward -enforce -syn_block_ttl_ns 5000000000
attacker hping3 -S -p 80 -c 600 -i u500 10.200.0.1 >/dev/null 2>&1 || true
[ "$(events 1)" -eq 1 ] || fail "flood didn't trigger"

out=$(attacker ping -c 3 -W 1 10.200.0.1 2>&1 || true)
[ "$(received "$out")" -eq 0 ] || fail "blocked source could still ping"
pass "blocklist drops non-TCP"

sleep 6
out=$(attacker ping -c 3 -W 1 10.200.0.1 2>&1 || true)
[ "$(received "$out")" -eq 3 ] || fail "block did not expire"
pass "blocklist expires"