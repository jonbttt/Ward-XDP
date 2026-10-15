#!/bin/bash
source "$(dirname "$0")/../lib.sh"

command -v arpspoof >/dev/null || fail "arpspoof not installed (dsniff missing?)"

ATK_MAC=$(attacker cat /sys/class/net/veth-atk/address)

start_ward -enforce -arp_trust 10.200.0.254=aa:aa:aa:aa:aa:aa
ping -c1 -W1 10.200.0.254 >/dev/null 2>&1 || true   # create a cache entry to poison
attacker timeout 5 arpspoof -i veth-atk -t 10.200.0.1 10.200.0.254 || true
sleep 1

[ "$(events 3)" -ge 1 ] || fail "no ARP spoof events"
grep -q "reason=3 mac=$ATK_MAC" "$WARD_LOG" || fail "event MAC doesn't match attacker ($ATK_MAC)"
pass "arp spoof detected"

ip neigh show 10.200.0.254 | grep -qi "$ATK_MAC" && fail "ARP cache was poisoned"
pass "arp cache protected"