#!/bin/bash
source "$(dirname "$0")/../lib.sh"

start_ward -scan_block_ttl_ns 1
for scan in sS sN sF sX; do
  before=$(events 2)
  attacker nmap -$scan -p 1-100 10.200.0.1 >/dev/null 2>&1
  after=$(events 2)
  [ "$after" -gt "$before" ] || fail "nmap -$scan did not trigger port scan"
  pass "portscan -$scan"
  sleep 6
done
[ "$(events 1)" -eq 0 ] || fail "SYN flood fired during port scans"