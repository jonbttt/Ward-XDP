# Ward-XDP
Kernel-resident network defense system: eBPF/XDP data plane (six ingress detectors) + BPF LSM socket policy, with a Go control plane (rule engine, userspace self-baseline, inline Isolation Forest) that ships structured alerts (ECS ndjson) to a SIEM.

## Status
Active development. SYN flood and port scan detection, allowlist, blocklist, and ring buffer all work and have been tested. Next is ARP spoofing.

## Scope
The six XDP features share a single parse pass (one eBPF program, fixed detector
order, cheapest exits first). The seventh runs at the LSM layer. The two layers
communicate through pinned BPF maps.

Status: [x] done · [~] in progress · [-] planned

1. **SYN flood mitigation** [x] per-source rate limit on SYN-only segments via an LRU map; drop above threshold in a rolling window, one alert per window over the ring buffer.
2. **Port scan detection** [x] flag sources touching many distinct ports; 64-bit bitmap per source for approximate distinct-port counting. Catches SYN, NULL, FIN, and XMAS scans.
3. **ARP spoofing prevention** [x] trusted IPv4 → MAC table; drop replies where the sender IP maps to a different MAC. Independent from allowlist and blocklist since spoofed IP is the victim's.
4. **IP spoofing / ingress filtering** [-] LPM-trie martian/bogon deny + uRPF-style allow (RFC 2827 / BCP 38).
5. **DNS amplification mitigation** [-] per-destination rate limit on unsolicited port-53 responses to protected hosts.
6. **ML anomaly detection** [-] Go control plane: rule engine → userspace per-source z-score baseline → inline Isolation Forest; hourly retrain.
7. **BPF LSM socket policy** [-] per-process bind()/connect() policy enforced at security hooks, returning -EPERM on violation.

## Results
SYN flood detector, native XDP on a veth pair, kernel 6.8, measured over 7.2M packets:
- **~51 ns per packet** (`run_time_ns / run_cnt` with `bpf_stats_enabled`)
- **~3.5x less softirq CPU per packet** than the default kernel receive path

Data in `results/`.

## Usage
    go generate ./... && go build -o ward-xdp .
    sudo ./ward-xdp -iface <iface> [flags]
  
| Flag | Default | Description |
|---|---|---|
| `-iface` | (required) | Network interface to attach to |
| `-enforce` | `false` | Allows packet dropping when true |
| `-allow` | none | Comma-delimited IPs that are never blocked |
| `-syn_max_pkts` | `500` | Number of packets to trigger SYN flood alert |
| `-syn_window_ns` | `5000000000` | Timeframe for packets to trigger SYN flood alert (ns) |
| `-syn_block_ttl_ns` | `60000000000` | How long to block a SYN flood source (ns) |
| `-scan_max_ports` | `20` | Number of distinct ports to trigger port scan alert (<64 due to bitmap) |
| `-scan_window_ns` | `5000000000` | Timeframe for ports accessed to trigger port scan alert (ns) |
| `-scan_block_ttl_ns` | `600000000000` | How long to block a port scan source (ns) |

Test rig and scripts in `tests/`.

## Safety defaults
- **Alert-only by default:** every drop/deny is gated by an `enforce` flag; off, the program logs the intended action and passes the packet.
- **Never-block allowlist:** gateway, DNS, and management IPs are checked before any detector can block, so the operator can't be locked out.
- **Blocklist with TTL:** when a detector fires, the source is blocked for a per-reason duration and checked before any protocol parsing.

## Environment
Ubuntu 24.04, kernel 6.8, `lsm=...,bpf` enabled. Go 1.26+, clang/LLVM 18+, bpftool.

## License
Apache-2.0 for userspace code. eBPF programs are Dual BSD/GPL, required to use GPL-only kernel helpers.
