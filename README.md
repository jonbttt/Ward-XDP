# Ward-XDP
Kernel-resident network defense system: eBPF/XDP data plane (six ingress detectors) + BPF LSM socket policy, with a Go control plane (rule engine, userspace self-baseline, inline Isolation Forest) that ships structured alerts (ECS ndjson) to a SIEM.

## Status
Early development. Environment up (kernel 6.8, BPF LSM enabled, CO-RE toolchain).
Working on XDP loader + first detector.

## Scope

The six XDP features share a single parse pass (one eBPF program, fixed detector
order, cheapest exits first). The seventh runs at the LSM layer. The two layers
communicate through pinned BPF maps.

Status: [x] done · [~] in progress · [-] planned

1. **SYN flood mitigation** [x] per-source rate limit on SYN-only segments via an LRU map; drop above threshold in a rolling window, one alert per window over the ring buffer.
2. **Port scan detection** [-] flag sources touching many distinct ports; compact approximate-cardinality structure per source (not a full bitmap).
3. **ARP spoofing prevention** [-] trusted IPv4→MAC table; drop replies where the sender IP maps to a different MAC. Uses bpf_dynptr for variable-length parsing.
4. **IP spoofing / ingress filtering** [-] LPM-trie martian/bogon deny + uRPF-style allow (RFC 2827 / BCP 38).
5. **DNS amplification mitigation** [-] per-destination rate limit on unsolicited port-53 responses to protected hosts.
6. **ML anomaly detection** [-] Go control plane: rule engine → userspace per-source z-score baseline → inline Isolation Forest; hourly retrain.
7. **BPF LSM socket policy** [-] per-process bind()/connect() policy enforced at security hooks, returning -EPERM on violation.

## Safety defaults
- **Alert-only by default:** every drop/deny is gated by an `enforce` flag;
  off, the program logs the intended action and passes the packet.
- **Never-block allowlist:** gateway, DNS, and management subnet are checked
  before any detector can block, so the operator can't be locked out.

## Environment
Ubuntu 24.04, kernel 6.8, `lsm=...,bpf` enabled. Go 1.26+, clang/LLVM 18+, bpftool.
