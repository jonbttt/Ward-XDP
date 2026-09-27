| File | Condition | Packets | Avg %soft | %soft per M pkts | Notes |
|---|---|---|---|---|---|
| baseline-mpstat.txt | No XDP attached | 4,576,381 | 6.49 | 1.42 | Kernel replies with RST to each SYN |
| xdp-mpstat.txt | ward-xdp `-enforce`, native XDP | 7,204,242 | 2.85 | 0.40 | ~3.5x less softirq per packet, bpf_stats on, 51 ns/pkt from run_time_ns / run_cnt |