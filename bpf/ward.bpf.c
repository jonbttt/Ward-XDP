#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int ward_main(struct xdp_md *ctx) {
    return XDP_PASS;
}