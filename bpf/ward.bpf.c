#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800 // macro def for IPv4 Packet
#define MAX_MAP_ENTRIES 131072

/* TODO: Change to config-based */
#define MAX_WINDOW_NS 5000000000
#define MAX_PACKETS 500

struct syn_stats {
    __u64 start_time;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32); // source IP addr
    __type(value, struct syn_stats); // starting time
} syn_map SEC(".maps"); 

SEC("xdp")
int ward_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    int iph_len = iph->ihl * 4;

    if (iph_len < 20 || iph_len > 60) {
        /* TODO: Change to XDP_DROP once enforce flag is implemented */
        return XDP_PASS;
    }

    struct tcphdr *tcph = (struct tcphdr *)((unsigned char*)iph + iph_len);
    if ((void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }
    
    if (tcph->syn == 0 || tcph->ack == 1) {
        return XDP_PASS;
    }

    u32 ip_src = iph->saddr;
    
    struct syn_stats *entry = bpf_map_lookup_elem(&syn_map, &ip_src);
    u64 curr_time = bpf_ktime_get_ns();

	if (!entry) {
        struct syn_stats init_entry = {curr_time, 1};
		bpf_map_update_elem(&syn_map, &ip_src, &init_entry, BPF_ANY);
        return XDP_PASS;
	}

    if (curr_time - entry->start_time > MAX_WINDOW_NS) {
        entry->start_time = curr_time;
        entry->count = 1;
    } else {
        __sync_fetch_and_add(&entry->count, 1);
    }

    if (entry->count > MAX_PACKETS) {
        return XDP_DROP;
        /* TODO: use enforce flag */
    }

    return XDP_PASS;
}