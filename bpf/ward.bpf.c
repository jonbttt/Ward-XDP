#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800 // macro def for IPv4 Packet
#define MAX_MAP_ENTRIES 131072

enum ward_verdict {
    WARD_OK = 0,
    WARD_BLOCK,
};

enum ward_reason {
    WARD_REASON_NONE = 0,
    WARD_REASON_SYN_FLOOD,
};

struct ward_result {
    enum ward_verdict verdict;
    enum ward_reason reason;
    __u64 value;
};

struct ward_cfg {
    __u64 enforce;
    __u64 syn_max_packets;
    __u64 syn_window_ns;
};

struct syn_stats {
    __u64 start_time;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ward_cfg);
    __uint(max_entries, 1);
} ward_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32); // source IP addr
    __type(value, struct syn_stats); // starting time
} syn_map SEC(".maps");

static __always_inline int check_syn_flood(__u32 ip_src, struct ward_cfg *cfg) {
    struct syn_stats *entry = bpf_map_lookup_elem(&syn_map, &ip_src);
    u64 curr_time = bpf_ktime_get_ns();

	if (!entry) {
        struct syn_stats init_entry = {curr_time, 1};
		bpf_map_update_elem(&syn_map, &ip_src, &init_entry, BPF_ANY);
        return XDP_PASS;
	}

    if (curr_time - entry->start_time > cfg->syn_window_ns) {
        entry->start_time = curr_time;
        entry->count = 1;
    } else {
        __sync_fetch_and_add(&entry->count, 1);
    }

    if (entry->count > cfg->syn_max_packets) {
        if (cfg->enforce == 1) {
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

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

    __u32 config_key = 0;
    struct ward_cfg *config = bpf_map_lookup_elem(&ward_config, &config_key);
    if (!config) {
        return XDP_PASS;
    }
    
    int iph_len = iph->ihl * 4;
    if (iph_len < 20 || iph_len > 60) {
        if (config->enforce == 1) {
            return XDP_DROP;
        }
        return XDP_PASS; // don't parse packets with nonsense header lengths
    }

    struct tcphdr *tcph = (struct tcphdr *)((unsigned char*)iph + iph_len);
    if ((void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }
    
    if (tcph->syn == 0 || tcph->ack == 1) {
        return XDP_PASS;
    }

    u32 ip_src = iph->saddr;
    enum ward_verdict verdict = check_syn_flood(ip_src, config);
    if (verdict == WARD_BLOCK) {
        return config->enforce ? XDP_DROP : XDP_PASS;
    }
    
    return XDP_PASS;
}