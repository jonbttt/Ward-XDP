#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800     // macro def for IPv4 Packet
#define ETH_P_ARP 0x0806    // macro def for ARP Packet
#define MAX_MAP_ENTRIES 131072

enum ward_verdict {
    WARD_OK = 0,
    WARD_BLOCK = 1,
    WARD_BLOCK_ALERTED = 2,
};

enum ward_reason {
    WARD_REASON_NONE = 0,
    WARD_REASON_SYN_FLOOD = 1,
    WARD_REASON_PORT_SCAN = 2,
    WARD_REASON_ARP_SPOOF = 3,
    WARD_REASON_ARP_UNTRUSTED = 4,
};

struct ward_result {
    enum ward_verdict verdict;
    enum ward_reason reason;
    __u64 value;
};

struct ward_event {
    __u64 timestamp;
    __u32 ip_src;
    enum ward_verdict verdict;
    enum xdp_action action;
    enum ward_reason reason;
    __u64 value;
};

struct ward_cfg {
    __u64 enforce;
    __u64 syn_max_packets;
    __u64 syn_window_ns;
    __u64 syn_block_ttl_ns;
    __u64 port_scan_max_ports;
    __u64 port_scan_window_ns;
    __u64 port_scan_block_ttl_ns;
    __u64 arp_strict;
};

struct block_stats {
    __u64 until_time;
    enum ward_reason reason;
};

struct syn_stats {
    __u64 start_time;
    __u64 count;
    bool alerted;
};

struct port_scan_stats {
    __u64 start_time;
    __u64 ports_seen;   // 64-bit bitmap
    __u64 distinct;     // num bits set
    bool alerted;
};

struct arp_eth_ipv4 {
    struct arphdr hdr;
    __u8 smac[6];   // sender MAC
    __u8 saddr[4];  // sender IP
    __u8 tmac[6];   // target MAC
    __u8 taddr[4];  // target IP
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ward_cfg);
} ward_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} ward_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, struct block_stats);
} ward_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, struct syn_stats);
} syn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, struct port_scan_stats);
} port_scan_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} arp_trust SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct ward_result check_syn_flood(struct tcphdr *tcph, __u32 ip_src, struct ward_cfg *cfg, __u64 curr_time) {
    struct ward_result pass = {WARD_OK, WARD_REASON_NONE, 0};
    if (tcph->syn == 0 || tcph->ack == 1) {
        return pass;
    }

    struct syn_stats *entry = bpf_map_lookup_elem(&syn_map, &ip_src);

	if (!entry) {
        struct syn_stats init_entry = {curr_time, 1, false};
		bpf_map_update_elem(&syn_map, &ip_src, &init_entry, BPF_ANY);
        return pass;
	}

    if (curr_time - entry->start_time > cfg->syn_window_ns) {
        entry->start_time = curr_time;
        entry->count = 1;
        entry->alerted = false;
    } else {
        __sync_fetch_and_add(&entry->count, 1);
    }

    if (entry->alerted) {
        struct ward_result res = {WARD_BLOCK_ALERTED, WARD_REASON_SYN_FLOOD, 0};
        return res;
    }

    if (entry->count > cfg->syn_max_packets) {
        struct ward_result res = {WARD_BLOCK, WARD_REASON_SYN_FLOOD, entry->count};
        entry->alerted = true;
        return res;
    }

    return pass;
}

static __always_inline struct ward_result check_port_scan(struct tcphdr *tcph, __u32 ip_src, struct ward_cfg *cfg, __u64 curr_time) {
    struct ward_result pass = {WARD_OK, WARD_REASON_NONE, 0};
    if (tcph->ack) {
        return pass;
    }

    __u64 bit = 1ULL << (bpf_ntohs(tcph->dest) % 64);
    struct port_scan_stats *entry = bpf_map_lookup_elem(&port_scan_map, &ip_src);

	if (!entry) {
        struct port_scan_stats init_entry = {curr_time, bit, 1, false};
		bpf_map_update_elem(&port_scan_map, &ip_src, &init_entry, BPF_ANY);
        return pass;
	}

    if (curr_time - entry->start_time > cfg->port_scan_window_ns) {
        entry->start_time = curr_time;
        entry->ports_seen = bit;
        entry->distinct = 1;
        entry->alerted = false;
    } else {
        __u64 old = __sync_fetch_and_or(&entry->ports_seen, bit);
        if (!(old & bit)) {
            __sync_fetch_and_add(&entry->distinct, 1);
        }
    }

    if (entry->alerted) {
        struct ward_result res = {WARD_BLOCK_ALERTED, WARD_REASON_PORT_SCAN, entry->distinct};
        return res;
    }

    if (entry->distinct > cfg->port_scan_max_ports) {
        struct ward_result res = {WARD_BLOCK, WARD_REASON_PORT_SCAN, entry->distinct};
        entry->alerted = true;
        return res;
    }

    return pass;
}

static __always_inline struct ward_result check_arp_spoof(__u32 ip_src, __u64 mac, struct ward_cfg *cfg) {
    struct ward_result pass = {WARD_OK, WARD_REASON_NONE, 0};
    
    __u64 *trusted = bpf_map_lookup_elem(&arp_trust, &ip_src);
    if (!trusted) {
        if (cfg->arp_strict) {
            struct ward_result res = {WARD_BLOCK, WARD_REASON_ARP_UNTRUSTED, mac};
            return res;
        }
        return pass;
    }

    if (*trusted != mac) {
        struct ward_result res = {WARD_BLOCK, WARD_REASON_ARP_SPOOF, mac};
        return res;
    }

    return pass;
}

static __always_inline void emit_event(__u32 ip_src, struct ward_result *res, enum xdp_action action) {
    if (res->verdict == WARD_BLOCK) {
        struct ward_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event) {
            return;
        }

        event->timestamp = bpf_ktime_get_ns();
        event->ip_src = ip_src;
        event->verdict = res->verdict;
        event->action = action;
        event->reason = res->reason;
        event->value = res->value;
        bpf_ringbuf_submit(event, 0);

        return;
    }

    if (res->verdict == WARD_BLOCK_ALERTED) {
        return;
    }
}

static __always_inline enum xdp_action handle_ipv4(void *data, void *data_end) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 ip_src = iph->saddr;
    if (bpf_map_lookup_elem(&ward_allowlist, &ip_src)) {
        return XDP_PASS;
    }

    __u32 config_key = 0;
    struct ward_cfg *config = bpf_map_lookup_elem(&ward_config, &config_key);
    if (!config) {
        return XDP_PASS;
    }

    enum xdp_action action = config->enforce ? XDP_DROP : XDP_PASS;

    __u64 curr_time = bpf_ktime_get_ns();
    struct block_stats *b = bpf_map_lookup_elem(&ward_blocklist, &ip_src);
    if (b) {
        if (curr_time < b->until_time) {
            return action;
        }
        bpf_map_delete_elem(&ward_blocklist, &ip_src);
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    int iph_len = iph->ihl * 4;
    if (iph_len < 20 || iph_len > 60) {
        return action; // best not to parse invalid header len
    }

    struct tcphdr *tcph = (struct tcphdr *)((unsigned char*)iph + iph_len);
    if ((void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }

    struct ward_result syn_res = check_syn_flood(tcph, ip_src, config, curr_time);
    struct ward_result port_scan_res = check_port_scan(tcph, ip_src, config, curr_time);
    enum ward_reason reason = WARD_REASON_NONE;
    __u64 until = 0;

    if (syn_res.verdict == WARD_BLOCK) {
        emit_event(ip_src, &syn_res, action);
        until = curr_time + config->syn_block_ttl_ns;
        reason = syn_res.reason;
    }

    if (port_scan_res.verdict == WARD_BLOCK) {
        emit_event(ip_src, &port_scan_res, action);
        __u64 scan_until = curr_time + config->port_scan_block_ttl_ns;
        if (scan_until > until) {
            until = scan_until;
            reason = port_scan_res.reason;
        }
    }

    if (until) {
        struct block_stats block_entry = {until, reason};
		bpf_map_update_elem(&ward_blocklist, &ip_src, &block_entry, BPF_ANY);
    }

    if (syn_res.verdict != WARD_OK || port_scan_res.verdict != WARD_OK) {
        return action;
    }
    
    return XDP_PASS;
}

static __always_inline enum xdp_action handle_arp(void *data, void *data_end) {
    struct arp_eth_ipv4 *arph = data + sizeof(struct ethhdr);
    if ((void *)(arph + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(arph->hdr.ar_hrd) != 1 ||                 // only ethernet
        bpf_ntohs(arph->hdr.ar_pro) != ETH_P_IP ||          // only IPv4
        arph->hdr.ar_hln != 6 || arph->hdr.ar_pln != 4 ||   // hardware/protocol addr len
        bpf_ntohs(arph->hdr.ar_op) != 2) {                  // only reply opcode
        return XDP_PASS;
    }

    __u32 config_key = 0;
    struct ward_cfg *config = bpf_map_lookup_elem(&ward_config, &config_key);
    if (!config) {
        return XDP_PASS;
    }

    enum xdp_action action = config->enforce ? XDP_DROP : XDP_PASS;

    __u32 ip_src;
    __builtin_memcpy(&ip_src, arph->saddr, 4);

    __u64 mac = 0;
    __builtin_memcpy(&mac, arph->smac, 6);

    struct ward_result arp_res = check_arp_spoof(ip_src, mac, config);

    if (arp_res.verdict == WARD_BLOCK) {
        emit_event(ip_src, &arp_res, action);
        return action;
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

    switch(bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        return handle_ipv4(data, data_end);
    case ETH_P_ARP:
        return handle_arp(data, data_end);
    default:
        return XDP_PASS;
    }

    
}