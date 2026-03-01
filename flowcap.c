//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOWS 65536 // placeholder, overridden by Go at runtime via spec.Maps["flows"].MaxEntries

// Drop counter indices
#define DROP_FRAGMENTS  0
#define DROP_NON_IPV4   1
#define DROP_PARSE_ERR  2
#define DROP_MAX        3

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u64 tcp_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_counters SEC(".maps");

static __always_inline void inc_drop(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&drop_counters, &idx);
    if (cnt)
        (*cnt)++;
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct flow_key *key, __u8 *tcp_flags) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -(DROP_PARSE_ERR + 1);

    // IPv4 only
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -(DROP_NON_IPV4 + 1);

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -(DROP_PARSE_ERR + 1);

    // Check for IP fragmentation - skip all fragments (offset > 0 or MF flag set)
    if (ip->frag_off & bpf_htons(0x3FFF))
        return -(DROP_FRAGMENTS + 1);

    // Validate minimum IP header length
    if (ip->ihl < 5)
        return -(DROP_PARSE_ERR + 1);

    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    *tcp_flags = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -(DROP_PARSE_ERR + 1);

        key->src_port = bpf_ntohs(tcp->source);
        key->dst_port = bpf_ntohs(tcp->dest);
        // Extract TCP flags from offset 13 (tcphdr flags byte)
        *tcp_flags = ((unsigned char *)tcp)[13];

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -(DROP_PARSE_ERR + 1);

        key->src_port = bpf_ntohs(udp->source);
        key->dst_port = bpf_ntohs(udp->dest);
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    return 0;
}

SEC("classifier")
int flow_capture(struct __sk_buff *skb) {
    // Ensure at least the first 74 bytes (ETH 14 + IP 20-60 + TCP/UDP 8-20)
    // are in linear memory. Non-linear skbs from GRO or certain NIC drivers
    // can cause parse failures when headers span paged data.
    if (bpf_skb_pull_data(skb, 74) < 0)
        return TC_ACT_OK;

    struct flow_key key = {};
    __u8 tcp_flags = 0;

    int ret = parse_packet(skb, &key, &tcp_flags);
    if (ret < 0) {
        __u32 idx = (-(ret + 1));
        if (idx < DROP_MAX)
            inc_drop(idx);
        return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 pkt_len = skb->len;

    struct flow_stats *stats = bpf_map_lookup_elem(&flows, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        __sync_lock_test_and_set(&stats->last_seen, now);
        __sync_fetch_and_or(&stats->tcp_flags, tcp_flags);
    } else {
        struct flow_stats new_stats = {
            .packets = 1,
            .bytes = pkt_len,
            .first_seen = now,
            .last_seen = now,
            .tcp_flags = tcp_flags,
        };
        if (bpf_map_update_elem(&flows, &key, &new_stats, BPF_NOEXIST) < 0) {
            // Another CPU created this flow between our lookup and insert - retry lookup
            stats = bpf_map_lookup_elem(&flows, &key);
            if (stats) {
                __sync_fetch_and_add(&stats->packets, 1);
                __sync_fetch_and_add(&stats->bytes, pkt_len);
                __sync_lock_test_and_set(&stats->last_seen, now);
                __sync_fetch_and_or(&stats->tcp_flags, tcp_flags);
            }
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
