#include "vmlinux.h"
#include "tc_capture.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EEXIST 17 /* File exists */
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define ETH_HLEN 14       /* Total octets in header.	 */
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#define IPPROTO_ICMP 1    /* Internet Control Message Protocol	*/
#define IPPROTO_ICMPV6 58 /* ICMPv6			*/
#define IPPROTO_TCP 6     /* Transmission Control Protocol	*/
#define IPPROTO_UDP 17    /* User Datagram Protocol		*/
#define IPPROTO_SCTP 132  /* Stream Control Transport Protocol	*/

#ifndef LEGACY_KERNEL
static const u8 u8_zero = 0;
static const u32 u32_zero = 0;
#endif

#define OFFSET_OF(type, member) (unsigned long)(&(((type*)0)->member))
#define SKB_OFFSET_HASH OFFSET_OF(struct sk_buff, hash)
#define __SKB_OFFSET_HASH OFFSET_OF(struct __sk_buff, hash)
#define SKB_OFFSET_HEAD OFFSET_OF(struct sk_buff, head)
#define SKB_OFFSET_NETWORK_HEADER OFFSET_OF(struct sk_buff, network_header)

#define NETIF_RECV_SKB 0
#define IP_RECV_SKB 1
#define TCP_RECV_SKB 1

// 用来创建struct packet_event_t
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct packet_event_t);
} packet_event_stack SEC(".maps");

// struct packet_event_t 传输到User space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} packet_events SEC(".maps");


// 用来创建 struct recv_timestamp_event_t
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct recv_timestamp_event_t);
} timestamp_event_stack SEC(".maps");

// struct recv_timestamp_event_t 传输到User space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} recv_timestamp_events SEC(".maps");

// 用以传递更改timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct timestamp_key);
    __type(value, struct recv_timestamp_event_t);
} recv_timestamp_hash SEC(".maps");

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline int parse_skb_l2(struct __sk_buff *skb, struct l2_t *l2, u32 *offset) {
    if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ethhdr, h_proto), &l2->h_protocol, sizeof(l2->h_protocol)) <
        0) {
        // debug_log("parse_skb_l2 1 failed:\n");
        return -1;
    }
    l2->h_protocol = bpf_ntohs(l2->h_protocol);
    *offset += sizeof(struct ethhdr);
    return 0;
}

static __always_inline int parse_skb_l3(struct __sk_buff *skb, u16 protocol, struct l3_t *l3, u32 *offset) {
    switch (protocol) {
    case ETH_P_IP: {
        struct iphdr ip_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &ip_hdr, sizeof(struct iphdr)) < 0) {
            // debug_log("parse_skb_l3 1 failed:\n");
            return -1;
        }
        l3->protocol = ip_hdr.protocol;
        l3->saddr[0] = ip_hdr.saddr;
        l3->daddr[0] = ip_hdr.daddr;
        *offset += sizeof(struct iphdr);
        return 0;
    }
    case ETH_P_IPV6: {
        struct ipv6hdr ip_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &ip_hdr, sizeof(struct ipv6hdr)) < 0) {
            // debug_log("parse_skb_l3 2 failed:\n");
            return -1;
        }
        l3->protocol = ip_hdr.nexthdr;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, saddr), &l3->saddr, sizeof(l3->saddr)) < 0) {
            // debug_log("parse_skb_l3 3 failed:\n");
            return -1;
        }
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, daddr), &l3->daddr, sizeof(l3->daddr)) < 0) {
            // debug_log("parse_skb_l3 4 failed:\n");
            return -1;
        }
        *offset += sizeof(struct ipv6hdr);
        return 0;
    }
    default: {
        return 0;
    }
    }

    return 0;
}

static __always_inline int parse_skb_l4(struct __sk_buff *skb, u8 protocol, struct l4_t *l4, u32 *offset) {
    switch (protocol) {
        //    case IPPROTO_ICMP: {
        //        l4->sport = 0;
        //        l4->dport = 0;
        //        *offset += sizeof(struct icmphdr);
        //        return 0;
        //     }
        //    case IPPROTO_ICMPV6: {
        //        l4->sport = 0;
        //        l4->dport = 0;
        //        *offset += sizeof(struct icmp6hdr);
        //        return 0;
        //     }
        case IPPROTO_TCP: {
            struct tcphdr tcp_hdr;
            if (bpf_skb_load_bytes(skb, *offset, &tcp_hdr, sizeof(struct tcphdr)) < 0) {
                // debug_log("parse_skb_l4 1 failed:\n");
                return -1;
            }
            l4->sport = bpf_ntohs(tcp_hdr.source);
            l4->dport = bpf_ntohs(tcp_hdr.dest);
            l4->seq = tcp_hdr.seq;
            l4->ack = tcp_hdr.ack_seq;
            *offset += sizeof(struct tcphdr);
        }
            return 0;
        case IPPROTO_UDP: {
            struct udphdr udp_hdr;
            if (bpf_skb_load_bytes(skb, *offset, &udp_hdr, sizeof(struct udphdr)) < 0) {
                // debug_log("parse_skb_l4 2 failed:\n");
                return -1;
            }
            l4->sport = bpf_ntohs(udp_hdr.source);
            l4->dport = bpf_ntohs(udp_hdr.dest);
            *offset += sizeof(struct udphdr);
            return 0;
        }
        case IPPROTO_SCTP: {
            struct sctphdr sctp_hdr;
            if (bpf_skb_load_bytes(skb, *offset, &sctp_hdr, sizeof(struct sctphdr)) < 0) {
                // debug_log("parse_skb_l4 3 failed:\n");
                return -1;
            }
            l4->sport = bpf_ntohs(sctp_hdr.source);
            l4->dport = bpf_ntohs(sctp_hdr.dest);
            *offset += sizeof(struct sctphdr);
            return 0;
        }
        default: {
            return 0;
        }
    }

    return 0;
}

static __always_inline int parse_skb_meta(struct __sk_buff *skb, struct packet_meta_t *meta) {
    meta->ifindex = skb->ifindex;

    if (parse_skb_l2(skb, &meta->l2, &meta->offset) < 0) {
        return -1;
    }

    if (parse_skb_l3(skb, meta->l2.h_protocol, &meta->l3, &meta->offset) < 0) {
        return -1;
    }

    if (parse_skb_l4(skb, meta->l3.protocol, &meta->l4, &meta->offset) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline void tc_capture_packets(struct __sk_buff *skb, bool ingress) {
    u64 tc_timestamp = bpf_ktime_get_ns();

    bpf_skb_pull_data(skb, 0);

    // TODO: FIXME: 只处理Tcp报文
    struct packet_meta_t packet_meta = {0};
    packet_meta.l4.seq = 0;
    int ret = parse_skb_meta(skb, &packet_meta);
    if (ret < 0) {
        return ;
    }

    if(packet_meta.l2.h_protocol != ETH_P_IP) {
        return ;
    }

    if(packet_meta.l3.protocol != IPPROTO_TCP) {
        return ;
    }

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, (void *)(long)skb->data, (void *)(long)skb->data_end)) {
        return;
    }

    struct packet_event_t *pk;
    pk = bpf_map_lookup_elem(&packet_event_stack, &u32_zero);
    if (!pk) {
        return;
    }

    __builtin_memset(&pk->process, 0, sizeof(pk->process));
    __builtin_memset(&pk->process.cgroup_name, 0, sizeof(pk->process.cgroup_name));

    unsigned char pk_type;
    u64 payload_len = (u64)skb->len;
    if (ingress) {
        pk_type = INGRESS_PACKET;
    } else {
        pk_type = EGRESS_PACKET;
    }
    pk->packet_type = pk_type;
    pk->ifindex     = skb->ifindex;
    pk->payload_len = payload_len;
    pk->tc_timestamp= tc_timestamp;

    int event_ret = bpf_perf_event_output(skb, &packet_events, BPF_F_CURRENT_CPU | (payload_len << 32), pk, sizeof(struct packet_event_t));
    if (event_ret != 0) {
    }

    struct recv_timestamp_event_t ts_value = {
        .tc = tc_timestamp,
        .net_recv = 0,
        .ip_recv = 0,
        .tcp_recv = 0,
    };

    struct timestamp_key ts_key = {
        .seq = packet_meta.l4.seq,
        .ack = packet_meta.l4.ack,
    };

    bpf_map_update_elem(&recv_timestamp_hash, &ts_key, &ts_value, BPF_ANY);
    

    return;
}


SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    tc_capture_packets(skb, true);
    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    tc_capture_packets(skb, false);
    return TC_ACT_OK;
}


static inline bool parse_tcp_hdr(struct sk_buff *skb, struct tcphdr* tcphdr)
{
	struct iphdr *piph;
	struct iphdr iph;
	struct tcphdr *ptcph;

	u16 network_header;
	void *head = NULL;
	char *ptr = NULL;

	if (bpf_probe_read(&network_header, sizeof(network_header), (void *)(skb)+SKB_OFFSET_NETWORK_HEADER)) {
		return false;
	}
	if (bpf_probe_read(&head, sizeof(head), (void *)(skb)+SKB_OFFSET_HEAD)) {
		return false;
	}
	piph = (struct iphdr*)(head+network_header);
	if (bpf_probe_read(&iph, sizeof(iph), piph)) {
		return false;
	}

	if (iph.protocol != IPPROTO_TCP)
		return false;

	ptcph = (struct tcphdr *)((void *)(piph) + iph.ihl * 4);
	if (bpf_probe_read(tcphdr, sizeof(struct tcphdr), ptcph)) {
		return false;
	}

    return true;
}

static inline bool update_timestamp_hash_map(struct sk_buff *skb, u64 timestamp, int hook_point, struct recv_timestamp_event_t* out)
{
    struct tcphdr tcphdr = {0};
    if (!parse_tcp_hdr(skb, &tcphdr)) {
        char fmt_str1[] = "failed parse tcp hdr";
        bpf_trace_printk(fmt_str1, sizeof(fmt_str1));
        return false;
    }
    
    struct timestamp_key ts_key = {
        .seq = tcphdr.seq,
        .ack = tcphdr.ack_seq,
    };

    struct recv_timestamp_event_t* ts_value;
    ts_value = bpf_map_lookup_elem(&recv_timestamp_hash, &ts_key);
    if (!ts_value) {
        char fmt_str1[] = "ts_value not found: seq:%lu, ack:%lu";
        bpf_trace_printk(fmt_str1, sizeof(fmt_str1), ts_key.seq, ts_key.ack);
        return false;
    }

    if(hook_point == NETIF_RECV_SKB) {

        ts_value->net_recv = timestamp;
        bpf_map_update_elem(&recv_timestamp_hash, &ts_key, ts_value, BPF_ANY);

const char fmt_str1[] = "netif: seq:%lu, ack:%lu, ";
bpf_trace_printk(fmt_str1, sizeof(fmt_str1), ts_key.seq, ts_key.ack);

    } else if(hook_point == IP_RECV_SKB) {

        ts_value->ip_recv = timestamp;
        bpf_map_update_elem(&recv_timestamp_hash, &ts_key, ts_value, BPF_ANY);

// const char fmt_str1[] = "ip: seq:%lu, ack:%lu, ";
// bpf_trace_printk(fmt_str1, sizeof(fmt_str1), ts_key.seq, ts_key.ack);

    } else {
        char fmt_str1[] = "hook point type error";
        bpf_trace_printk(fmt_str1, sizeof(fmt_str1));
        return false;
    }
	
    return true;
}



struct netif_receive_skb_args
{
    uint64_t pad;
    struct sk_buff *skb;
};

SEC("tracepoint/net/netif_receive_skb")
int netif_rx_hook(struct netif_receive_skb_args *args)
{
    u64 netif_timestamp = bpf_ktime_get_ns();
    
    struct sk_buff *skb = args->skb;

    if(!update_timestamp_hash_map(skb, netif_timestamp, NETIF_RECV_SKB, NULL)) {
        return 0;
    }

	return 0;
}

SEC("kprobe/ip_rcv")
int ip_rcv_hook(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
    u64 ip_timestamp = bpf_ktime_get_ns();
    
    if(!update_timestamp_hash_map(skb, ip_timestamp, IP_RECV_SKB, NULL)) {
        return 0;
    }

	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv_hook(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
    u64 tcp_timestamp = bpf_ktime_get_ns();

    struct tcphdr tcphdr = {0};
    if (!parse_tcp_hdr(skb, &tcphdr)) {
        return 0;
    }

    struct timestamp_key ts_key = {
        .seq = tcphdr.seq,
        .ack = tcphdr.ack_seq,
    };

    struct recv_timestamp_event_t* ts_value;
    ts_value = bpf_map_lookup_elem(&recv_timestamp_hash, &ts_key);
    if (!ts_value) {
        return false;
    }
    ts_value->tcp_recv = tcp_timestamp;

    int event_ret = bpf_perf_event_output(ctx, &recv_timestamp_events, BPF_F_CURRENT_CPU, ts_value, sizeof(struct recv_timestamp_event_t));

    bpf_map_delete_elem(&recv_timestamp_hash, &ts_key);

	return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
