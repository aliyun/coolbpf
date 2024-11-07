/**
 * @author Bin Yang (binyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_COMMON_BPF_H__
#define __ENETSTL_COMMON_BPF_H__

#include <vmlinux.h>
#include <linux/errno.h>
#include "coolbpf.h"

#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0

#define STR(s) #s
#define XSTR(s) STR(s)

#define asm_bound_check(variable, max_size)                        \
	({                                                         \
		asm volatile("%[tmp] &= " XSTR(max_size - 1) " \n" \
			     : [tmp] "+&r"(variable));             \
	})

/*
*DEBUG: LEVEL=4
*INFO: LEVEL=3
*WARN: LEVEL=2
*ERROR: LEVEL=1
*/

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(FMT, ...) ({ bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__); })
#else
#define log_debug(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(FMT, ...) ({ bpf_printk("[INFO]" FMT, ##__VA_ARGS__); })
#else
#define log_info(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(FMT, ...) ({ bpf_printk("[WARN]" FMT, ##__VA_ARGS__); })
#else
#define log_warn(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define log_error(FMT, ...) ({ bpf_printk("[ERROR]" FMT, ##__VA_ARGS__); })
#else
#define log_error(fmt, ...) ({})
#endif

#define SHIFT_TO_SIZE(_shift) ((unsigned long)1 << (_shift))

#define BOUND_INDEX(idx, shift)                             \
	({                                                  \
		typeof(idx) __idx;                          \
		__idx = (idx) & (SHIFT_TO_SIZE(shift) - 1); \
	})

#define ETH_P_IP 0x0800

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct __ports {
	__be16 src_port;
	__be16 dst_port;
} __attribute__((packed));

#define CHECK_BOUND(p, data_end)                      \
	do {                                          \
		if ((void *)((p) + 1) > (data_end)) { \
			goto out_of_bound;            \
		}                                     \
	} while (0)

struct hdr_cursor {
	void *pos;
};


/**
 * parse_pkt_5tuple() - Parse into packet 5-tuple.
 * 
 * @nh: Cursor
 * @data_end: `(void *)(long)ctx->data_end`
 * @pkt: Packet 5-tuple to parse into (source/destination IPs/ports are not
 *       converted to host byte order)
 * 
 * Return: 0 if successful, `-EINVAL` if failed to parse.
 */
static __always_inline int32_t parse_pkt_5tuple(struct hdr_cursor *nh,
						void *data_end,
						struct pkt_5tuple *pkt)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct __ports *ports;

	eth = nh->pos;
	CHECK_BOUND(eth, data_end);
	if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
		bpf_printk(
			" cannot parse pkt_5tuple: unsupported protocol in Ethernet header: %d (!= %d)",
			eth->h_proto, bpf_htons(ETH_P_IP));
		goto unsupported;
	}
	nh->pos += sizeof(*eth);

	ip = nh->pos;
	CHECK_BOUND(ip, data_end);
	if (unlikely(ip->protocol != IPPROTO_TCP &&
		     ip->protocol != IPPROTO_UDP)) {
		bpf_printk(
			" cannot parse pkt_5tuple: unsupported protocol in IP header %d (not in %d, %d)",
			ip->protocol, IPPROTO_TCP, IPPROTO_UDP);
		goto unsupported;
	}
	nh->pos += sizeof(*ip);

	ports = nh->pos;
	CHECK_BOUND(ports, data_end);

	pkt->src_ip = ip->saddr;
	pkt->dst_ip = ip->daddr;
	pkt->proto = ip->protocol;
	pkt->src_port = ports->src_port;
	pkt->dst_port = ports->dst_port;

	return 0;

out_of_bound:
unsupported:
	return -22;
}

#endif