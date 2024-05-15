/**
 * @file coolbpf_bpf.h
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief
 * @version 0.1
 * @date 2022-12-26
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef COOLBPF_BPF_H
#define COOLBPF_BPF_H
#define BPF_NO_GLOBAL_DATA
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_core.h"

#define MAX_STACK_DEPTH 20

// from linux/icmp.h
#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4   /* Source Quench		*/
#define ICMP_REDIRECT 5        /* Redirect (change route)	*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIME_EXCEEDED 11  /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12  /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/
#define NR_ICMP_TYPES 18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable		*/
#define ICMP_HOST_UNREACH 1 /* Host Unreachable		*/
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH 3 /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED 5    /* Source Route failed		*/
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13   /* Packet filtered */
#define ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define ICMP_PREC_CUTOFF 15    /* Precedence cut off */
#define NR_ICMP_UNREACH 15     /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET 0     /* Redirect Net			*/
#define ICMP_REDIR_HOST 1    /* Redirect Host		*/
#define ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL 0      /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME 1 /* Fragment Reass time exceeded	*/

/**
 * @brief bpf helper function: get timestamp
 *
 */
#define ns() bpf_ktime_get_ns()
/**
 * @brief bpf helper function: get pid
 *
 */
#define pid() (bpf_get_current_pid_tgid() >> 32)
/**
 * @brief bpf helper function: get tid
 *
 */
#define tid() ((u32)bpf_get_current_pid_tgid())
/**
 * @brief bpf helper function: get comm of current
 *
 */
#define comm(c) bpf_get_current_comm(c, sizeof(c))
/**
 * @brief bpf helper function: get cpu number
 *
 */
#define cpu() bpf_get_smp_processor_id()

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct                                                          \
    {                                                               \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

/**
 * @brief One line of code to create BPF_MAP_TYPE_HASH
 *
 */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_LRU_HASH
 *
 */
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_ARRAY
 *
 */
#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_PERCPU_ARRAY
 *
 */
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_PERF_EVENT_ARRAY
 *
 */
#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

static inline int fast_log2(long value)
{
    int n = 0;
    int i;

    if (value < 1)
    {
        goto end;
    }

#pragma unroll
    for (i = 32; i > 0; i /= 2)
    {
        long v = 1ULL << i;
        if (value >= v)
        {
            n += i;
            value = value >> i;
        }
    }
end:
    return n;
}

#define NUM_E16 10000000000000000ULL
#define NUM_E8 100000000ULL
#define NUM_E4 10000ULL
#define NUM_E2 100ULL
#define NUM_E1 10ULL
static inline int fast_log10(long v)
{
    int n = 0;
    if (v >= NUM_E16)
    {
        n += 16;
        v /= NUM_E16;
    }
    if (v >= NUM_E8)
    {
        n += 8;
        v /= NUM_E8;
    }
    if (v >= NUM_E4)
    {
        n += 4;
        v /= NUM_E4;
    }
    if (v >= NUM_E2)
    {
        n += 2;
        v /= NUM_E2;
    }
    if (v >= NUM_E1)
    {
        n += 1;
    }
    return n;
}

static inline void add_hist(struct bpf_map_def *maps, int k, int v)
{
    u64 *pv = bpf_map_lookup_elem(maps, &k);
    if (pv)
    {
        __sync_fetch_and_add(pv, v);
    }
}

#define incr_hist(maps, k) add_hist(maps, k, 1)

static inline void hist2_push(struct bpf_map_def *maps, long v)
{
    int k = fast_log2(v);
    incr_hist(maps, k);
}

static inline void hist10_push(struct bpf_map_def *maps, long v)
{
    int k = fast_log10(v);
    incr_hist(maps, k);
}

char _license[] SEC("license") = "GPL";

#endif