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

#define MAX_STACK_DEPTH     20 

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

    if (value < 1) {
        goto end;
    }

    #pragma unroll
    for (i = 32; i > 0; i /= 2) {
        long v = 1ULL << i;
        if (value >= v) {
            n += i;
            value = value >> i;
        }
    }
end:
    return n;
}

#define NUM_E16 10000000000000000ULL
#define NUM_E8  100000000ULL
#define NUM_E4  10000ULL
#define NUM_E2  100ULL
#define NUM_E1  10ULL
static inline int fast_log10(long v)
{
    int n = 0;
    if (v >= NUM_E16) {n += 16; v /= NUM_E16;}
    if (v >=  NUM_E8) {n +=  8; v /=  NUM_E8;}
    if (v >=  NUM_E4) {n +=  4; v /=  NUM_E4;}
    if (v >=  NUM_E2) {n +=  2; v /=  NUM_E2;}
    if (v >=  NUM_E1) {n +=  1;}
    return n;
}

static inline void add_hist(struct bpf_map_def* maps, int k, int v) {
    u64 *pv = bpf_map_lookup_elem(maps, &k);
    if (pv) {
        __sync_fetch_and_add(pv, v);
    }
}

#define incr_hist(maps, k) add_hist(maps, k, 1)

static inline void hist2_push(struct bpf_map_def* maps, long v) {
    int k = fast_log2(v);
    incr_hist(maps, k);
}

static inline void hist10_push(struct bpf_map_def* maps, long v) {
    int k = fast_log10(v);
    incr_hist(maps, k);
}

char _license[] SEC("license") = "GPL";

#endif