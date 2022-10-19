//
// Created by 廖肇燕 on 2021/7/16.
//

#ifndef LBC_LBC_H
#define LBC_LBC_H

#include "vmlinux.h"

#ifndef _LINUX_POSIX_TYPES_H
#define _LINUX_POSIX_TYPES_H
#endif
#ifndef _LINUX_POSIX_TYPES_H
#define __ASM_GENERIC_POSIX_TYPES_H
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

ENUM_DEFINE_STACK_CMP

ENUM_DEFINE_BPF_ANY

#ifndef KERN_STACKID_FLAGS
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#endif
#ifndef USER_STACKID_FLAGS
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)
#endif

typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;

#define LBC_PERF_OUTPUT(MAPS, CELL, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
        .key_size = sizeof(int), \
        .value_size = sizeof(s32), \
        .max_entries = ENTRIES, \
    }

#define LBC_HASH(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_ARRAY(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_ARRAY, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_HIST2(MAPS) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_ARRAY, \
        .key_size = sizeof(int), \
        .value_size = sizeof(long), \
        .max_entries = 64, \
    }

#define LBC_HIST10(MAPS) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_ARRAY, \
        .key_size = sizeof(int), \
        .value_size = sizeof(long), \
        .max_entries = 20, \
    }

#define LBC_LRU_HASH(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_LRU_HASH, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_PERCPU_HASH(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_PERCPU_HASH, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_LRU_PERCPU_HASH(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_LRU_PERCPU_HASH, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_PERCPU_ARRAY(MAPS, KEY_T, VALUE_T, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_PERCPU_ARRAY, \
        .key_size = sizeof(KEY_T), \
        .value_size = sizeof(VALUE_T), \
        .max_entries = ENTRIES, \
    }

#define LBC_STACK(MAPS, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_STACK_TRACE, \
        .key_size = sizeof(u32), \
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64), \
        .max_entries = ENTRIES, \
    }

#define _(P) ({typeof(P) val = 0; bpf_probe_read((void*)&val, sizeof(val), (const void*)&P); val;})

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef NULL
#define NULL ((void*)0)
#endif
#ifndef ntohs
#define ntohs(x) (0xff00 & x << 8) \
                |(0x00ff & x >> 8)
#endif
#ifndef ntohl
#define ntohl(x) (0xff000000 & x << 24) \
                |(0x00ff0000 & x <<  8) \
                |(0x0000ff00 & x >>  8) \
                |(0x000000ff & x >> 24)
#endif
#ifndef ntohll
#define ntohll(x) ((((long long)ntohl(x))<<32) + (ntohl((x)>>32)))
#endif
#define BPF_F_CURRENT_CPU 0xffffffffULL

#ifdef LBC_DEBUG
#define lbc_debug(...) bpf_printk(__VA_ARGS__)
#else
#define lbc_debug(...)
#endif


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

#endif //LBC_LBC_H
