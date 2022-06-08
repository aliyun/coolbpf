//
// Created by 廖肇燕 on 2021/7/16.
//

#ifndef LBC_LBC_H
#define LBC_LBC_H

#define _LINUX_POSIX_TYPES_H
#define __ASM_GENERIC_POSIX_TYPES_H

#define PERF_MAX_STACK_DEPTH 127
#define BPF_F_FAST_STACK_CMP	(1ULL << 9)

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;

enum {
    BPF_ANY         = 0, /* create new element or update existing */
    BPF_NOEXIST     = 1, /* create new element if it didn't exist */
    BPF_EXIST       = 2, /* update existing element */
    BPF_F_LOCK      = 4, /* spin_lock-ed map_lookup/map_update */
};

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

#define LBC_STACK(MAPS, ENTRIES) \
    struct bpf_map_def SEC("maps") MAPS = { \
        .type = BPF_MAP_TYPE_STACK_TRACE, \
        .key_size = sizeof(u32), \
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64), \
        .max_entries = ENTRIES, \
    }

#define _(P) ({typeof(P) val = 0; bpf_probe_read((void*)&val, sizeof(val), (const void*)&P); val;})

#include "vmlinux.h"
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

#endif //LBC_LBC_H
