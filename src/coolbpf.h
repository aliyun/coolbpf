/**
 * @file coolbpf.h
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief 
 * @version 0.1
 * @date 2022-12-22
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef __COOLBPF_H
#define __COOLBPF_H

#ifdef __VMLINUX_H__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ns() bpf_ktime_get_ns()
#define pid() (bpf_get_current_pid_tgid() >> 32)
#define tid() ((u32)bpf_get_current_pid_tgid())
#define comm(c) bpf_get_current_comm(c, sizeof(c))
// return u32
#define cpu() bpf_get_smp_processor_id()

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct                                                          \
    {                                                               \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

#else

#define COOLBPF_MAJOR_VERSION 0
#define COOLBPF_MINOR_VERSION 1

/**
 * @brief get coolbpf major verison
 * 
 * @return uint32_t 
 */
uint32_t coolbpf_major_version();

/**
 * @brief get coolbpf minor version
 * 
 * @return uint32_t 
 */
uint32_t coolbpf_minor_version();

/**
 * @brief get coolbpf version as string
 * 
 * @return const char* 
 */
const char *coolbpf_version_string(void);



#endif

#endif
