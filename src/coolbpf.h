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

#else

#define COOLBPF_MAJOR_VERSION 0
#define COOLBPF_MINOR_VERSION 1


#ifndef COOLBPF_API
#define COOLBPF_API __attribute__((visibility("default")))
#endif

/**
 * @brief Parameters required to create perf threads
 * 
 */
struct perf_thread_arguments {
    int mapfd;                          /**< fd of perf event map */
    perf_buffer_sample_fn sample_cb;    /**< callback function */
    perf_buffer_lost_fn lost_cb;        /**< callback function when the event is lost */
    int pg_cnt;                         /**< perf buffer size in page, default is 128 page */
    int timeout_ms;                     /**< timeout of perf poll in ms, default is 100ms */
};

/**
 * @brief get coolbpf major verison
 * 
 * @return uint32_t 
 */
COOLBPF_API uint32_t coolbpf_major_version();

/**
 * @brief get coolbpf minor version
 * 
 * @return uint32_t 
 */
COOLBPF_API uint32_t coolbpf_minor_version();

/**
 * @brief get coolbpf version as string
 * 
 * @return const char* 
 */
COOLBPF_API const char *coolbpf_version_string(void);

/**
 * @brief Create a perf thread to receive perf events
 * 
 * @param mapfd fd of map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY
 * @return pthread_t thread id, you can use it later to destroy the thread
 */
COOLBPF_API pthread_t initial_perf_thread(struct perf_thread_arguments *args);

/**
 * @brief Destroy perf thread
 * 
 * @param thread perf thread id
 * @return int 
 */
COOLBPF_API int kill_perf_thread(pthread_t thread);

#endif

#endif
