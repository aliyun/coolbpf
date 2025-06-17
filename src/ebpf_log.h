#pragma once

#define BPF_NO_GLOBAL_DATA

/* Macro to output debug logs to /sys/kernel/debug/tracing/trace_pipe
 */
#ifdef BPF_DEBUG
#define BPF_DEBUG(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
// No op
#define BPF_DEBUG(fmt, ...)
#endif