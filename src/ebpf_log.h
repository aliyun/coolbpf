#pragma once

#define BPF_NO_GLOBAL_DATA

/* Macro to output debug logs to /sys/kernel/debug/tracing/trace_pipe
 */
#ifdef COOLBPF_DEBUG
#include <bpf/bpf_tracing.h>
#define BPF_DEBUG(__fmt, ...) bpf_printk(__fmt, ##__VA_ARGS__)
#else
// No op
#define BPF_DEBUG(__fmt, ...)
#endif