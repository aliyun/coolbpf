/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_PERF_EVENT_H__
#define _UAPI__LINUX_BPF_PERF_EVENT_H__

// #include <asm/bpf_perf_event.h>
#include <linux/ptrace.h>
/* Export kernel pt_regs structure */
typedef struct pt_regs bpf_user_pt_regs_t;

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
};

#endif /* _UAPI__LINUX_BPF_PERF_EVENT_H__ */
