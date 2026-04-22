#pragma once

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"
#include "type.h"

struct secure_tailcall_stack {
    enum secure_funcs func;
	union {
        struct tcp_data_t tcp_data;
        struct file_data_t file_data;
    };
} __attribute__((packed));