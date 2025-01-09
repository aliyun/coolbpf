#ifndef _PERF_HANDLE_H
#define _PERF_HANDLE_H

#include "arch_smb.h"
#include "uthash/utarray.h"

#define MAX_STACK_SIZE 32

typedef struct {
    u32 pid, tid;  // PERF_SAMPLE_TID
    regs_t callchain_nr;  // PERF_SAMPLE_CALLCHAIN
    regs_t *callchain;
    regs_t *chain_kernel;
    regs_t *chain_user;
    int chain_kernel_size;
    int chain_user_size;
    regs_t user_regs_nr;
    regs_t *user_regs;
    regs_t stack_size;  // PERF_SAMPLE_STACK_USER
    regs_t *stack;
}perf_sample_t;

typedef struct perf_sample_handle{
    UT_array *array;
    int (*cb)(perf_sample_t* sample);
    int flag;
}perf_sample_handle_t;

#endif
