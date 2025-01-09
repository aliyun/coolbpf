#ifndef _PERF_SAMPLE_H
#define _PERF_SAMPLE_H

#include <linux/perf_event.h>
#include "arch_smb.h"
#include "perf_handle.h"

#define STACK_KERNEL_USER_DEVIDE (1UL << (8 * sizeof(regs_t) - 1))
#define STACK_IS_USER(X) (((X)&STACK_KERNEL_USER_DEVIDE) == 0)

void perf_live_free_sample(void* handle);
void* perf_live_on_start(int freq, int (*cb)(perf_sample_t* sample));
void perf_live_on_stop(void* handle);
int perf_live_on_read(void* handle);

#endif
