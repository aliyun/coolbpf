#ifndef __EBPF_TRACEPOINT_H_
#define __EBPF_TRACEPOINT_H_
#include "linux/filter.h"

int ebpf_register_tp(struct bpf_prog *bp, char *sym);
void ebpf_unregister_tp(struct bpf_prog *bp);

#endif
