#ifndef __EBPF_TRACEPOINT_H_
#define __EBPF_TRACEPOINT_H_
#include "linux/filter.h"

struct bpf_tracepoint_event
{
    void *category;
    void *name;
    // void *tp;
    void *bpf_func;
};

struct bpf_tracepoint_event *bpf_find_tracepoint(char *tp_name);
int bpf_tracepoint_register(struct bpf_tracepoint_event *bte, struct bpf_prog *prog);
void bpf_tracepoint_unregister(struct bpf_tracepoint_event *bte, struct bpf_prog *prog);

#endif
