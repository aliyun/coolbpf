#ifndef __EBPF_KPROBE_H_
#define __EBPF_KPROBE_H_
#include <linux/kprobes.h>
#include "linux/filter.h"


int ebpf_register_kprobe(struct bpf_prog *bp, char *sym);
void ebpf_unregister_kprobe(struct bpf_prog *bp);

#endif
