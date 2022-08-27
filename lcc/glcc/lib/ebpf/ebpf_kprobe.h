#ifndef __EBPF_KPROBE_H_
#define __EBPF_KPROBE_H_
#include <linux/kprobes.h>
#include "linux/filter.h"

struct bpf_kprobe_event
{
    unsigned long __percpu *nhit;
    const char *symbol;
    struct kretprobe rp;    // 3.10 kretprobe does not have kp
    struct kprobe kp;
    struct bpf_prog *prog;
};

struct bpf_kprobe_event *alloc_bpf_kprobe_event(struct bpf_prog *prog, char *symbol, bool is_return);

int bpf_kprobe_register(struct bpf_kprobe_event *bke);
void bpf_kprobe_unregister(struct bpf_kprobe_event *bke);

#endif
