//
// Created by 廖肇燕 on 2021/7/15.
//
#include "lbc.h"

struct data_t {
    u32 pid;
    u32 stack_id;
    u32 parent_id;
    u64 cookie;
    char comm[16];
} ;

LBC_PERF_OUTPUT(my_map, struct data_t, 1024);
LBC_HASH(pids, u64, u32, 1024);
LBC_STACK(callStack,32);

SEC("kprobe/_do_fork")
int bpf_prog1(struct pt_regs *ctx)
{
    struct data_t data = {0, 0};
    u32 *pcnt, cnt = 1;
    u32 pid;
    struct task_struct *parent;


    data.pid = bpf_get_current_pid_tgid()>>32;
    data.cookie = 0x12345678;
    bpf_get_current_comm(&(data.comm), 16);
    data.stack_id = bpf_get_stackid(ctx, &callStack, KERN_STACKID_FLAGS);
    bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    data.parent_id = BPF_CORE_READ(parent, pid);

    pid = data.pid;
    pcnt =  bpf_map_lookup_elem(&pids, &pid);
    if (pcnt) {
        cnt = *pcnt + 1;
        bpf_printk("count: %d\n", cnt);
    } else {
        cnt = 1;
    }
    bpf_map_update_elem(&pids, &pid, &cnt, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
