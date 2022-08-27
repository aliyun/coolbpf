#include "ebpf_tracepoint.h"
#include <linux/tracepoint.h>
#include <linux/ftrace_event.h>
#include <linux/string.h>
#include "allsyms.h"

#include <linux/skbuff.h>

static __always_inline void __bpf_tracepoint_run(struct bpf_prog *prog, u64 *args)
{
    rcu_read_lock();
    preempt_disable();
    (void)BPF_PROG_RUN(prog, args);
    preempt_enable();
    rcu_read_unlock();
}

static int ebpf_net_dev_xmit(void *data, void *skbaddr, int rc, void *dev, int len)
{
    // trace_net_dev_xmit(skb, rc, dev, len);
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        void *skbaddr;
        unsigned int len;
        int rc;
        u32 __data_loc_name;
        char __data[0];
    } arg = {
        .skbaddr = skbaddr,
        .rc = rc,
        .len = len,
    };
    __bpf_tracepoint_run(prog, &arg);
    return ret;
}

static int ebpf_netif_receive_skb(void *data, struct sk_buff *skb)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        struct sk_buff *skb;
        unsigned int len;
    } arg = {
        .skb = skb,
        .len = skb->len,
    };
    __bpf_tracepoint_run(prog, &arg);
    return ret;
}

static int ebpf_sched_wakeup(void *data, struct task_struct *p, int success)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        char comm[TASK_COMM_LEN];
        pid_t pid;
        int prio;
        int success;
        int target_cpu;
    } arg = {
        .pid = p->pid,
        .prio = p->prio,
        .success = success,
        .target_cpu = task_cpu(p),
    };
    memcpy(arg.comm, p->comm, TASK_COMM_LEN);
    __bpf_tracepoint_run(prog, &arg);
    return ret;
}

static int ebpf_softirq_raise(void *data, unsigned int vec_nr)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        unsigned int vec;
    } arg = {
        .vec = vec_nr,
    };
    __bpf_tracepoint_run(prog, &arg);
    return ret;
}

static int ebpf_net_dev_queue(void *data, struct sk_buff *skb)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        struct sk_buff *skb;
        unsigned int len;
    } arg = {
        .skb = skb,
        .len = skb->len,
    };
    __bpf_tracepoint_run(prog, &arg);
    return ret;
}

static struct bpf_tracepoint_event events_table[] =
    {
        {.name = "net_dev_queue", .bpf_func = ebpf_net_dev_queue},
        {.name = "softirq_raise", .bpf_func = ebpf_softirq_raise},
        {.name = "sched_wakeup", .bpf_func = ebpf_sched_wakeup},
        {.name = "netif_receive_skb", .bpf_func = ebpf_netif_receive_skb},
        {.name = "net_dev_xmit", .bpf_func = ebpf_net_dev_xmit},
};

struct bpf_tracepoint_event *bpf_find_tracepoint(char *tp_name)
{
    int i;
    for (i = 0; i < sizeof(events_table) / sizeof(struct bpf_tracepoint_event); i++)
    {
        if (strcmp(events_table[i].name, tp_name) == 0)
        {
            return &events_table[i];
        }
    }
    return NULL;
}

int bpf_tracepoint_register(struct bpf_tracepoint_event *bte, struct bpf_prog *prog)
{
    return tracepoint_probe_register(bte->name, bte->bpf_func, prog);
}

void bpf_tracepoint_unregister(struct bpf_tracepoint_event *bte, struct bpf_prog *prog)
{
    tracepoint_probe_unregister(bte->name, bte->bpf_func, prog);
}
