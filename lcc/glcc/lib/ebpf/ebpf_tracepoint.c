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
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_netif_receive_skb(void *data, struct sk_buff *skb)
{
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
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_sched_wakeup(void *data, struct task_struct *p, int success)
{
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
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_sched_wakeup_new(void *data, struct task_struct *p, int success)
{
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
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_sched_switch(void *data, struct task_struct *prev, struct task_struct *next)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        char prev_comm[TASK_COMM_LEN];
        pid_t prev_pid;
        int prev_prio;
        long prev_state;
        char next_comm[TASK_COMM_LEN];
        pid_t next_pid;
        int next_prio;
    } arg = {
        .prev_pid = prev->pid,
        .prev_prio = prev->prio,
        .prev_state = prev->state,
        .next_pid = next->pid,
        .next_prio = next->prio,
    };
    memcpy(arg.prev_comm, prev->comm, TASK_COMM_LEN);
    memcpy(arg.next_comm, next->comm, TASK_COMM_LEN);
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_softirq_raise(void *data, unsigned int vec_nr)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args
    {
        struct trace_entry entry;
        unsigned int vec;
    } arg = {
        .vec = vec_nr,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_net_dev_queue(void *data, struct sk_buff *skb)
{
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
    __bpf_tracepoint_run(prog, (u64 *)&arg);
    return 0;
}

static int ebpf_sched_stat_template(void *data, struct task_struct *tsk, u64 delay)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        struct trace_entry entry;
        char comm[TASK_COMM_LEN];
        pid_t pid;
        u64 delay;
    } arg = {
        .pid = tsk->pid,
        .delay = delay,
    };
     memcpy(arg.comm, tsk->comm, TASK_COMM_LEN);
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_workqueue_execute_start(void *data, struct work_struct *work)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        void *work;
        void *function;
    } arg = {
        .work = work,
        .function = work->func,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_workqueue_work_template(void *data, struct work_struct *work)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        void *work;
    } arg = {
        .work = work,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_mm_vmscan_direct_reclaim_begin_template(void *data, int order, int may_writepage, gfp_t gfp_flags)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        int order;
        gfp_t gfp_flags;
    } arg = {
        .order = order,
        .gfp_flags = gfp_flags,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_mm_vmscan_direct_reclaim_end_template(void *data, unsigned long nr_reclaimed)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        unsigned long nr_reclaimed;
    } arg = {
        .nr_reclaimed = nr_reclaimed,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_mm_vmscan_memcg_reclaim_begin_template(void *data, int order, int may_writepage, gfp_t gfp_flags)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        int order;
        gfp_t gfp_flags;
    } arg = {
        .order = order,
        .gfp_flags = gfp_flags,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static int ebpf_mm_vmscan_memcg_reclaim_end_template(void *data, unsigned long nr_reclaimed)
{
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args {
        unsigned long nr_reclaimed;
    } arg = {
        .nr_reclaimed = nr_reclaimed,
    };
    __bpf_tracepoint_run(prog, (u64 *)&arg);

    return 0;
}

static struct bpf_tracepoint_event events_table[] =
    {
        {.name = "net_dev_queue", .bpf_func = ebpf_net_dev_queue},
        {.name = "softirq_raise", .bpf_func = ebpf_softirq_raise},
        {.name = "sched_wakeup", .bpf_func = ebpf_sched_wakeup},
        {.name = "sched_wakeup_new", .bpf_func = ebpf_sched_wakeup_new},
        {.name = "sched_switch", .bpf_func = ebpf_sched_switch},
        {.name = "netif_receive_skb", .bpf_func = ebpf_netif_receive_skb},
        {.name = "net_dev_xmit", .bpf_func = ebpf_net_dev_xmit},
        {.name = "sched_stat_wait", .bpf_func = ebpf_sched_stat_template},
        {.name = "sched_stat_iowait", .bpf_func = ebpf_sched_stat_template},
        {.name = "sched_stat_blocked", .bpf_func = ebpf_sched_stat_template},
        {.name = "workqueue_execute_start", .bpf_func = ebpf_workqueue_execute_start},
        {.name = "workqueue_execute_end", .bpf_func = ebpf_workqueue_work_template},
        {.name = "workqueue_activate_work", .bpf_func = ebpf_workqueue_work_template},
        {.name = "mm_vmscan_direct_reclaim_begin", .bpf_func = ebpf_mm_vmscan_direct_reclaim_begin_template},
        {.name = "mm_vmscan_direct_reclaim_end", .bpf_func = ebpf_mm_vmscan_direct_reclaim_end_template},
        {.name = "mm_vmscan_memcg_reclaim_begin", .bpf_func = ebpf_mm_vmscan_memcg_reclaim_begin_template},
        {.name = "mm_vmscan_memcg_reclaim_end", .bpf_func = ebpf_mm_vmscan_memcg_reclaim_end_template},
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
