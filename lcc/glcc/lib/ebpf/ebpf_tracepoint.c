#include "ebpf_tracepoint.h"
#include <linux/tracepoint.h>
#include <linux/ftrace_event.h>
#include <linux/string.h>
#include "allsyms.h"

#include <linux/skbuff.h>

struct bpf_tp_list
{
    struct list_head lists;
    struct bpf_prog *prog;
    void *func;
    char name[128];
};

static struct bpf_tp_list tp_list = {0};
static int bpf_tp_list_init = 0;


static int ebpf_net_dev_xmit(void *data, void *skbaddr, int rc, void *dev, int len)
{
// trace_net_dev_xmit(skb, rc, dev, len);
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args{
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
    ret = prog->bpf_func(&arg, prog->insnsi);
    return ret;
}

static int ebpf_netif_receive_skb(void *data, struct sk_buff *skb)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args{
        struct trace_entry entry;
        struct sk_buff *skb;
        unsigned int len;
    } arg = {
        .skb = skb,
        .len = skb->len,
    };
    ret = prog->bpf_func(&arg, prog->insnsi);
    return ret;
}

static int ebpf_sched_wakeup(void *data, struct task_struct *p, int success)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args{
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
    ret = prog->bpf_func(&arg, prog->insnsi);
    return ret;
}

static int ebpf_softirq_raise(void *data, unsigned int vec_nr)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args{
        struct trace_entry entry;
        unsigned int vec;
    } arg = {
        .vec = vec_nr,
    };
    ret = prog->bpf_func(&arg, prog->insnsi);
    return ret;
}

static int ebpf_net_dev_queue(void *data, struct sk_buff *skb)
{
    unsigned int ret;
    struct bpf_prog *prog = (struct bpf_prog *)data;
    struct args{
        struct trace_entry entry;
        struct sk_buff *skb;
        unsigned int len;
    } arg = {
        .skb = skb,
        .len = skb->len,
    };
    ret = prog->bpf_func(&arg, prog->insnsi);
    return ret;
}

struct tracepoints_table {
    const char *name;
    void *func;
};

static struct tracepoints_table table[] = 
{
    {.name = "net_dev_queue", .func = ebpf_net_dev_queue},
    {.name = "softirq_raise", .func = ebpf_softirq_raise},
    {.name = "sched_wakeup", .func = ebpf_sched_wakeup},
    {.name = "netif_receive_skb", .func = ebpf_netif_receive_skb},
    {.name = "net_dev_xmit", .func = ebpf_net_dev_xmit},
};

void *get_func(char *name)
{
    int i;
    for (i=0;i<sizeof(table)/sizeof(struct tracepoints_table); i++)
    {
        if (strcmp(table[i].name, name) == 0)
        {
            return table[i].func;
        }
    }
    return NULL;
}

int ebpf_register_tp(struct bpf_prog *prog, char *name)
{
    int ret;
    struct bpf_tp_list *entry;
    void *func;

    if (bpf_tp_list_init == 0)
    {
        INIT_LIST_HEAD(&tp_list.lists);
        bpf_tp_list_init = 1;
    }

    entry = kzalloc(sizeof(struct bpf_tp_list), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->prog = prog;
    strcpy(entry->name, name);
    printk("register tracepoint %s\n",name);

    func = get_func(name);
    if (!func)
    {
        printk("can not find tracepoint in tracepoint table.\n");
        return -ENOTSUPP;
    }
    entry->func = func;
    ret = tracepoint_probe_register(name, func, prog);
    if (ret < 0)
    {
        printk("register tracepoint failed for %s, error %d\n", name, ret);
        kfree(entry);
    }
    else
    {
        list_add(&entry->lists, &tp_list.lists);
    }
    return ret;
}

void ebpf_unregister_tp(struct bpf_prog *prog)
{
    struct bpf_tp_list *entry;

    if (bpf_tp_list_init == 0)
    {
        INIT_LIST_HEAD(&tp_list.lists);
        bpf_tp_list_init = 1;
    }

    list_for_each_entry(entry, &tp_list.lists, lists)
    {
        if (entry->prog == prog)
        {
            printk("unregister tracepoint\n");
            tracepoint_probe_unregister(entry->name, entry->func, prog);
            list_del(&entry->lists);
            kfree(entry);
            return;
        }
    }
}
