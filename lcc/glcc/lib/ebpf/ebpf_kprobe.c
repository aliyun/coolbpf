#include "ebpf_kprobe.h"

#define KPROBE_MAGIC 0x22

struct bpf_kprobe_list
{
    struct list_head lists;
    struct bpf_prog *prog;
    struct kprobe kp;
};

static struct bpf_kprobe_list kprobe_list = {0};
static int bpf_kprobe_list_init = 0;

static int ebpf_handle_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct bpf_kprobe_list *entry = container_of(kp, struct bpf_kprobe_list, kp);
    unsigned int ret;
    ret = entry->prog->bpf_func(regs, entry->prog->insnsi);
    return ret;
}

int ebpf_register_kprobe(struct bpf_prog *prog, char *sym)
{
    int ret;
    struct bpf_kprobe_list *entry;

    if (bpf_kprobe_list_init == 0)
    {
        INIT_LIST_HEAD(&kprobe_list.lists);
        bpf_kprobe_list_init = 1;
    }

    entry = kzalloc(sizeof(struct bpf_kprobe_list), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->prog = prog;
    entry->kp.symbol_name = sym;
    entry->kp.pre_handler = ebpf_handle_pre;

    ret = register_kprobe(&entry->kp);
    if (ret < 0)
    {
        printk("register kprobe failed for %s, error %d\n", sym, ret);
        kfree(entry);
    }
    else
    {
        list_add(&entry->lists, &kprobe_list.lists);
    }

    return ret;
}

void ebpf_unregister_kprobe(struct bpf_prog *prog)
{
    struct bpf_kprobe_list *entry;
    // if (bp->probe && ek->magic == KPROBE_MAGIC)
    // {
    //     printk("unregister kprobe\n");
    //     unregister_kprobe(&ek->kp);
    //     kzfree(ek);
    // }

    if (bpf_kprobe_list_init == 0)
    {
        INIT_LIST_HEAD(&kprobe_list.lists);
        bpf_kprobe_list_init = 1;
    }

    list_for_each_entry(entry, &kprobe_list.lists, lists)
    {
        if (entry->prog == prog)
        {
            printk("unregister kprobe\n");
            unregister_kprobe(&entry->kp);
            list_del(&entry->lists);
            kfree(entry);
            return;
        }
    }
}
