#include "ebpf_kprobe.h"

#define KPROBE_MAGIC 0x22

static __always_inline void __bpf_kprobe_run(struct bpf_prog *prog, u64 *args)
{
    rcu_read_lock();
    preempt_disable();
    (void)BPF_PROG_RUN(prog, args);
    preempt_enable();
    rcu_read_unlock();
}

static int bpf_kprobe_dispatcher(struct kprobe *kp, struct pt_regs *regs)
{
    struct bpf_kprobe_event *bke = container_of(kp, struct bpf_kprobe_event, rp.kp);
    __bpf_kprobe_run(bke->prog, (u64 *)regs);
    return 0;
}

static int bpf_kretprobe_dispatcher(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct bpf_kprobe_event *bke = container_of(ri->rp, struct bpf_kprobe_event, rp);
    __bpf_kprobe_run(bke->prog, (u64 *)regs);
    return 0;
}

struct bpf_kprobe_event *alloc_bpf_kprobe_event(struct bpf_prog *prog, char *symbol, bool is_return)
{
    struct bpf_kprobe_event *bke;
    int err = 0;

    bke = kzalloc(sizeof(*bke), GFP_USER);
	if (!bke)
		return ERR_PTR(-ENOMEM);
    
    bke->is_return = is_return;
    // todo: alloc nhit

    if (symbol) {
        bke->symbol = kstrdup(symbol, GFP_USER);
        if (!bke->symbol) {
            err = -ENOMEM;
            goto free_bke;
        }
        bke->rp.kp.symbol_name = bke->symbol;
        bke->rp.kp.offset = 0;
    } else {
        printk(KERN_ERR "BUG: no symbol exists\n");
        err = -EINVAL;
        goto free_bke;
    }

    if (is_return)
        bke->rp.handler = bpf_kretprobe_dispatcher;
    else
        bke->rp.kp.pre_handler = bpf_kprobe_dispatcher;
    
    bke->prog = prog;
    return bke;

// free_symbol:
//     kfree(bke->symbol);
free_bke:
    kfree(bke);
    return ERR_PTR(err);
}

void free_bpf_kprobe_event(struct bpf_kprobe_event *bke)
{
    kfree(bke->symbol);
    kfree(bke);
}

int bpf_kprobe_register(struct bpf_kprobe_event *bke)
{
    if (bke->is_return)
        return register_kretprobe(&bke->rp);
    else 
        return register_kprobe(&bke->rp.kp);
}

void bpf_kprobe_unregister(struct bpf_kprobe_event *bke)
{
    if (bke->is_return)
        unregister_kretprobe(&bke->rp);
    else 
        unregister_kprobe(&bke->rp.kp);
}

