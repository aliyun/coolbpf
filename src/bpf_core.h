

#ifndef __BPF_CORE_H
#define __BPF_CORE_H

struct task_struct_____state
{
    unsigned int __state;
};
struct task_struct___state
{
    volatile long state;
};

static __always_inline long bpf_core_task_struct_state(void *task)
{
    long res = 0;
    struct task_struct_____state *__state = task;
    struct task_struct___state *state = task;
    if (bpf_core_field_exists(__state->__state))
    {
        bpf_core_read(&res, sizeof(__state->__state), &__state->__state);
    }
    else
    {
        bpf_core_read(&res, sizeof(state->state), &state->state);
    }
    return res;
}

#endif