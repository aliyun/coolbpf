

#ifndef __BPF_CORE_H
#define __BPF_CORE_H

#if 0

#ifndef bpf_core_field_offset
#define bpf_core_field_offset(field...) \
    __builtin_preserve_field_info(___bpf_field_ref(field), BPF_FIELD_BYTE_OFFSET)
#endif

struct task_struct_____state
{
    unsigned int __state;
};
struct task_struct___state
{
    volatile long state;
};

static __always_inline u64 bpf_core_task_struct_state_offset(void *task)
{
    struct task_struct_____state *__state = task;
    struct task_struct___state *state = task;
    if (bpf_core_field_exists(__state->__state))
    {
        return bpf_core_field_offset(struct task_struct_____state, __state);
    }
    else
    {
        return bpf_core_field_offset(struct task_struct___state, state);
    }
}

static __always_inline u32 bpf_core_task_struct_state_size(void *task)
{
    struct task_struct_____state *__state = task;
    struct task_struct___state *state = task;
    if (bpf_core_field_exists(__state->__state))
    {
        return bpf_core_field_size(__state->__state);
    }
    else
    {
        return bpf_core_field_size(state->state);
    }
}

static __always_inline u64 bpf_core_task_struct_state_addr(void *task)
{
    return bpf_core_task_struct_state_offset(task) + (u64)task;
}

static __always_inline long bpf_core_task_struct_state(void *task)
{
    long res = 0;
    bpf_probe_read(&res, bpf_core_task_struct_state_size(task), bpf_core_task_struct_state_addr(task));
    return res;
}
#endif 

static __always_inline bool bpf_core_task_struct_thread_info_exist(struct task_struct *task)
{
    return bpf_core_field_exists(task->thread_info);
}

#endif