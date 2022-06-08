#include "linux/config.h"
#include "allsyms.h"

#include <linux/file.h>

trace_printk_init_buffers_t trace_printk_init_buffers_p;
perf_prepare_sample_t perf_prepare_sample_p;
perf_output_begin_t perf_output_begin_p;
perf_output_sample_t perf_output_sample_p;
perf_output_end_t perf_output_end_p;
free_uid_t free_uid_p;
__vmalloc_node_range_t __vmalloc_node_range_p;
get_callchain_buffers_t get_callchain_buffers_p;
sha_init_t sha_init_p;
sha_transform_t sha_transform_p;
module_alloc_t module_alloc_p;
module_free_t module_free_p;
// struct file_operations *perf_fops_p;
ftrace_find_event_t ftrace_find_event_p;
perf_callchain_kernel_t perf_callchain_kernel_p;


int load_allsyms(void)
{
    trace_printk_init_buffers_p = (trace_printk_init_buffers_t)kallsyms_lookup_name("trace_printk_init_buffers");
    if (trace_printk_init_buffers_p == NULL)
        goto err;
	
	perf_prepare_sample_p = (perf_prepare_sample_t)kallsyms_lookup_name("perf_prepare_sample");
	if (perf_prepare_sample_p == NULL)
		goto err;
	
	perf_output_begin_p = (perf_output_begin_t)kallsyms_lookup_name("perf_output_begin");
	if (perf_output_begin_p == NULL)
		goto err;
	
	perf_output_sample_p = (perf_output_sample_t)kallsyms_lookup_name("perf_output_sample");
	if (perf_output_sample_p == NULL)
		goto err;

	perf_output_end_p = (perf_output_end_t)kallsyms_lookup_name("perf_output_end");
	if (perf_output_end_p == NULL)
		goto err;

    free_uid_p = (free_uid_t)kallsyms_lookup_name("free_uid");
    if (free_uid_p == NULL)
        goto err;

    __vmalloc_node_range_p = (__vmalloc_node_range_t)kallsyms_lookup_name("__vmalloc_node_range");
    if (__vmalloc_node_range_p == NULL)
        goto err;

	get_callchain_buffers_p = (get_callchain_buffers_t)kallsyms_lookup_name("get_callchain_buffers");
	if (get_callchain_buffers_p == NULL)
		goto err;
	
	sha_init_p = (sha_init_t)kallsyms_lookup_name("sha_init");
    if (sha_init_p == NULL)
        goto err;
	
	sha_transform_p = (sha_transform_t)kallsyms_lookup_name("sha_transform");
    if (sha_transform_p == NULL)
        goto err;
	
	module_alloc_p = (module_alloc_t)kallsyms_lookup_name("module_alloc");
	if (module_alloc_p == NULL)
        goto err;
	
	module_free_p = (module_free_t)kallsyms_lookup_name("module_free");
	if (module_free_p == NULL)
        goto err;
	
	// perf_fops_p = (struct file_operations *)kallsyms_lookup_name("perf_fops");
	// if (perf_fops_p == NULL)
	// 	goto err;

	ftrace_find_event_p = (ftrace_find_event_t)kallsyms_lookup_name("ftrace_find_event");
	if (ftrace_find_event_p == NULL)
        goto err;
	
	perf_callchain_kernel_p = (perf_callchain_kernel_t)kallsyms_lookup_name("perf_callchain_kernel");
	if (perf_callchain_kernel_p == NULL)
		goto err;

    return 0;
err:
	printk(KERN_NOTICE "Error to find function syms\n");
    return -EINVAL;
}

void perf_event_output(struct perf_event *event,
				struct perf_sample_data *data,
				struct pt_regs *regs)
{
	struct perf_output_handle handle;
	struct perf_event_header header;

	/* protect the callchain buffers */
	rcu_read_lock();

	perf_prepare_sample_p(&header, data, event, regs);

	if (perf_output_begin_p(&handle, event, header.size))
		goto exit;

	perf_output_sample_p(&handle, &header, data, event);

	perf_output_end_p(&handle);

exit:
	rcu_read_unlock();
}

struct file *perf_event_get(unsigned int fd)
{
	struct file *file;

	file = fget_raw(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	// if (file->f_op != &perf_fops) {
	// 	fput(file);
	// 	return ERR_PTR(-EBADF);
	// }

	return file;
}

static inline u64 perf_clock(void)
{
	return local_clock();
}

/*
 * State based event timekeeping...
 *
 * The basic idea is to use event->state to determine which (if any) time
 * fields to increment with the current delta. This means we only need to
 * update timestamps when we change state or when they are explicitly requested
 * (read).
 *
 * Event groups make things a little more complicated, but not terribly so. The
 * rules for a group are that if the group leader is OFF the entire group is
 * OFF, irrespecive of what the group member states are. This results in
 * __perf_effective_state().
 *
 * A futher ramification is that when a group leader flips between OFF and
 * !OFF, we need to update all group member times.
 *
 *
 * NOTE: perf_event_time() is based on the (cgroup) context time, and thus we
 * need to make sure the relevant context time is updated before we try and
 * update our timestamps.
 */

static __always_inline enum perf_event_active_state
__perf_effective_state(struct perf_event *event)
{
	struct perf_event *leader = event->group_leader;

	if (leader->state <= PERF_EVENT_STATE_OFF)
		return leader->state;

	return event->state;
}

static __always_inline void
__perf_update_times(struct perf_event *event, u64 now, u64 *enabled, u64 *running)
{
	// RH_KABI_REPLACE(u64		tstamp_stopped, u64		tstamp)
	enum perf_event_active_state state = __perf_effective_state(event);
	u64 delta = now - event->tstamp_stopped;

	*enabled = event->total_time_enabled;
	if (state >= PERF_EVENT_STATE_INACTIVE)
		*enabled += delta;

	*running = event->total_time_running;
	if (state >= PERF_EVENT_STATE_ACTIVE)
		*running += delta;
}

int perf_event_read_local(struct perf_event *event, u64 *value,
			  u64 *enabled, u64 *running)
{
	unsigned long flags;
	int ret = 0;

	/*
	 * Disabling interrupts avoids all counter scheduling (context
	 * switches, timer based rotation and IPIs).
	 */
	local_irq_save(flags);

	/*
	 * It must not be an event with inherit set, we cannot read
	 * all child counters from atomic context.
	 */
	if (event->attr.inherit) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* If this is a per-task event, it must be for current */
	if ((event->attach_state & PERF_ATTACH_TASK) &&
	    event->hw.target != current) {
		ret = -EINVAL;
		goto out;
	}

	/* If this is a per-CPU event, it must be for this CPU */
	if (!(event->attach_state & PERF_ATTACH_TASK) &&
	    event->cpu != smp_processor_id()) {
		ret = -EINVAL;
		goto out;
	}

	/* If this is a pinned event it must be running on this CPU */
	if (event->attr.pinned && event->oncpu != smp_processor_id()) {
		ret = -EBUSY;
		goto out;
	}

	/*
	 * If the event is currently on this CPU, its either a per-task event,
	 * or local to this CPU. Furthermore it means its ACTIVE (otherwise
	 * oncpu == -1).
	 */
	if (event->oncpu == smp_processor_id())
		event->pmu->read(event);

	*value = local64_read(&event->count);
	if (enabled || running) {
		u64 now = event->shadow_ctx_time + perf_clock();
		u64 __enabled, __running;

		__perf_update_times(event, now, &__enabled, &__running);
		if (enabled)
			*enabled = __enabled;
		if (running)
			*running = __running;
	}
out:
	local_irq_restore(flags);

	return ret;
}
