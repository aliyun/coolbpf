/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_NEW_BPF_COW_H
#define __PROCESS_NEW_BPF_COW_H

/*
 * CoW page fault tracing via kprobe on do_wp_page.
 * Aggregates fault count per PID.
 * Note: do_wp_page is an internal kernel function; availability varies by kernel version.
 */

SEC("kprobe/do_wp_page")
int trace_cow_fault(struct pt_regs *ctx)
{
	if (!trace_cow)
		return 0;
	if (!is_event_tracked())
		return 0;

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_COW_FAULT;
	/* detail left empty: aggregate count per pid */

	update_agg_map(&key, 1, 0);
	return 0;
}

#endif /* __PROCESS_NEW_BPF_COW_H */
