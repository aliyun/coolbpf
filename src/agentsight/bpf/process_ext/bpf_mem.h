/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_NEW_BPF_MEM_H
#define __PROCESS_NEW_BPF_MEM_H

/*
 * mmap tracepoint: only capture MAP_SHARED mappings.
 * MAP_SHARED = 0x01 on Linux.
 */

SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_memory)
		return 0;
	if (!is_event_tracked())
		return 0;

	int flags = (int)ctx->args[3];
	if (!(flags & 0x01))  /* MAP_SHARED = 0x01 */
		return 0;

	int fd = (int)ctx->args[4];
	u64 len = ctx->args[1];

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_MMAP_SHARED;
	format_fd_detail(key.detail, sizeof(key.detail), fd);

	update_agg_map(&key, 1, len);
	return 0;
}

#endif /* __PROCESS_NEW_BPF_MEM_H */
