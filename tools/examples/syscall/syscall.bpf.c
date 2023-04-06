


#include <vmlinux.h>
#include <coolbpf/coolbpf.h>

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_statfs_entry(struct trace_event_raw_sys_enter *ctx)
{
	return 0;
}