#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "map.h"
#include "tracemgmt.h"

#include "types.h"

SEC("uprobe")
int uprobe_get_hostpid(struct pt_regs *ctx)
{
    int nspid = 0;
#if defined(__TARGET_ARCH_x86)
    nspid = ctx->di;
#elif defined(__TARGET_ARCH_arm64)
    nspid = ctx->regs[0];
#endif
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_map_update_elem(&nspid_pid, &nspid, &pid, BPF_ANY);
	return 0;
}


char _license[] SEC("license") = "GPL";