// This file contains the code and map definitions for the tracepoint on the scheduler to
// report the stopping a process.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "map.h"
#include "tracemgmt.h"

#include "types.h"

// tracepoint__sched_process_exit is a tracepoint attached to the scheduler that stops processes.
// Every time a processes stops this hook is triggered.
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched_process_exit(void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = (u32)(pid_tgid >> 32);
  u32 tid = (u32)(pid_tgid & 0xFFFFFFFF);

  if (pid != tid)
  {
    // Only if the thread group ID matched with the PID the process itself exits. If they don't
    // match only a thread of the process stopped and we do not need to report this PID to
    // userspace for further processing.
    goto exit;
  }

  u32 syscfg_key = 0;
  SystemConfig *syscfg = bpf_map_lookup_elem(&system_config, &syscfg_key);
  if (!syscfg)
  {
    return -1;
  }

  if (syscfg->has_pid_namespace)
  {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid = get_task_ns_pid(task);
  }

#if 0
  if (!bpf_map_lookup_elem(&reported_pids, &pid) && !pid_information_exists(ctx, pid)) {
#else
  if (!pid_information_exists(ctx, pid))
  {
#endif
    // Only report PIDs that we explicitly track. This avoids sending kernel worker PIDs
    // to userspace.
    goto exit;
  }

  if (report_pid_for_sched_exit(ctx, pid))
  {
    increment_metric(metricID_NumProcExit);
  }
exit:
  return 0;
}

char _license[] SEC("license") = "GPL";