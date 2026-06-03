// This file contains the code and map definitions that are shared between
// the tracers, as well as a dispatcher program that can be attached to a
// perf event and will call the appropriate tracer for a given process
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "map.h"
#include "types.h"
#include "tracemgmt.h"
#include "tsd.h"

#ifdef HAS_APM
// End shared maps
#if 0
bpf_map_def SEC("maps") apm_int_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(ApmIntProcInfo),
  .max_entries = 128,
};
#endif
BPF_HASH(apm_int_procs, pid_t, ApmIntProcInfo, 128);
static inline __attribute__((__always_inline__))
void maybe_add_apm_info(Trace *trace) {

  u32 pid = trace->pid; // verifier needs this to be on stack on 4.15 kernel
  ApmIntProcInfo *proc = bpf_map_lookup_elem(&apm_int_procs, &pid);
  if (!proc) {
    return;
  }

  DEBUG_PRINT("Trace is within a process with APM integration enabled");

#if defined(__x86_64__)
  if (proc->tracing_type == TRACE_GO_AGENT) {
    const struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
    const void* fs_base;
    bpf_probe_read(&fs_base, sizeof(void *), &task_ptr->thread.fsbase);

    size_t g_addr; // address of struct runtime.g
    bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + (-8)));

    size_t go_string_addr; // address of field traceId in runtime.g
    bpf_probe_read_user(&go_string_addr, sizeof(void*), (void*)(g_addr + proc->tracing_field_offset + 8));
    
    size_t trace_id_addr;
    bpf_probe_read_user(&trace_id_addr, sizeof(void*), (void*)(go_string_addr + 0));
    
    const char trace_id[32];
    bpf_probe_read_user(trace_id, sizeof(trace_id), (void*)(trace_id_addr));

    __builtin_memcpy(trace->trace_id, trace_id, sizeof(trace->trace_id));
    return;
  }
#endif

  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    increment_metric(metricID_UnwindApmIntErrReadTsdBase);
    DEBUG_PRINT("Failed to get TSD base for APM integration");
    return;
  }

  DEBUG_PRINT("APM corr ptr should be at 0x%llx", tsd_base + proc->tls_offset);

  void *apm_corr_buf_ptr;
  if (bpf_probe_read_user(&apm_corr_buf_ptr, sizeof(apm_corr_buf_ptr),
                          (void *)(tsd_base + proc->tls_offset))) {
    increment_metric(metricID_UnwindApmIntErrReadCorrBufPtr);
    DEBUG_PRINT("Failed to read APM correlation buffer pointer");
    return;
  }

  ApmCorrelationBuf corr_buf;
  if (bpf_probe_read_user(&corr_buf, sizeof(corr_buf), apm_corr_buf_ptr)) {
    increment_metric(metricID_UnwindApmIntErrReadCorrBuf);
    DEBUG_PRINT("Failed to read APM correlation buffer");
    return;
  }

  if (corr_buf.trace_present && corr_buf.valid) {
    trace->apm_trace_id.as_int.hi = corr_buf.trace_id.as_int.hi;
    trace->apm_trace_id.as_int.lo = corr_buf.trace_id.as_int.lo;
    trace->apm_transaction_id.as_int = corr_buf.transaction_id.as_int;
  }

  increment_metric(metricID_UnwindApmIntReadSuccesses);

  // WARN: we print this as little endian
  DEBUG_PRINT("APM transaction ID: %016llX, flags: 0x%02X",
              trace->apm_transaction_id.as_int, corr_buf.trace_flags);
}
#else
static inline __attribute__((__always_inline__))
void maybe_add_apm_info(Trace *trace) {}
#endif


SEC("perf_event")
int unwind_stop(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;
  Trace *trace = &record->trace;
  UnwindState *state = &record->state;

  maybe_add_apm_info(trace);

  // If the stack is otherwise empty, push an error for that: we should
  // never encounter empty stacks for successful unwinding.
  if (trace->stack_len == 0 && trace->kernel_stack_id < 0 && trace->user_stack_id < 0) {
    DEBUG_PRINT("unwind_stop called but the stack is empty");
    increment_metric(metricID_ErrEmptyStack);
    if (!state->unwind_error) {
      state->unwind_error = ERR_EMPTY_STACK;
    }
  }

  // If unwinding was aborted due to a critical error, push an error frame.
  if (state->unwind_error) {
    push_error(&record->trace, state->unwind_error);
  }

  switch (state->error_metric) {
  case -1:
    // No Error
    break;
  case metricID_UnwindNativeErrWrongTextSection:;
  #if 0
    if (report_pid(ctx, trace->pid, record->ratelimitAction)) {
      increment_metric(metricID_NumUnknownPC);
    }
  #endif
    // Fallthrough to report the error
  default:
    increment_metric(state->error_metric);
  }

  // TEMPORARY HACK
  //
  // If we ended up with a trace that consists of only a single error frame, drop it.
  // This is required as long as the process manager provides the option to filter out
  // error frames, to prevent empty traces from being sent. While it might seem that this
  // filtering should belong into the HA code that does the filtering, it is actually
  // surprisingly hard to implement that way: since traces and their counts are reported
  // through different data structures, we'd have to keep a list of known empty traces to
  // also prevent the corresponding trace counts to be sent out. OTOH, if we do it here,
  // this is trivial.
  if (trace->stack_len == 1 && trace->kernel_stack_id < 0 && trace->user_stack_id < 0 && state->unwind_error) {
    u32 syscfg_key = 0;
    SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &syscfg_key);
    if (!syscfg) {
      return -1; // unreachable
    }

    if (syscfg->drop_error_only_traces) {
      return 0;
    }
  }
  // TEMPORARY HACK END

  send_trace(ctx, trace);

  return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;

// tracepoint__sys_enter_read serves as dummy tracepoint so we can check if tracepoints are
// enabled and we can make use of them.
// The argument that is passed to the tracepoint for the sys_enter_read hook is described in sysfs
// at /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format.
#if 0
SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__sys_enter_read(void *ctx) {
  printt("The read tracepoint was triggered");
  return 0;
}
#endif
