#ifndef OPTI_MAP_H
#define OPTI_MAP_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "types.h"

// The sizeof in bpf_trace_printk() must include \0, else no output
// is generated. The \n is not needed on 5.8+ kernels, but definitely on
// 5.4 kernels.
#define printt(fmt, ...)                                       \
  ({                                                           \
    const char ____fmt[] = fmt "\n";                           \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __constant_cpu_to_be32(x) __builtin_bswap32(x)
# define __constant_cpu_to_be64(x) __builtin_bswap64(x)
#elif defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __constant_cpu_to_be32(x) (x)
# define __constant_cpu_to_be64(x) (x)
#else
# error "Unknown endianness"
#endif

// #define OPTI_DEBUG

#ifdef OPTI_DEBUG
  #define DEBUG_PRINT(fmt, ...) printt(fmt, ##__VA_ARGS__);

  // Sends `SIGTRAP` to the current task, killing it and capturing a coredump.
  //
  // Only use this in code paths that you expect to be hit by a very specific process that you
  // intend to debug. Placing it into frequently taken code paths might otherwise take down
  // important system processes like sshd or your window manager. For frequently taken cases,
  // prefer using the `DEBUG_CAPTURE_COREDUMP_IF_TGID` macro.
  //
  // This macro requires linking against kernel headers >= 5.6.
  #define DEBUG_CAPTURE_COREDUMP()                                                          \
    ({                                                                                      \
      /* We don't define `bpf_send_signal_thread` globally because it requires a      */    \
      /* rather recent kernel (>= 5.6) and otherwise breaks builds of older versions. */    \
      long (*bpf_send_signal_thread)(u32 sig) = (void *)BPF_FUNC_send_signal_thread;        \
      bpf_send_signal_thread(SIGTRAP);                                                      \
    })

  // Like `DEBUG_CAPTURE_COREDUMP`, but only coredumps if the current task is a member of the given
  // thread group ID ("process").
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)                                              \
    ({                                                                                      \
      if (bpf_get_current_pid_tgid() >> 32 == (tgid)) {                                     \
        DEBUG_PRINT("coredumping process %d", (tgid));                                      \
        DEBUG_CAPTURE_COREDUMP();                                                           \
      }                                                                                     \
    })
#else
  #define DEBUG_PRINT(fmt, ...)
  #define DEBUG_CAPTURE_COREDUMP()
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)
#endif


#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct                                                          \
    {                                                               \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

#if 0 // native_stack.bpf.c
// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
bpf_map_def SEC("maps") unwind_info_array = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(UnwindInfo),
  // Maximum number of unique stack deltas needed on a system. This is based on
  // normal desktop /usr/bin/* and /usr/lib/*.so having about 9700 unique deltas.
  // Can be increased up to 2^15, see also STACK_DELTA_COMMAND_FLAG.
  .max_entries = 16384,
};

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
bpf_map_def SEC("maps") interpreter_offsets = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(OffsetRange),
  .max_entries = 32,
};

// Maps fileID and page to information of stack deltas associated with that page.
bpf_map_def SEC("maps") stack_delta_page_to_info = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(StackDeltaPageKey),
  .value_size = sizeof(StackDeltaPageInfo),
  .max_entries = 40000,
};

// This contains the kernel PCs as returned by bpf_get_stackid(). Unfortunately the ebpf
// program cannot read the contents, so we return the stackid in the Trace directly, and
// make the profiling agent read the kernel mode stack trace portion from this map.
bpf_map_def SEC("maps") kernel_stackmap = {
  .type = BPF_MAP_TYPE_STACK_TRACE,
  .key_size = sizeof(u32),
  .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
  .max_entries = 16*1024,
};
#endif
BPF_ARRAY(unwind_info_array, UnwindInfo, 16384);
BPF_HASH(interpreter_offsets, u64, OffsetRange, 32);
BPF_HASH(stack_delta_page_to_info, StackDeltaPageKey, StackDeltaPageInfo, 40000);
typedef __u64 stack_trace_t[32];
BPF_MAP(kernel_stackmap, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, 16 * 1024)

#if 0 // interpreter_dispatcher.bpf.c
// Begin shared maps

// Per-CPU record of the stack being built and meta-data on the building process
bpf_map_def SEC("maps") per_cpu_records = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(PerCPURecord),
  .max_entries = 1,
};

// metrics maps metric ID to a value
bpf_map_def SEC("maps") metrics = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = metricID_Max,
};

// progs maps from a program ID to an eBPF program
bpf_map_def SEC("maps") progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

// report_events notifies user space about events (GENERIC_PID and TRACES_FOR_SYMBOLIZATION).
//
// As a key the CPU number is used and the value represents a perf event file descriptor.
// Information transmitted is the event type only. We use 0 as the number of max entries
// for this map as at load time it will be replaced by the number of possible CPUs. At
// the same time this will then also define the number of perf event rings that are
// used for this map.
bpf_map_def SEC("maps") report_events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(u32),
  .max_entries = 0,
};

// reported_pids is a map that holds PIDs recently reported to user space.
//
// We use this map to avoid sending multiple notifications for the same PID to user space.
// As key, we use the PID and value is a rate limit token (see pid_event_ratelimit()).
// When sizing this map, we are thinking about the maximum number of unique PIDs that could
// be stored, without immediately being removed, that we would like to support. PIDs are
// either left to expire from the LRU or updated based on the rate limit token. Note that
// timeout checks are done lazily on access, so this map may contain multiple expired PIDs.
bpf_map_def SEC("maps") reported_pids = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(u64),
  .max_entries = 65536,
};

// pid_events is a map that holds PIDs that should be processed in user space.
//
// User space code will periodically iterate through the map and process each entry.
// Additionally, each time eBPF code writes a value into the map, user space is notified
// through event_send_trigger (which uses maps/report_events). As key we use the PID of
// the process and as value always true. When sizing this map, we are thinking about
// the maximum number of unique PIDs that could generate events we're interested in
// (process new, process exit, unknown PC) within a map monitor/processing interval,
// that we would like to support.
bpf_map_def SEC("maps") pid_events = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(bool),
  .max_entries = 65536,
};


// The native unwinder needs to be able to determine how each mapping should be unwound.
//
// This map contains data to help the native unwinder translate from a virtual address in a given
// process. It contains information of the unwinder program to use, how to convert the virtual
// address to relative address, and what executable file is in question.
bpf_map_def SEC("maps") pid_page_to_mapping_info = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(PIDPage),
  .value_size = sizeof(PIDPageMappingInfo),
  .max_entries = 524288, // 2^19
  .map_flags = BPF_F_NO_PREALLOC,
};

// inhibit_events map is used to inhibit sending events to user space.
//
// Only one event needs to be sent as it's a manual trigger to start processing
// traces / PIDs early. HA (Go) will reset this entry once it has reacted to the
// trigger, so next event is sent when needed.
// NOTE: Update .max_entries if additional event types are added. The value should
// equal the number of different event types using this mechanism.
bpf_map_def SEC("maps") inhibit_events = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(bool),
  .max_entries = 2,
};

// Perf event ring buffer for sending completed traces to user-mode.
//
// The map is periodically polled and read from in `tracer`.
bpf_map_def SEC("maps") trace_events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = 0,
  .max_entries = 0,
};

#endif

BPF_PERCPU_ARRAY(per_cpu_records, PerCPURecord, 1);
#if 0
BPF_PERCPU_ARRAY(metrics, u64, metricID_Max);
#endif
BPF_PROG_ARRAY(progs, NUM_TRACER_PROGS);
BPF_PERF_OUTPUT(report_events, 0);
#if 0
BPF_LRU_HASH(reported_pids, u32, u64, 65536);
BPF_HASH(pid_events, u32, bool, 65536);
#endif
// BPF_MAP(pid_page_to_mapping_info, BPF_MAP_TYPE_LPM_TRIE, PIDPage, PIDPageMappingInfo, 524288); // BPF_F_NO_PREALLOC

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 524288);
	__type(key, PIDPage);
	__type(value, PIDPageMappingInfo);
} pid_page_to_mapping_info SEC(".maps");

#if 0
BPF_HASH(inhibit_events, u32, bool, 2);
#endif
BPF_PERF_OUTPUT(trace_events, 0);

#if 0 // system_config.bpf.c
// system config is the bpf map containing HA provided system configuration
bpf_map_def SEC("maps") system_config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct SystemConfig),
    .max_entries = 1,
};
#endif

BPF_ARRAY(system_config, struct SystemConfig, 1);

// mapping from nspid to host pid
BPF_HASH(nspid_pid, u32, u32, 1024);


#endif