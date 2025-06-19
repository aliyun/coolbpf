//
// Created by qianlu on 2024/6/16.
//

#ifndef SYSAK_PROCESS_H
#define SYSAK_PROCESS_H

#include "../coolbpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_event.h"
#include "bpf_cred.h"
#include "bpf_common.h"
#include "compiler.h"
#include "api.h"

#include "type.h"
#include "bpf_process_event_type.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct msg_execve_event);
} execve_msg_heap_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, struct execve_map_value);
} execve_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __s32);
  __type(value, __s64);
} execve_map_stats SEC(".maps");

enum {
  MAP_STATS_COUNT = 0,
  MAP_STATS_ERROR = 1,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __s32);
  __type(value, struct execve_map_value);
} execve_val SEC(".maps");

struct execve_heap {
  union {
    char pathname[PATHNAME_SIZE];
    char maxpath[4096];
  };
  struct execve_info info;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __s32);
  __type(value, struct execve_heap);
} execve_heap SEC(".maps");

/* The tg_execve_joined_info_map allows to join and combine
 * exec info that is gathered during different hooks
 * through the execve call. The list of current hooks is:
 *   1. kprobe/security_bprm_committing_creds
 *      For details check tg_kp_bprm_committing_creds bpf program.
 *   2. tracepoint/sys_execve
 *      For details see event_execve bpf program.
 *
 * Important: the information stored here is complementary
 * information only, the core logic should not depend on entries
 * of this map to be present.
 *
 * tgid+tid is key as execve is a complex syscall where failures
 * may happen at different levels and hooks, also the thread
 * that triggered and succeeded at execve will be the only new
 * and main thread.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct execve_info);
} tg_execve_joined_info_map SEC(".maps");

/* The tg_execve_joined_info_map_stats will hold stats about
 * entries and map update errors.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __s32);
  __type(value, __s64);
} tg_execve_joined_info_map_stats SEC(".maps");

FUNC_INLINE int64_t validate_msg_execve_size(int64_t size)
{
  size_t max = sizeof(struct msg_execve_event);

  /* validate_msg_size() calls need to happen near caller using the
   * size. Otherwise, depending on kernel version, the verifier may
   * lose track of the size bounds. Place a compiler barrier here
   * otherwise clang will likely place this check near other msg
   * population calls which can be significant distance away resulting
   * in losing bounds on older kernels where bounds are not tracked
   * as rigorously.
   */
  compiler_barrier();
  if (size > max)
    size = max;
  if (size < 1)
    size = offsetof(struct msg_execve_event, buffer);
  compiler_barrier();
  return size;
}

// execve_map_error() will increment the map error counter
FUNC_INLINE void execve_map_error(void)
{
  int one = MAP_STATS_ERROR;
  __s64 *cntr;

  cntr = bpf_map_lookup_elem(&execve_map_stats, &one);
  if (cntr)
    *cntr = *cntr + 1;
}

FUNC_INLINE uint64_t get_start_time()
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  uint64_t gl_off = offsetof(struct task_struct, group_leader);
  struct task_struct *group_leader_ptr;
  bpf_probe_read(&group_leader_ptr,
                 sizeof(struct task_struct *),
                 (uint8_t *)task + gl_off);

  uint64_t start_time = 0;

  if (bpf_core_field_exists(group_leader_ptr->start_time))
  {
    uint64_t st_off = offsetof(struct task_struct, start_time);
    bpf_probe_read(&start_time,
                 sizeof(uint64_t),
                 (uint8_t *)group_leader_ptr + st_off);
  }
  else if (bpf_core_field_exists(group_leader_ptr->start_boottime))
  {
    uint64_t st_off = offsetof(struct task_struct, start_boottime);
    bpf_probe_read(&start_time,
                 sizeof(uint64_t),
                 (uint8_t *)group_leader_ptr + st_off);
  } else {
    start_time = bpf_ktime_get_ns();
  }

  return start_time;
  // return nsec_to_clock_t(start_time);
}

// execve_map_get will look up if pid exists and return it if it does. If it
// does not, it will create a new one and return it.
FUNC_INLINE struct execve_map_value *execve_map_get(__u32 pid)
{
  struct execve_map_value *event;

  event = bpf_map_lookup_elem(&execve_map, &pid);
  if (!event) {
    struct execve_map_value *value;
    int err, zero = MAP_STATS_COUNT;
    __s64 *cntr;

    value = bpf_map_lookup_elem(&execve_val, &zero);
    if (!value)
    return 0;

    memset(value, 0, sizeof(struct execve_map_value));
    err = bpf_map_update_elem(&execve_map, &pid, value, 0);
    if (!err) {
      cntr = bpf_map_lookup_elem(&execve_map_stats, &zero);
      if (cntr)
      *cntr = *cntr + 1;
    } else {
      execve_map_error();
    }
    event = bpf_map_lookup_elem(&execve_map, &pid);
  }
  return event;
}

FUNC_INLINE struct execve_map_value *execve_map_get_noinit(__u32 pid)
{
  return bpf_map_lookup_elem(&execve_map, &pid);
}

FUNC_INLINE void execve_map_delete(__u32 pid)
{
  int err = bpf_map_delete_elem(&execve_map, &pid);
  int zero = MAP_STATS_COUNT;
  __s64 *cntr;

  if (!err) {
    cntr = bpf_map_lookup_elem(&execve_map_stats, &zero);
  if (cntr)
    *cntr = *cntr - 1;
  } else {
    execve_map_error();
  }
}

// execve_joined_info_map_error() will increment the map error counter
FUNC_INLINE void execve_joined_info_map_error(void)
{
  int one = MAP_STATS_ERROR;
  __s64 *cntr;

  cntr = bpf_map_lookup_elem(&tg_execve_joined_info_map_stats, &one);
  if (cntr)
    *cntr = *cntr + 1;
}

FUNC_INLINE void execve_joined_info_map_set(__u64 tid, struct execve_info *info)
{
  int err, zero = MAP_STATS_COUNT;
  __s64 *cntr;

  err = bpf_map_update_elem(&tg_execve_joined_info_map, &tid, info, BPF_ANY);
  if (err < 0) {
    /* -EBUSY or -ENOMEM with the help of the cntr error
     * on the stats map this can be a good indication of
     * long running workloads and if we have to make the
     * map size bigger for such cases.
     */
    execve_joined_info_map_error();
    return;
  }

  cntr = bpf_map_lookup_elem(&tg_execve_joined_info_map_stats, &zero);
  if (cntr)
    *cntr = *cntr + 1;
}

/* Clear up some space for next threads */
FUNC_INLINE void execve_joined_info_map_clear(__u64 tid)
{
  int err, zero = MAP_STATS_COUNT;
  __s64 *cntr;

  err = bpf_map_delete_elem(&tg_execve_joined_info_map, &tid);
  if (!err) {
    cntr = bpf_map_lookup_elem(&tg_execve_joined_info_map_stats, &zero);
  if (cntr)
    *cntr = *cntr - 1;
}
/* We don't care here about -ENOENT as there is no guarantee entries
 * will be present anyway.
 */
}

/* Returns an execve_info if found. A missing entry is perfectly fine as it
 * could mean we are not interested into storing more information about this task.
 */
FUNC_INLINE struct execve_info *execve_joined_info_map_get(__u64 tid)
{
  return bpf_map_lookup_elem(&tg_execve_joined_info_map, &tid);
}

_Static_assert(sizeof(struct execve_map_value) % 8 == 0,
               "struct execve_map_value should have size multiple of 8 bytes");

struct kernel_stats {
  __u64 sent_failed[256];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct kernel_stats);
  __uint(max_entries, 1);
} tg_stats_map SEC(".maps");

FUNC_INLINE void perf_event_output_update_error_metric(u8 msg_op, long err) {
  struct kernel_stats *valp;
  __u32 zero = 0;

  valp = bpf_map_lookup_elem(&tg_stats_map, &zero);
  if (valp) {
    __sync_fetch_and_add(&valp->sent_failed[msg_op], 1);
  }
}

FUNC_INLINE void perf_event_output_metric(void *ctx, u8 msg_op, void *map,
                                          u64 flags, void *data, u64 size) {
  long err;

  err = bpf_perf_event_output(ctx, map, flags, data, size);
  if (err < 0)
    perf_event_output_update_error_metric(msg_op, err);
}

#endif //SYSAK_PROCESS_H
