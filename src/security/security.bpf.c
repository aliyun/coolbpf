//
// Created by qianlu on 2024/6/12.
//

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"

#include "int_maps.h"
#include "filter.h"
#include "type.h"
#include "process.h"
#include "addr_lpm_maps.h"
#include "string_maps.h"
#include "bpf_exit.h"
#include "tailcall_stack.h"
//#include "bpf_execve.h"
#include "../ebpf_log.h"

BPF_ARRAY(cidr_filter_list, struct cidr_entry, SYSAK_SECURE_MAX_CIDR_LIMIT);
BPF_ARRAY(port_filter_list, struct port_entry, SYSAK_SECURE_MAX_PORT_LIMIT);

BPF_HASH(sock_secure_port_filter, u16, struct port_entry, 1024);
BPF_PERF_OUTPUT(sock_secure_output, 1024);
BPF_PERCPU_ARRAY(sock_secure_data_heap, struct tcp_data_t, 1);

BPF_ARRAY(path_filter_list, struct path_entry, SYSAK_SECURE_MAX_PATH_LIMIT);
BPF_PERF_OUTPUT(file_secure_output, 1024);
BPF_PERCPU_ARRAY(file_secure_data_heap, struct file_data_t, 1);
BPF_PERCPU_ARRAY(tailcall_stack, struct secure_tailcall_stack, 1);

struct
{
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 3);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} file_path_filter_calls SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 3);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} secure_tailcall_map SEC(".maps");
//////////////////////////// process ////////////////////////////
/////////////////////////////////////////////////////////////////

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 2);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} execve_calls SEC(".maps");

#include "data_event.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct msg_data);
} data_heap SEC(".maps");

FUNC_INLINE __u32
read_args(void *ctx, struct msg_execve_event *event)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct msg_process *p = &event->process;
  unsigned long start_stack, end_stack;
  unsigned long free_size, args_size;
  __u32 zero = 0, size = 0;
  struct execve_heap *heap;
  struct mm_struct *mm;
  char *args;
  long off;
  int err;

  bpf_probe_read(&mm, sizeof(mm), _(&task->mm));
  if (!mm)
    return 0;

  bpf_probe_read(&start_stack, sizeof(start_stack),
             _(&mm->arg_start));
  bpf_probe_read(&end_stack, sizeof(start_stack), _(&mm->arg_end));

  if (!start_stack || !end_stack)
    return 0;

  /* skip first argument - binary path */
  heap = bpf_map_lookup_elem(&execve_heap, &zero);
  if (!heap)
    return 0;

  /* poor man's strlen */
  off = bpf_probe_read_str(&heap->maxpath, 4096, (char *)start_stack);
  if (off < 0)
    return 0;

  start_stack += off;

  size = p->size & 0x1ff /* 2*MAXARGLENGTH - 1*/;
  args = (char *)p + size;

  if (args >= (char *)&event->process + BUFFER)
    return 0;

  /* Read arguments either to rest of the space in the event,
   * or use data event to send it separatelly.
   */
  free_size = (char *)&event->process + BUFFER - args;
  args_size = end_stack - start_stack;

  if (args_size < BUFFER && args_size < free_size) {
    size = args_size & 0x3ff /* BUFFER - 1 */;
    err = bpf_probe_read(args, size, (char *)start_stack);
    if (err < 0) {
      p->flags |= EVENT_ERROR_ARGS;
      size = 0;
    }
  } else {
    size = data_event_bytes(ctx, (struct data_event_desc *)args,
                            (unsigned long)start_stack,
                            args_size,
                            (struct bpf_map_def *)&data_heap);
    if (size > 0)
      p->flags |= EVENT_DATA_ARGS;
  }
  return size;
}

FUNC_INLINE __u32
read_path(void *ctx, struct msg_execve_event *event, void *filename)
{
  struct msg_process *p = &event->process;
  __u32 size = 0;
  __u32 flags = 0;
  char *earg;

  earg = (void *)p + offsetof(struct msg_process, args);

  size = bpf_probe_read_str(earg, MAXARGLENGTH - 1, filename);
  if (size < 0) {
    flags |= EVENT_ERROR_FILENAME;
    size = 0;
  } else if (size == MAXARGLENGTH - 1) {
    size = data_event_str(ctx, (struct data_event_desc *)earg,
                          (unsigned long)filename,
                          (struct bpf_map_def *)&data_heap);
    if (size == 0)
      flags |= EVENT_ERROR_FILENAME;
    else
      flags |= EVENT_DATA_FILENAME;
  }

  p->flags |= flags;
  return size;
}

FUNC_INLINE __u32
read_cwd(void *ctx, struct msg_process *p)
{
  if (p->flags & EVENT_ERROR_CWD)
    return 0;
  return getcwd(p, p->size, p->pid);
}

FUNC_INLINE void
read_execve_shared_info(void *ctx, struct msg_process *p, __u64 pid)
{
  struct execve_info *info;

  info = execve_joined_info_map_get(pid);
  if (!info) {
    p->secureexec = 0;
    p->i_ino = 0;
    p->i_nlink = 0;
    return;
  }

  p->secureexec = info->secureexec;
  p->i_ino = info->i_ino;
  p->i_nlink = info->i_nlink;
  execve_joined_info_map_clear(pid);
}

/**
 * read_exe() Reads the path from the backing executable file of the current
 * process.
 *
 * The executable file of a process can change using the prctl() system call
 * and PR_SET_MM_EXE_FILE. Thus, this function should only be used under the
 * execve path since the executable file is locked and usually there is only
 * one remaining thread at its exit path.
 */
#ifdef __LARGE_BPF_PROG
FUNC_INLINE __u32
read_exe(struct task_struct *task, struct heap_exe *exe)
{
	struct file *file = BPF_CORE_READ(task, mm, exe_file);
	struct path *path = __builtin_preserve_access_index(&file->f_path);

	// we need to walk the complete 4096 len dentry in order to have an accurate
	// matching on the prefix operators, even if we only keep a subset of that
	char *buffer;

	buffer = d_path_local(path, (int *)&exe->len, (int *)&exe->error);
	if (!buffer)
		return 0;

	// buffer used by d_path_local can contain up to MAX_BUF_LEN i.e. 4096 we
	// only keep the first 255 chars for our needs (we sacrifice one char to the
	// verifier for the > 0 check)
	if (exe->len > 255)
		exe->len = 255;
	asm volatile("%[len] &= 0xff;\n"
		     : [len] "+r"(exe->len));
	probe_read(exe->buf, exe->len, buffer);

	return exe->len;
}
#endif

// int wake_up_process(struct task_struct *p)
SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
  struct execve_map_value *curr, *parent;
  struct msg_clone_event msg;
  u64 msg_size = sizeof(struct msg_clone_event);
  struct msg_k8s kube;
  u32 tgid = 0;

  if (!task)
    return 0;

  tgid = BPF_CORE_READ(task, tgid);

  /* Do not try to create any msg or calling execve_map_get
   * (that will add a new process in the execve_map) if we
   * cannot find it's parent in the execve_map.
   */
  parent = __event_find_parent(task);
  if (!parent)
    return 0;

  curr = execve_map_get(tgid);
  if (!curr)
    return 0;

  /* Generate an EVENT_COMMON_FLAG_CLONE event once per process,
   * that is, thread group.
   */
  if (curr->key.ktime != 0)
    return 0;

  /* Setup the execve_map entry. */
  curr->flags = EVENT_COMMON_FLAG_CLONE;
  curr->key.pid = tgid;
  curr->key.ktime = bpf_ktime_get_ns();
  curr->nspid = get_task_pid_vnr();
  memcpy(&curr->bin, &parent->bin, sizeof(curr->bin));
  curr->pkey = parent->key;

  /* Store the thread leader capabilities so we can check later
   * before the execve hook point if they changed or not.
   * This needs to be converted later to credentials.
   */
  get_current_subj_caps(&curr->caps, task);

  /* Store the thread leader namespaces so we can check later
   * before the execve hook point if they changed or not.
   */
  get_namespaces(&curr->ns, task);

  /* Set EVENT_IN_INIT_TREE flag on the process if its parent is in a
   * container's init tree or if it has nspid=1.
   */
  set_in_init_tree(curr, parent);

  /* Setup the msg_clone_event and sent to the user. */
  msg.common.op = MSG_OP_CLONE;
  msg.common.size = msg_size;
  msg.common.ktime = curr->key.ktime;
  msg.parent = curr->pkey;
  msg.tgid = curr->key.pid;
  /* Per thread tracking rules TID == PID :
   *  Since we generate one event per thread group, then when this task
   *  wakes up it will be the only one in the thread group, and it is
   *  the leader. Ensure to pass TID to user space.
   */
  msg.tid = BPF_CORE_READ(task, pid);
  msg.ktime = curr->key.ktime;
  msg.nspid = curr->nspid;
  msg.flags = curr->flags;

  __event_get_cgroup_info(task, &kube);

  if (cgroup_rate(ctx, &kube, msg.ktime)) {
    perf_event_output_metric(ctx, MSG_OP_CLONE, &tcpmon_map, BPF_F_CURRENT_CPU, &msg, msg_size);
  }

  return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int event_execve(struct trace_event_raw_sched_process_exec *ctx)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  char *filename = (char *)ctx + (_(ctx->__data_loc_filename) & 0xFFFF);
  struct msg_execve_event *event;
  struct execve_map_value *parent;
  struct msg_process *p;
  __u32 zero = 0;
  __u64 pid;

  event = bpf_map_lookup_elem(&execve_msg_heap_map, &zero);
  if (!event)
    return 0;

  pid = bpf_get_current_pid_tgid();
  parent = event_find_parent();
  if (parent) {
    event->parent = parent->key;
  } else {
    event_minimal_parent(event, task);
  }

  p = &event->process;
  p->flags = EVENT_EXECVE;
  /**
   * Per thread tracking rules TID == PID :
   *  At exec all threads other than the calling one are destroyed, so
   *  current becomes the new thread leader since we hook late during
   *  execve.
   */
  p->pid = pid >> 32;
  p->tid = (__u32)pid;
  p->nspid = get_task_pid_vnr();
  p->ktime = bpf_ktime_get_ns();
  p->size = offsetof(struct msg_process, args);
  p->auid = get_auid();
  read_execve_shared_info(ctx, p, pid);

  p->size += read_path(ctx, event, filename);
  p->size += read_args(ctx, event);
  p->size += read_cwd(ctx, p);

  event->common.op = MSG_OP_EXECVE;
  event->common.ktime = p->ktime;
  event->common.size = offsetof(struct msg_execve_event, process) + p->size;

  get_current_subj_creds(&event->creds, task);
  /**
   * Instead of showing the task owner, we want to display the effective
   * uid that is used to calculate the privileges of current task when
   * acting upon other objects. This allows to be compatible with the 'ps'
   * tool that reports snapshot of current processes.
   */
  p->uid = event->creds.euid;
  get_namespaces(&event->ns, task);
  p->flags |= __event_get_cgroup_info(task, &event->kube);

  bpf_tail_call(ctx, &execve_calls, 0);
  return 0;
}

//__attribute__((section("tracepoint/0"), used))
SEC("tracepoint/0")
int execve_rate(void *ctx)
{
  struct msg_execve_event *msg;

  __u32 zero = 0;

  msg = bpf_map_lookup_elem(&execve_msg_heap_map, &zero);
  if (!msg)
    return 0;

  if (cgroup_rate(ctx, &msg->kube, msg->common.ktime))
    bpf_tail_call(ctx, &execve_calls, 1);
  return 0;
}

///**
// * execve_send() sends the collected execve event data.
// *
// * This function is the last tail call of the execve event, its sole purpose
// * is to update the pid execve_map entry to reflect the new execve event that
// * has already been collected, then send it to the perf buffer.
// */
////__attribute__((section("tracepoint/1"), used)) int
SEC("tracepoint/1")
int execve_send(void *ctx)
{
  struct msg_execve_event *event;
  struct execve_map_value *curr;
  struct msg_process *p;
  __u32 zero = 0;
  uint64_t size;
  __u32 pid;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
  bool init_curr = 0;
#endif

  event = bpf_map_lookup_elem(&execve_msg_heap_map, &zero);
  if (!event)
    return 0;

#ifdef __LARGE_BPF_PROG
  // Reading the absolute path of the process exe for matchBinaries.
	// Historically we used the filename, a potentially relative path (maybe to
	// a symlink) coming from the execve tracepoint. For kernels not supporting
	// large BPF prog, we still use the filename.
	read_exe((struct task_struct *)bpf_get_current_task(), &event->exe);
#endif

  p = &event->process;

  pid = (bpf_get_current_pid_tgid() >> 32);

  curr = execve_map_get_noinit(pid);
  if (curr) {
    event->cleanup_key = curr->key;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
    /* if this exec event preceds a clone, initialize  capabilities
		 * and namespaces as well.
		 */
		if (curr->flags == EVENT_COMMON_FLAG_CLONE)
			init_curr = 1;
#endif
    curr->key.pid = p->pid;
    curr->key.ktime = p->ktime;
    curr->nspid = p->nspid;
    curr->pkey = event->parent;
    if (curr->flags & EVENT_COMMON_FLAG_CLONE) {
      event_set_clone(p);
    }
    curr->flags &= ~EVENT_COMMON_FLAG_CLONE;
    /* Set EVENT_IN_INIT_TREE flag on the process if nspid=1.
     */
    set_in_init_tree(curr, NULL);
    if (curr->flags & EVENT_IN_INIT_TREE) {
        event->process.flags |= EVENT_IN_INIT_TREE;
    }
#ifdef __NS_CHANGES_FILTER
    if (init_curr)
			memcpy(&(curr->ns), &(event->ns),
			       sizeof(struct msg_ns));
#endif
#ifdef __CAP_CHANGES_FILTER
    if (init_curr) {
			curr->caps.permitted = event->creds.caps.permitted;
			curr->caps.effective = event->creds.caps.effective;
			curr->caps.inheritable = event->creds.caps.inheritable;
		}
#endif
    // buffer can be written at clone stage with parent's info, if previous
    // path is longer than current, we can have leftovers at the end.
    memset(&curr->bin, 0, sizeof(curr->bin));
#ifdef __LARGE_BPF_PROG
    // read from proc exe stored at execve time
		if (event->exe.len <= BINARY_PATH_MAX_LEN) {
			curr->bin.path_length = bpf_probe_read(curr->bin.path, event->exe.len, event->exe.buf);
			if (curr->bin.path_length == 0)
				curr->bin.path_length = event->exe.len;
		}
#else
    // reuse p->args first string that contains the filename, this can't be
    // above 256 in size (otherwise the complete will be send via data msg)
    // which is okay because we need the 256 first bytes.
    curr->bin.path_length = bpf_probe_read_str(curr->bin.path, BINARY_PATH_MAX_LEN, &p->args);
    if (curr->bin.path_length > 1) {
      // don't include the NULL byte in the length
      curr->bin.path_length--;
    }
#endif
  }

  event->common.flags = 0;
  size = validate_msg_execve_size(
    sizeof(struct msg_common) + sizeof(struct msg_k8s) +
    sizeof(struct msg_execve_key) + sizeof(__u64) +
    sizeof(struct msg_cred) + sizeof(struct msg_ns) +
    sizeof(struct msg_execve_key) + p->size);
  perf_event_output_metric(ctx, MSG_OP_EXECVE, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
  return 0;
}

//
//
//
//// exit
//
////__attribute__((section("kprobe/acct_process"), used))
SEC("kprobe/acct_process")
int event_exit_acct_process(struct pt_regs *ctx)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  event_exit_send(ctx, pid);
  return 0;
}

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's called with on_exit argument != 0 when called from do_exit
 * function with same conditions like for acct_process described above.
 */
//__attribute__((section("kprobe/disassociate_ctty"), used)) int

SEC("kprobe/disassociate_ctty")
int event_exit_disassociate_ctty(struct pt_regs *ctx)
{
  int on_exit = (int)PT_REGS_PARM1_CORE(ctx);
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (on_exit)
    event_exit_send(ctx, pid);
  return 0;
}


//////////////////////////// filters ////////////////////////////

#define POLICY_FILTER_MAX_POLICIES 128

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
	__uint(key_size, sizeof(u32)); /* policy id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u64); /* cgroup id */
			__type(value, __u8); /* empty  */
		});
} policy_filter_maps SEC(".maps");

/////////////////////////////////////////////////////////////////


//////////////////////////// network ////////////////////////////
/////////////////////////////////////////////////////////////////

static __always_inline u16 bpf_core_sock_sk_protocol_ak(struct sock *sk)
{
  return (u16)BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
}

static inline int cidr_match(__u32 addr, __u32 net, __u32 subnet) {
  __u32 mask = subnet == 0 ? 0 : (0xFFFFFFFF << (32 - subnet));
  return (addr & mask) == (net & mask);
}

// return value:
//   0 --- pass
//   1 --- reject
// direction: 0 for source addr, 1 for dest addr
int port_filter(__u16 port, int direction) {
  int start = 0;
  if (direction == 1) {
    start = (SYSAK_SECURE_MAX_PORT_LIMIT >> 1);
  }

  int key;
  struct port_entry *entry;
  // 0 for blacklist
  // 1 for whitelist
  int blacklist = 3;

#pragma unroll
  for (key = 0; key < SYSAK_SECURE_MAX_PORT_LIMIT; key++) {
    int tmp = start + key;
    entry = bpf_map_lookup_elem(&port_filter_list, &tmp);
    if (!entry || entry->inited == 0) {
      // need stop
      break;
    }
    blacklist = entry->black;
    BPF_DEBUG("[kprobe][port_filter] black:%u, port:%u, income_port:%u", entry->black, entry->port, port);
    if (port == entry->port) {
      if (blacklist == 1) {
        // blacklist
        BPF_DEBUG("[kprobe][port_filter] filtered by blacklist port, port:%u : disabled.",
                   port);
        return 1;
      } else if (blacklist == 0) {
        // whitelist
        return 0;
      }
    }

    return (entry->black == 0) ? 1 : 0;
  }

  // blacklist
  if (blacklist == 1) return 0;
  if (blacklist == 0) {
    // whitelist
    BPF_DEBUG("[kprobe][port_filter] filtered by whitelist port, port:%u . disabled.", port);
    return 1;
  }

  // no filters
  return 0;
}

// return value:
//   0 --- pass
//   1 --- reject
// direction: 0 for source addr, 1 for dest addr
int addr_filter(__u32 addr, int direction) {
  int start = 0;
  if (direction == 1) {
    start = (SYSAK_SECURE_MAX_CIDR_LIMIT >> 1);
  }

  int key;

  // 0 for blacklist
  // 1 for whitelist
  int blacklist = 3;
#pragma unroll
  for (key = 0; key < SYSAK_SECURE_MAX_CIDR_LIMIT; key++) {
    int tmp = start + key;
    struct cidr_entry *entry = bpf_map_lookup_elem(&cidr_filter_list, &tmp);
    if (!entry || entry->inited == 0) break;
    BPF_DEBUG("[kprobe][addr_filter] black:%u, net:%u, mask:%u", entry->black, entry->net, entry->mask);
    blacklist = entry->black;
    if (cidr_match(addr, entry->net, entry->mask)) {
      if (blacklist == 1) {
        // bingo black list
        BPF_DEBUG("[kprobe][addr_filter] filtered by blacklist cidr, ip:%u net:%u mask:%u: disabled.",
                   addr, entry->net, entry->mask);
        return 1;
      } else if (blacklist == 0) {
        // bingo white list
        return 0;
      }
    }
  }

  // blacklist
  if (blacklist == 1) return 0;
  if (blacklist == 0) {
    // whitelist
    BPF_DEBUG("[kprobe][addr_filter] filtered by white cidr, ip:%u disabled.",
               addr);
    return 1;
  }

  // no filters
  return 0;
}

static __always_inline u32 get_netns(struct sock *sk) {
  return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg] pid:%u never enter. skip collect", pid);
    return 0;
  }
  BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  // define event
  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_SENDMSG;
  data->key = enter->key;
  data->pkey = enter->pkey;

  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);
  data->bytes = size;

  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_SENDMSG;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_SENDMSG;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  stack->tcp_data.bytes = size;
  BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg][dump] saddr:%u, daddr:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.daddr, data->family);
  BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg][dump] daddr:%u, sport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.sport, data->state);


  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  // do filters
  // int sf, df, sp, dp;
  // sf = addr_filter(data->saddr, 0);
  // df = addr_filter(data->daddr, 1);
  // sp = port_filter(data->sport, 0);
  // dp = port_filter(data->dport, 1);
  // if (sf || df || sp || dp) {
  //   BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg] skip submit because of filters.");
  //   return 0;
  // }

  // bpf_perf_event_output(ctx, &sock_secure_output, BPF_F_CURRENT_CPU, data, sizeof(struct tcp_data_t));
  // BPF_DEBUG("[kprobe][kprobe_tcp_sendmsg] pid:%u ktime:%llu send to perfbuffer.", pid, enter->key.ktime);
  return 0;
}

// void tcp_close(struct sock *sk, long timeout);
SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    BPF_DEBUG("[kprobe][kprobe_tcp_close] pid:%u never enter. skip collect", pid);
    return 0;
  }
  BPF_DEBUG("[kprobe][kprobe_tcp_close] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_CLOSE;
  data->key = enter->key;
  data->pkey = enter->pkey;
  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);

  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_CLOSE;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_CLOSE;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  BPF_DEBUG("[kprobe][kprobe_tcp_close][dump] saddr:%u, daddr:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.daddr, data->family);
  BPF_DEBUG("[kprobe][kprobe_tcp_close][dump] daddr:%u, sport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.sport, data->state);


  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);

  // do filters
//   int sf, df, sp, dp;
//   sf = addr_filter(data->saddr, 0);
//   df = addr_filter(data->daddr, 1);
//   sp = port_filter(data->sport, 0);
//   dp = port_filter(data->dport, 1);
//   if (sf || df || sp || dp) {
//     BPF_DEBUG("[kprobe][kprobe_tcp_close] skip submit because of filters.");
//     return 0;
//   }

// //  BPF_DEBUG("Packet matched CIDR: %x/%x/%u/%u\n", entry->net, entry->mask, entry->enable, entry->src);
//   bpf_perf_event_output(ctx, &sock_secure_output, BPF_F_CURRENT_CPU, data, sizeof(struct tcp_data_t));
//   BPF_DEBUG("[kprobe][kprobe_tcp_close] pid:%u ktime:%llu send to perfbuffer.", pid, enter->key.ktime);
  return 0;
}

//
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    BPF_DEBUG("[kprobe][kprobe_tcp_connect] pid:%u never enter. skip collect", pid);
    return 0;
  }
  BPF_DEBUG("[kprobe][kprobe_tcp_connect] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_CONNECT;
  data->key = enter->key;
  data->pkey = enter->pkey;
  // struct inet_sock *inet = (struct inet_sock *)sk;
  // data->timestamp = bpf_ktime_get_ns();
  // data->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  // data->daddr = bpf_htonl(data->daddr);
  // data->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  // data->dport = bpf_htons(data->dport);
  // data->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  // data->saddr = bpf_htonl(data->saddr);
  // data->sport = BPF_CORE_READ(inet, inet_sport);
  // data->sport = bpf_htons(data->sport);
  // data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  // data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  // data->net_ns = get_netns(sk);
  // data->protocol = bpf_core_sock_sk_protocol_ak(sk);

  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);


  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_CONNECT;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_CONNECT;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  BPF_DEBUG("[kprobe][kprobe_tcp_connect][dump] saddr:%u, daddr:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.daddr, data->family);
  BPF_DEBUG("[kprobe][kprobe_tcp_connect][dump] daddr:%u, sport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.sport, data->state);

  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);

  // do filters
//   int sf, df, sp, dp;
//   sf = addr_filter(data->saddr, 0);
//   df = addr_filter(data->daddr, 1);
//   sp = port_filter(data->sport, 0);
//   dp = port_filter(data->dport, 1);
//   if (sf || df || sp || dp) {
//     BPF_DEBUG("[kprobe][kprobe_tcp_connect] skip submit because of filters.");
//     return 0;
//   }

// //  BPF_DEBUG("Packet matched CIDR: %x/%x/%u/%u\n", entry->net, entry->mask, entry->enable, entry->src);
//   bpf_perf_event_output(ctx, &sock_secure_output, BPF_F_CURRENT_CPU, data, sizeof(struct tcp_data_t));
//   BPF_DEBUG("[kprobe][kprobe_tcp_connect] pid:%u ktime:%llu send to perfbuffer.", pid, enter->key.ktime);
  return 0;
}



////// file //////
// char _license[] SEC("license") = "GPL";
//  Function to calculate the length of the string
static inline __attribute__((always_inline)) u32 str_len(const char *str)
{
  u32 len = 0;
#pragma unroll
  for (int i = 0; i < SYSAK_SECURE_MAX_PATH_LENGTH_LIMIT; i++)
  {
    if (str[i] == '\0')
      break;
    len++;
  }
  return len;
}

static inline __attribute__((always_inline)) long copy_path(char *args, const struct path *arg)
{
  int *s = (int *)args;
  int size = 0, flags = 0;
  char *buffer;
  void *curr = &args[4];
  umode_t i_mode;
  buffer = d_path_local(arg, &size, &flags);
  if (!buffer)
    return 0;
 // tips: path size between 0~255
  if (size > 255) size = 255;
  asm volatile("%[size] &= 0xff;\n" ::[size] "+r"(size)
               :);
  bpf_probe_read(curr, size, buffer);
  *s = size;
  size += 4;
  BPF_CORE_READ_INTO(&i_mode, arg, dentry, d_inode, i_mode);
  /*
   * the format of the path is:
   * -----------------------------------------
   * | 4 bytes | N bytes | 4 bytes | 2 bytes |
   * | pathlen |  path   |  flags  |   mode  |
   * -----------------------------------------
   * Next we set up the flags.
   */
  asm volatile goto(
      "r1 = *(u64 *)%[pid];\n"
      "r7 = *(u32 *)%[offset];\n"
      "if r7 s< 0 goto %l[a];\n"
      "if r7 s> 1188 goto %l[a];\n"
      "r1 += r7;\n"
      "r2 = *(u32 *)%[flags];\n"
      "*(u32 *)(r1 + 0) = r2;\n"
      "r2 = *(u16 *)%[mode];\n"
      "*(u16 *)(r1 + 4) = r2;\n"
      :
      : [pid] "m"(args), [flags] "m"(flags), [offset] "+m"(size), [mode] "m"(i_mode)
      : "r0", "r1", "r2", "r7", "memory"
      : a);
a:
  size += sizeof(u32) + sizeof(u16); // for the flags + i_mode
  return size;
}


void write_ipv6_addr32(u32 *dest, u32 *src)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

SEC("kprobe/tailcall_prog") 
int filter_prog(struct pt_regs *ctx) {
  BPF_DEBUG("[secure][tailcall] enter filter_prog");
  __u32 zero = 0;
  struct secure_tailcall_stack *stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack)
    return 0;
  
  int call_name_idx = stack->func;
  struct selector_filters* filters = NULL;
  filters = bpf_map_lookup_elem(&filter_map, &call_name_idx);

  if (filters == NULL) {
    // no filter was set ...
    // should send data directly.
    bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_SEND);
    return 0;
  }
  
  // get data
  int i = 0;
  int pass = 1;
  #pragma unroll
  for (; i < MAX_FILTER_FOR_PER_CALLNAME; i ++) {
    int idx = i;
    struct selector_filter filter = filters->filters[idx];
    // if (filter.filter_type != FILTER_TYPE_UNKNOWN) {
    //   BPF_DEBUG("get file prefix filter, callname idx:%u type:%u, map index:%u", call_name_idx, filter.filter_type, filter.map_idx[0]);
    //   // BPF_DEBUG("get file prefix filter, vallen:%u, plus 8:%u", filter.vallen, filter.vallen << 3);
    // }
    struct addr4_lpm_trie arg4;
    // struct addr6_lpm_trie arg6;
    switch(filter.filter_type) {
    case FILTER_TYPE_SADDR: {
      uint32_t saddr = stack->tcp_data.saddr;
      struct bpf_map* inner_map4 = NULL;
      // struct bpf_map* inner_map6 = NULL;
      if (filter.map_idx[0] != -1) {
        inner_map4 = bpf_map_lookup_elem(&addr4lpm_maps, &filter.map_idx[0]);
      }
      // if (filter.map_idx[1] != -1) {
      //   inner_map6 = bpf_map_lookup_elem(&addr6lpm_maps, &filter.map_idx[1]);
      // }
      if (inner_map4 == NULL) {
        BPF_DEBUG("there is something wrong with the lpm maps... callname idx:%u cannot find inner map for saddr, continue ... ", call_name_idx);
        continue;
      }
      arg4.addr = saddr;
      arg4.prefix = 32;
      // arg6.prefix = 128;
  		// write the address in as 4 u32s due to alignment
  		// write_ipv6_addr32(arg6.addr, (__u32 *)stack->tcp_data.saddr);
      __u8 *ppass4 = NULL, *ppass6 = NULL;
      if (inner_map4 != NULL) ppass4 = bpf_map_lookup_elem(inner_map4, &arg4);
      
      // ppass6 = bpf_map_lookup_elem(inner_map6, &arg6);
      if (filter.op_type == OP_TYPE_IN) {
        // not in white list
        if (ppass4 == NULL) {
          BPF_DEBUG("callname idx:%u arg4 saddr:%u, prefix:%u not in whitelist", call_name_idx, arg4.addr, arg4.prefix);
          return 0;
        }
      } else if (filter.op_type == OP_TYPE_NOT_IN) {
        // or in black list
        if (ppass4 != NULL) {
          BPF_DEBUG("callname idx:%u arg4 saddr:%u, prefix:%u in blacklist", call_name_idx, arg4.addr, arg4.prefix);
          return 0;
        }
      }
      break;
    }
    case FILTER_TYPE_DADDR: {
      uint32_t daddr = stack->tcp_data.daddr;
      arg4.addr = daddr;
      arg4.prefix = 32;
      struct bpf_map* inner_map = bpf_map_lookup_elem(&addr4lpm_maps, &filter.map_idx[0]);
      if (inner_map == NULL) {
        BPF_DEBUG("callname idx:%u cannot find inner map for daddr, continue ... ", call_name_idx);
        continue;
      }
      __u8* ppass = NULL;
      ppass = bpf_map_lookup_elem(inner_map, &arg4);
      if (filter.op_type == OP_TYPE_IN) {
        // not in white list
        if (ppass == NULL) {
          BPF_DEBUG("callname idx:%u arg4 daddr:%u, prefix:%u not in whitelist", call_name_idx, arg4.addr, arg4.prefix);
          return 0;
        }
      } else if (filter.op_type == OP_TYPE_NOT_IN) {
        // or in black list
        BPF_DEBUG("callname idx:%u arg4 daddr:%u, prefix:%u in blacklist", call_name_idx, arg4.addr, arg4.prefix);
        if (ppass != NULL) return 0;
      }

      break;
    }
    case FILTER_TYPE_SPORT: {
      uint32_t sport = stack->tcp_data.sport;
      struct bpf_map* inner_map = bpf_map_lookup_elem(&port_maps, &filter.map_idx[0]);
      if (inner_map == NULL) {
        BPF_DEBUG("callname idx:%u cannot find inner map for sport, continue ... ", call_name_idx);
        continue;
      }
      __u8* ppass = NULL;
      ppass = bpf_map_lookup_elem(inner_map, &sport);
      if (filter.op_type == OP_TYPE_IN) {
        // not in white list
        if (ppass == NULL) {
          BPF_DEBUG("callname idx:%u arg4 sport:%u not in whitelist", call_name_idx, sport);
          return 0;
        }
      } else if (filter.op_type == OP_TYPE_NOT_IN) {
        // or in black list
        if (ppass != NULL) {
          BPF_DEBUG("callname idx:%u arg4 sport:%u in blacklist", call_name_idx, sport);
          return 0;
        }
      }
    }
    case FILTER_TYPE_DPORT: {
      uint32_t dport = stack->tcp_data.dport;
      struct bpf_map* inner_map = bpf_map_lookup_elem(&port_maps, &filter.map_idx[0]);
      if (inner_map == NULL) {
        BPF_DEBUG("callname idx:%u cannot find inner map for dport, continue ... ", call_name_idx);
        continue;
      }
      __u8* ppass = NULL;
      ppass = bpf_map_lookup_elem(inner_map, &dport);
      if (filter.op_type == OP_TYPE_IN) {
        // not in white list
        if (ppass == NULL) {
          BPF_DEBUG("callname idx:%u arg4 dport:%u not in whitelist", call_name_idx, dport);
          return 0;
        }
      } else if (filter.op_type == OP_TYPE_NOT_IN) {
        // or in black list
        if (ppass != NULL) {
          BPF_DEBUG("callname idx:%u arg4 dport:%u in blacklist", call_name_idx, dport);
          return 0;
        }
      }
      break;
    }
    // case FILTER_TYPE_FILE_PREFIX: {
    //   struct string_prefix_lpm_trie *prefix = NULL;
    //   int zero = 0;
    //   prefix = bpf_map_lookup_elem(&string_prefix_maps_heap, &zero);
    //   if (prefix == NULL) {
    //     BPF_DEBUG("[kprobe][tailcall] callname idx:%u cannot lookup string_prefix_maps_heap", call_name_idx);
    //     break;
    //   }
    //   __u32 path_size = 0;
    //   bpf_probe_read(&path_size, 4, stack->file_data.path);
    //   prefix->prefixlen = path_size * 8;
    //   bpf_probe_read(prefix->data, path_size & (STRING_PREFIX_MAX_LENGTH - 1), stack->file_data.path + 4);
    //   int path_len = *(int *)stack->file_data.path;
    //   BPF_DEBUG("[kprobe][tailcall] callname idx:%u begin to query inner map. stack path length:%d", call_name_idx, path_len);
    //   BPF_DEBUG("[kprobe][tailcall] callname idx:%u begin to query inner map. stack path+4:%s", call_name_idx, &stack->file_data.path[4]);
    //   BPF_DEBUG("[kprobe][tailcall] callname idx:%u begin to query inner map. prefix path:%s, path size:%u", call_name_idx, prefix->data, path_size);
      
    //   struct bpf_map* inner_map = bpf_map_lookup_elem(&string_prefix_maps, &filter.map_idx[0]);
    //   __u8* ppass = NULL;
    //   if (inner_map != NULL) {
    //     ppass = bpf_map_lookup_elem(inner_map, prefix);
    //     if (ppass == NULL || *ppass == 0) pass &= 0;
    //     else pass &= 1;
    //   } else {
    //     // no filters were set ...
    //     BPF_DEBUG("[kprobe][tailcall] callname idx:%u cannot find inner map, no filter set, pass", call_name_idx);
    //   }
    //   break;
    // }
    default:
      break;
    }
  }

  if (pass) {
    bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_SEND);
  } else {
    BPF_DEBUG("[filter_prog] skip submit due to the filter");
  }

  return 0;
}

SEC("kprobe/secure_data_send")
int secure_data_send(struct pt_regs *ctx)
{
  BPF_DEBUG("[secure][tailcall] enter secure_data_send");
  // the max tail call, just flush event
  __u32 zero = 0;
  struct secure_tailcall_stack *data = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!data)
    return 0;
  
  switch (data->func)
  {
  case SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION:
  case SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_MMAP_FILE:
  case SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_PATH_TRUNCATE:
  case SECURE_FUNC_TRACEPOINT_FUNC_SYS_WRITE:
  case SECURE_FUNC_TRACEPOINT_FUNC_SYS_READ:{
    bpf_perf_event_output(ctx, &file_secure_output, BPF_F_CURRENT_CPU, &data->file_data, sizeof(struct file_data_t));
    BPF_DEBUG("[kprobe][secure_data_send][file] pid:%u, ktime:%u, func:%d send to perfbuffer.\n", data->file_data.key.pid, data->file_data.key.ktime, data->func);
    break;
  }
  case SECURE_FUNC_TRACEPOINT_FUNC_TCP_CLOSE:
  case SECURE_FUNC_TRACEPOINT_FUNC_TCP_CONNECT:
  case SECURE_FUNC_TRACEPOINT_FUNC_TCP_SENDMSG:
    bpf_perf_event_output(ctx, &sock_secure_output, BPF_F_CURRENT_CPU, &data->tcp_data, sizeof(struct tcp_data_t));
    BPF_DEBUG("[kprobe][secure_data_send][socket] pid:%u, ktime:%u, func:%d send to perfbuffer.\n", data->file_data.key.pid, data->file_data.key.ktime, data->func);
  default:
    break;
  }
  // bpf_perf_event_output(ctx, &file_secure_output, BPF_F_CURRENT_CPU, data, sizeof(struct secure_tailcall_stack));
  // BPF_DEBUG("[kprobe][kprobe_security_file_permission] pid:%u, ktime:%u send to perfbuffer.\n", data->key.pid, data->key.ktime);
  return 0;
}

SEC("kprobe/security_file_permission")
int kprobe_security_file_permission(struct pt_regs *ctx)
{
  BPF_DEBUG("[kprobe][kprobe_security_file_permission] enter security_file_permission.");
  __u32 zero = 0;
  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  const struct path *path_arg = 0;
  path_arg = _(&file->f_path);
  long ret = copy_path(stack->file_data.path, path_arg);
  int path_len = *(int *)stack->file_data.path;
  const u32 flag_prefix = 4 + path_len;
  int flag = -1;
  if (flag_prefix < 2000 && flag_prefix >= 0) bpf_probe_read(&flag, 4, stack->file_data.path + flag_prefix);
  const u32 mode_prefix = 8 + path_len;
  short mode = -1;
  if (mode_prefix < 2000 && mode_prefix >= 0) bpf_probe_read(&mode, 2, stack->file_data.path + mode_prefix);
  BPF_DEBUG("[kprobe][tailcall][permission] before ~ stack path length:%d, ret:%lld, flag:%d", path_len, ret, flag);
  BPF_DEBUG("[kprobe][tailcall][permission] before ~ stack path+4:%s, mode:%d", &stack->file_data.path[4], mode);

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    BPF_DEBUG("[kprobe][tailcall][permission] no init!!! return! stack path:%s, pid:%u", stack->file_data.path, pid);
    BPF_DEBUG("[kprobe][tailcall][permission] no init!!! return! stack path+4:%s, pid:%u", &stack->file_data.path[4], pid);
    return 0;
  }
  BPF_DEBUG("[kprobe][kprobe_security_file_permission] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
  // __u32 zero = 0;
  // struct secure_tailcall_stack* stack = NULL;
  // stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  // if (!stack) return 0;
  // memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION;
  stack->file_data.func = TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION;
  stack->file_data.key = enter->key;
  stack->file_data.pkey = enter->pkey;
  stack->file_data.timestamp = bpf_ktime_get_ns();
  // struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  // const struct path *path_arg = 0;
  // path_arg = _(&file->f_path);
  // copy_path(stack->file_data.path, path_arg);
  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

SEC("kprobe/security_mmap_file")
int kprobe_security_mmap_file(struct pt_regs *ctx)
{
  BPF_DEBUG("[kprobe][security_mmap_file] enter security_mmap_file.");
  __u32 zero = 0;
  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  const struct path *path_arg = 0;
  path_arg = _(&file->f_path);
  long ret = copy_path(stack->file_data.path, path_arg);
  int path_len = *(int *)stack->file_data.path;
  BPF_DEBUG("[kprobe][tailcall][mmap] before ~ stack path length:%s, ret:%lld", path_len, ret);
  BPF_DEBUG("[kprobe][tailcall][mmap] before ~ stack path+4:%s", &stack->file_data.path[4]);

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    return 0;
  }
  BPF_DEBUG("[kprobe][security_mmap_file] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
  
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_MMAP_FILE;
  stack->file_data.func = TRACEPOINT_FUNC_SECURITY_MMAP_FILE;
  stack->file_data.key = enter->key;
  stack->file_data.pkey = enter->pkey;
  stack->file_data.timestamp = bpf_ktime_get_ns();

  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

SEC("kprobe/security_path_truncate")
int kprobe_security_path_truncate(struct pt_regs *ctx)
{
  BPF_DEBUG("[kprobe][security_path_truncate] enter security_path_truncate.");
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    return 0;
  }
  BPF_DEBUG("[kprobe][security_path_truncate] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
  __u32 zero = 0;  
  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_PATH_TRUNCATE;
  stack->file_data.func = TRACEPOINT_FUNC_SECURITY_PATH_TRUNCATE;
  stack->file_data.key = enter->key;
  stack->file_data.pkey = enter->pkey;
  stack->file_data.timestamp = bpf_ktime_get_ns();
  struct path *path = (struct path *)PT_REGS_PARM1(ctx);
  const struct path *path_arg = 0;
  path_arg = _(path);
  copy_path(stack->file_data.path, path_arg);
  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

// char _license[] SEC("license") = "GPL";
