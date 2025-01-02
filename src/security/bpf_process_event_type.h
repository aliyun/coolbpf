//
// Created by qianlu on 2024/6/20.
//

#ifndef SYSAK_BPF_PROCESS_EVENT_TYPE_H
#define SYSAK_BPF_PROCESS_EVENT_TYPE_H

#ifdef __cplusplus
#include <linux/types.h>
#endif
#include "bpf_common.h"
#include "bpf_cred.h"
#include "msg_type.h"


/* Max number of args to parse */
#define MAXARGS 20
/* Max length of any given arg */
#define MAXARGLENGTH 256
/* This is the absolute buffer size for args and filenames including some
 * extra head room so we can append last args string to buffer. The extra
 * headroom is an unfortunate result of bounds on offset/size in
 * event_args_builder().
 *
 * For example given an offset bounds
 *
 *   offset <- (0, 100)
 *
 * We will read into the buffer using this offset giving a max offset
 * of eargs + 100.
 *
 *   args[offset] <- (0, 100)
 *
 * Now we want to read this with call 45 aka bpf_probe_read_str as follows,
 * where 'kernel_struct_arg' is the kernel data struct we are reading.
 *
 *   bpf_probe_read_str(args[offset], size, kernel_struct_arg)
 *
 * But we have a bit of a problem determining if 'size' is out of array
 * range. The math would be,
 *
 *   size = length - offset
 *
 * Giving the remainder of the buffer,
 *
 * args          offset             length
 *    |---------------|------------------|
 *
 *                    |-------size-------|
 *
 * But verifier math works on bounds so bounds analysis of size is the
 * following,
 *
 *   length = 1024
 *   offset = (0, 100)
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   size <- (924, 1124)
 *
 * And verifier throws an error because args[offset + size] with bounds
 * anaylsis,
 *
 *   args_(max)[100 + 1024] = args_(max)[1124]
 *
 * To circumvent this, at least until we teach the verifier about
 * dependent variables, create a maxarg value and pad arg buffer with
 * it. Giving a args buffer of size 'length + pad' with above bounds
 * analysis,
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   if size > pad goto done
 *   size <- (924, 1124) // 1124 < length + pad
 *
 * Phew all clear now?
 */
#define CWD_MAX	     256
#define BUFFER	     1024
#define SIZEOF_EVENT 56
#define PADDED_BUFFER \
	(BUFFER + MAXARGLENGTH + SIZEOF_EVENT + SIZEOF_EVENT + CWD_MAX)
/* This is the usable buffer size for args and filenames. It is calculated
 * as the (BUFFER SIZE - sizeof(parent) - sizeof(curr) but unfortunately
 * preprocess doesn't know types so we do it manually without sizeof().
 */
#define ARGSBUFFER	 (BUFFER - SIZEOF_EVENT - SIZEOF_EVENT)
#define __ASM_ARGSBUFFER 976
#define ARGSBUFFERMASK	 (ARGSBUFFER - 1)
#define MAXARGMASK	 (MAXARG - 1)
#define PATHNAME_SIZE	 256

/* Task flags */
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */
#endif

/* Msg flags */
#define EVENT_UNKNOWN		      0x00
#define EVENT_EXECVE		      0x01
#define EVENT_EXECVEAT		      0x02
#define EVENT_PROCFS		      0x04
#define EVENT_TRUNC_FILENAME	      0x08
#define EVENT_TRUNC_ARGS	      0x10
#define EVENT_TASK_WALK		      0x20
#define EVENT_MISS		      0x40
#define EVENT_NEEDS_AUID	      0x80
#define EVENT_ERROR_FILENAME	      0x100
#define EVENT_ERROR_ARGS	      0x200
#define EVENT_NEEDS_CWD		      0x400
#define EVENT_NO_CWD_SUPPORT	      0x800
#define EVENT_ROOT_CWD		      0x1000
#define EVENT_ERROR_CWD		      0x2000
#define EVENT_CLONE		      0x4000
#define EVENT_ERROR_SOCK	      0x8000
#define EVENT_ERROR_CGROUP_NAME	      0x010000
#define EVENT_ERROR_CGROUP_KN	      0x020000
#define EVENT_ERROR_CGROUP_SUBSYSCGRP 0x040000
#define EVENT_ERROR_CGROUP_SUBSYS     0x080000
#define EVENT_ERROR_CGROUPS	      0x100000
#define EVENT_ERROR_CGROUP_ID	      0x200000
#define EVENT_ERROR_PATH_COMPONENTS   0x400000
#define EVENT_DATA_FILENAME	      0x800000
#define EVENT_DATA_ARGS		      0x1000000

#define EVENT_COMMON_FLAG_CLONE 0x01

/* Docker IDs are unique at first 12 characters, but we want to get
 * 12chars plus any extra prefix used by the container environment.
 * Minikube for example prepends 'docker-' to the id. So lets copy
 * 32B and assume at least 12B of it is ID info.
 */
#define DOCKER_ID_LENGTH 128

struct msg_execve_key {
  __u32 pid; // Process TGID
  __u8 pad[4];
  __u64 ktime;
}; // All fields aligned so no 'packed' attribute.

/* This is the struct stored in bpf map to share info between
 * different execve hooks.
 */
struct execve_info {
  /* The secureexec is to reflect the kernel bprm->secureexec that is exposed
   * to userspace through auxiliary vector which can be read from
   * /proc/self/auxv or https://man7.org/linux/man-pages/man3/getauxval.3.html
   *
   * The AT_SECURE of auxv can have a value of 1 or 0 and it is set from
   * the bprm->secureexec that is a bit field.
   * If bprm->secureexec is 1 then it means executable should be treated securely.
   * Most commonly, 1 indicates that the process is executing a set-user-ID
   * or set-group-ID binary (so that its real and effective UIDs or GIDs differ
   * from one another), or that it gained capabilities by executing a binary file
   * that has capabilities (see capabilities(7)).
   * Alternatively, a nonzero value may be triggered by a Linux Security Module.
   * When this value is nonzero, the dynamic linker disables the use of certain
   * environment variables.
   *
   * The secureexec here can have the following bit flags:
   *   EXEC_SETUID or EXEC_SETGID
   */
  __u32 secureexec;
  __u32 i_nlink; /* inode links */
  __u64 i_ino; /* inode number */
};

/* process information
 *
 * Manually linked to ARGSBUFFER and PADDED_BUFFER if this changes then please
 * also change SIZEOF_EVENT.
 */
struct msg_process {
  __u32 size;
  __u32 pid; // Process TGID
  __u32 tid; // Process thread
  __u32 nspid;
  __u32 secureexec;
  __u32 uid;
  __u32 auid;
  __u32 flags;
  __u32 i_nlink;
  __u32 pad;
  __u64 i_ino;
  __u64 ktime;
  char *args;
}; // All fields aligned so no 'packed' attribute.

/* msg_clone_event holds only the necessary fields to construct a new entry from
 * the parent after a clone() event.
 */
struct msg_clone_event {
  struct msg_common common;
  struct msg_execve_key parent;
  __u32 tgid;
  __u32 tid;
  __u32 nspid;
  __u32 flags;
  __u64 ktime;
} __attribute__((packed));

struct exit_info {
  __u32 code;
  __u32 tid; // Thread ID
};

struct msg_exit {
  struct msg_common common;
  struct msg_execve_key current;
  struct exit_info info;
}; // All fields aligned so no 'packed' attribute.

enum {
  ns_uts = 0,
  ns_ipc = 1,
  ns_mnt = 2,
  ns_pid = 3,
  ns_pid_for_children = 4,
  ns_net = 5,
  ns_time = 6,
  ns_time_for_children = 7,
  ns_cgroup = 8,
  ns_user = 9,

  // If you update the value of ns_max_types you
  // should also update parseMatchNamespaces()
  // in kernel.go
  ns_max_types = 10,
};

struct msg_ns {
  union {
    struct {
      __u32 uts_inum;
      __u32 ipc_inum;
      __u32 mnt_inum;
      __u32 pid_inum;
      __u32 pid_for_children_inum;
      __u32 net_inum;
      __u32 time_inum;
      __u32 time_for_children_inum;
      __u32 cgroup_inum;
      __u32 user_inum;
    };
    __u32 inum[ns_max_types];
  };
}; // All fields aligned so no 'packed' attribute.

struct msg_k8s {
  __u32 net_ns;
  __u32 cid;
  __u64 cgrpid;
  char docker_id[DOCKER_ID_LENGTH];
}; // All fields aligned so no 'packed' attribute.

#define BINARY_PATH_MAX_LEN 256

struct heap_exe {
  // because of verifier limitations, this has to be 2 * 256 bytes while 256
  // should be theoretically sufficient, and actually is, in unit tests.
  char buf[BINARY_PATH_MAX_LEN * 2];
  // offset points to the start of the path in the above buffer. Use offset to
  // read the path in the buffer since it's written from the end.
  char *off;
  __u32 len;
  __u32 error;
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_event {
  struct msg_common common;
  struct msg_k8s kube;
  struct msg_execve_key parent;
  __u64 parent_flags;
  struct msg_cred creds;
  struct msg_ns ns;
  struct msg_execve_key cleanup_key;
  /* if add anything above please also update the args of
   * validate_msg_execve_size() in bpf_execve_event.c */
  union {
    struct msg_process process;
    char buffer[PADDED_BUFFER];
  };
  /* below fields are not part of the event, serve just as
   * heap for execve programs
   */
#ifdef __LARGE_BPF_PROG
  struct heap_exe exe;
#endif
}; // All fields aligned so no 'packed' attribute.

// This structure stores the binary path that was recorded on execve.
// Technically PATH_MAX is 4096 but we limit the length we store since we have
// limits on the length of the string to compare:
// - Artificial limits for full string comparison.
// - Technical limits for prefix and postfix, using LPM_TRIE that have a 256
//   bytes size limit.
struct binary {
  // length of the path stored in path, this should be < BINARY_PATH_MAX_LEN
  // but can contain negative value in case of copy error.
  // While s16 would be sufficient, 64 bits are handy for alignment.
  __s64 path_length;
  // BINARY_PATH_MAX_LEN first bytes of the path
  char path[BINARY_PATH_MAX_LEN];
}; // All fields aligned so no 'packed' attribute

// The execve_map_value is tracked by the TGID of the thread group
// the msg_execve_key.pid. The thread IDs are recorded on the
// fly and sent with every corresponding event.
struct execve_map_value {
  struct msg_execve_key key;
  struct msg_execve_key pkey;
  __u32 flags;
  __u32 nspid;
  struct msg_ns ns;
  struct msg_capabilities caps;
  struct binary bin;
} __attribute__((packed)) __attribute__((aligned(8)));


struct msg_throttle {
  struct msg_common common;
  struct msg_k8s kube;
};


struct cgroup_rate_key {
  __u64 id;
};

struct cgroup_rate_value {
  __u64 curr;
  __u64 prev;
  __u64 time;
  __u64 rate;
  __u64 throttled;
};

struct cgroup_rate_options {
  __u64 events;
  __u64 interval;
};



#endif //SYSAK_BPF_PROCESS_EVENT_TYPE_H
