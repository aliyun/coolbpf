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

struct
{
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 3);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} secure_tailcall_map SEC(".maps");

BPF_PERCPU_ARRAY(tailcall_stack, struct secure_tailcall_stack, 1);

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

SEC("kprobe/security_file_permission")
int kprobe_security_file_permission(struct pt_regs *ctx)
{
  bpf_printk("[kprobe][kprobe_security_file_permission] enter security_file_permission.");
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
  bpf_printk("[kprobe][tailcall][permission] before ~ stack path length:%d, ret:%lld, flag:%d", path_len, ret, flag);
  bpf_printk("[kprobe][tailcall][permission] before ~ stack path+4:%s, mode:%d", &stack->file_data.path[4], mode);

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    bpf_printk("[kprobe][tailcall][permission] no init!!! return! stack path:%s, pid:%u", stack->file_data.path, pid);
    bpf_printk("[kprobe][tailcall][permission] no init!!! return! stack path+4:%s, pid:%u", &stack->file_data.path[4], pid);
    return 0;
  }
  bpf_printk("[kprobe][kprobe_security_file_permission] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION;
  stack->file_data.func = TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION;
  stack->file_data.key = enter->key;
  stack->file_data.pkey = enter->pkey;
  stack->file_data.timestamp = bpf_ktime_get_ns();
  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

SEC("kprobe/security_mmap_file")
int kprobe_security_mmap_file(struct pt_regs *ctx)
{
  bpf_printk("[kprobe][security_mmap_file] enter security_mmap_file.");
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
  bpf_printk("[kprobe][tailcall][mmap] before ~ stack path length:%s, ret:%lld", path_len, ret);
  bpf_printk("[kprobe][tailcall][mmap] before ~ stack path+4:%s", &stack->file_data.path[4]);

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    return 0;
  }
  bpf_printk("[kprobe][security_mmap_file] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
  
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
  bpf_printk("[kprobe][security_path_truncate] enter security_path_truncate.");
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0)
  {
    return 0;
  }
  bpf_printk("[kprobe][security_path_truncate] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);
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