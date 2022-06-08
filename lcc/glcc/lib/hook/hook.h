#ifndef __HOOK_H
#define __HOOK_H

#define IOCTL_BPF_MAP_CREATE _IOW(';', 0, union bpf_attr *)
#define IOCTL_BPF_MAP_LOOKUP_ELEM _IOWR(';', 1, union bpf_attr *)
#define IOCTL_BPF_MAP_UPDATE_ELEM _IOW(';', 2, union bpf_attr *)
#define IOCTL_BPF_MAP_DELETE_ELEM _IOW(';', 3, union bpf_attr *)
#define IOCTL_BPF_MAP_GET_NEXT_KEY _IOW(';', 4, union bpf_attr *)
#define IOCTL_BPF_PROG_LOAD _IOW(';', 5, union bpf_attr *)
#define IOCTL_BPF_PROG_ATTACH _IOW(';', 6, __u32)
#define IOCTL_BPF_PROG_FUNCNAME _IOW(';', 7, char *)
#define IOCTL_BPF_OBJ_GET_INFO_BY_FD _IOWR(';', 8, union bpf_attr *)

#define DEBUG 1
static void level_print(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

#define pr_err(fmt, ...)                                    \
    do                                                      \
    {                                                       \
        level_print("LCCHOOK: ERROR: " fmt, ##__VA_ARGS__); \
    } while (0)

#ifdef DEBUG
#define pr_dbg(fmt, ...)                                    \
    do                                                      \
    {                                                       \
        level_print("LCCHOOK: DEBUG: " fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_dbg(...)
#endif


#endif
