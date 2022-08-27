#include <stdio.h>
#include <stdarg.h>
#include <linux/bpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/perf_event.h>
#include <dlfcn.h>

#include "hook.h"
#define RTLD_NEXT ((void *)-1l)
typedef int (*ioctl_t)(int __fd, unsigned long int __request, ...);
typedef FILE *(*fopen_t)(const char *__filename, const char *__modes);
typedef FILE *(*fopen64_t)(const char *__filename, const char *__modes);
typedef long int (*syscall_t)(long int __sysno, ...);
static ioctl_t ioctl_p = NULL;
static fopen_t fopen_p = NULL;
static syscall_t syscall_p = NULL;
static fopen64_t fopen64_p = NULL;

static struct hook_env
{
    bool init_done;
    bool init_failed;
    int ebpfdrv_fd;
} env = {
    .init_done = false,
    .init_failed = false;
};

#define __NR_perf_event_open 298
#define __NR_bpf 321

static int env_init()
{
    int err = 0;

    if (env.init_done)
        return 0;

    if (env.init_failed)
    {
        pr_dbg("ebpfdrv has init failed, we don't try again.\n");
        return -EACCES;
    }

    ioctl_p = (ioctl_t)dlsym(RTLD_NEXT, "ioctl");
    if (ioctl_p == NULL)
        return -ENOTSUP;
#if 1 // we need this to avoid libbpf create perf event by kprobe_events
    fopen_p = (fopen_t)dlsym(RTLD_NEXT, "fopen");
    if (fopen_p == NULL)
        return -ENOTSUP;

    fopen64_p = (fopen64_t)dlsym(RTLD_NEXT, "fopen64");
    if (fopen64_p == NULL)
        return -ENOTSUP;
#endif
    syscall_p = (syscall_t)dlsym(RTLD_NEXT, "syscall");
    if (syscall_p == NULL)
        return -ENOTSUP;

#define EBPFDRV_PATH "/dev/ebpfdrv"
#define F_OK 0 /* Test for existence.  */
    env.ebpfdrv_fd = open(EBPFDRV_PATH, O_RDWR);
    if (env.ebpfdrv_fd < 0)
    {
        env.init_failed = true;
        err = -errno;
        pr_err("failed to open: %s, error message: %s\n", EBPFDRV_PATH, strerror(errno));
        return err;
    }

    pr_dbg("init ebpfdrv sucessfully.\n");
    env.init_done = true;
    return err;
}

static int bpf_prog_attach(union bpf_attr *attr)
{
    pr_dbg("attach program type is %u and program name is %s\n", attr->attach_type, attr->prog_name);
    return 0;
}

long int handle_bpf_call(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    int err;
    switch (cmd)
    {
    case BPF_MAP_CREATE:
        pr_dbg("BPF_MAP_CREATE\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_MAP_CREATE, attr);
        pr_dbg("BPF_MAP_CREATE result is %d\n", err);
        break;
    case BPF_MAP_LOOKUP_ELEM:
        pr_dbg("BPF_MAP_LOOKUP_ELEM\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_MAP_LOOKUP_ELEM, attr);
        pr_dbg("BPF_MAP_LOOKUP_ELEM result is %d\n", err);
        break;
    case BPF_MAP_UPDATE_ELEM:
        pr_dbg("BPF_MAP_UPDATE_ELEM\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_MAP_UPDATE_ELEM, attr);
        pr_dbg("BPF_MAP_UPDATE_ELEM result is %d\n", err);
        break;
    case BPF_MAP_DELETE_ELEM:
        pr_dbg("BPF_MAP_DELETE_ELEM\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_MAP_DELETE_ELEM, attr);
        pr_dbg("BPF_MAP_DELETE_ELEM result is %d\n", err);
        break;
    case BPF_MAP_GET_NEXT_KEY:
        pr_dbg("BPF_MAP_GET_NEXT_KEY\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_MAP_GET_NEXT_KEY, attr);
        pr_dbg("BPF_MAP_GET_NEXT_KEY result is %d\n", err);
        break;
    case BPF_PROG_LOAD:
        pr_dbg("BPF_PROG_LOAD\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_LOAD, attr);
        pr_dbg("BPF_PROG_LOAD result is %d\n", err);
        break;
    case BPF_PROG_ATTACH:
        pr_dbg("BPF_PROG_ATTACH\n");
        err = bpf_prog_attach(attr);
        break;
    case BPF_PROG_DETACH:
        pr_dbg("BPF_PROG_DETACH\n");
        // err = bpf_prog_detach(&attr);
        break;
    case BPF_PROG_TEST_RUN:
        pr_dbg("BPF_PROG_TEST_RUN\n");
        break;
    case BPF_BTF_LOAD:
        pr_dbg("BPF_BTF_LOAD\n");
        err = 0;
        break;
    case BPF_OBJ_GET_INFO_BY_FD:
        pr_dbg("BPF_OBJ_GET_INFO_BY_FD\n");
        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_OBJ_GET_INFO_BY_FD, attr);
        pr_dbg("BPF_OBJ_GET_INFO_BY_FD result is %d\n", err);
        break;
    default:
        pr_dbg("Unexpected bpf cmd, cmd is %d\n", cmd);
        err = -EINVAL;
        break;
    }
    return err;
}



int handle_perf_call(struct perf_event_attr *old_attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    struct perf_event_attr attr = {};
    int type;
    int err;
    int pfd;
    const char *name = (char *)old_attr->config1;

    if (old_attr->config == PERF_COUNT_SW_BPF_OUTPUT)
    {
        pr_dbg("perf_event_open create perf buffer\n");
        old_attr->config = PERF_COUNT_SW_DUMMY;
        pfd = syscall_p(__NR_perf_event_open, old_attr, pid, /* pid */ cpu, /* cpu */ group_fd /* group_fd */, flags);
        if (pfd < 0)
        {
            err = -errno;
            pr_err("create perf buffer failed: %s\n", strerror(err));
            return err;
        }
    }
    else // kprobe or tracepoint
    {
       
        // config1 is function name
        if (old_attr->config1 == 0)
        {
            // tracepoint
            pr_dbg("perf_event_open create perf event, type is tracepoint\n");
        }
        else
        {
            pr_dbg("perf_event_open create perf event, type is kprobe\n");
            // kprobe
            err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_FUNCNAME, old_attr->config1);
            if (err < 0)
            {
                pr_err("IOCTL_BPF_PROG_FUNCNAME set func name error %d\n", err);
                return err;
            }
            pfd = 0xbeef; // fake perf event fd
        }
    }
    return pfd;
}

long int syscall(long int __sysno, ...)
{
    int err;
    struct perf_event_attr *attr = NULL;
    pid_t pid;
    int cpu;
    int group_fd;
    unsigned long flags;

    va_list valist;
    va_start(valist, __sysno);
    err = env_init();
    if (err < 0)
    {
        pr_err("env init error, error %d, error string %s\n", err, strerror(err));
        return err;
    }
    switch (__sysno)
    {
    case __NR_perf_event_open:
        attr = va_arg(valist, struct perf_event_attr *);
        pid = va_arg(valist, pid_t);
        cpu = va_arg(valist, int);
        group_fd = va_arg(valist, int);
        flags = va_arg(valist, unsigned long);
        va_end(valist);
        err = handle_perf_call(attr, pid, cpu, group_fd, flags);
        break;
    case __NR_bpf:
    {
        enum bpf_cmd cmd;
        union bpf_attr *attr;
        unsigned int size;
        cmd = va_arg(valist, enum bpf_cmd);
        attr = va_arg(valist, union bpf_attr *);
        size = va_arg(valist, unsigned int);
        va_end(valist);
        err = handle_bpf_call(cmd, attr, size);
        break;
    }
    default:
    {
        err = -ENOTSUP;
        pr_err("Unexpected syscall number, program exit.\n");
        break;
    }
    }
    return err;
}

int ioctl(int __fd, unsigned long int __request, ...)
{
    int err;
    va_list valist;
    __u32 prog_fd;
    va_start(valist, __request);

    err = env_init();
    if (err < 0)
    {
        pr_err("env init error, error %d, error string %s\n", err, strerror(err));
        return err;
    }

    switch (__request)
    {
    // detach and free buffer
    case PERF_EVENT_IOC_DISABLE:
    {
        pr_dbg("PERF_EVENT_IOC_DISABLE not implement.\n");
        err = 0;
        break;
    }
    // attach
    case PERF_EVENT_IOC_SET_BPF:
    {
        pr_dbg("PERF_EVENT_IOC_SET_BPF\n");
        prog_fd = va_arg(valist, __u32);
        va_end(valist);

        err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_ATTACH, prog_fd);
        pr_dbg("PERF_EVENT_IOC_SET_BPF result %d\n", err);
        break;
    }
    // attach and enable
    case PERF_EVENT_IOC_ENABLE:
    {
        err = 0;
        pr_dbg("PERF_EVENT_IOC_ENABLE result %d\n", err);
        break;
    }
    default:
    {
        err = -ENOTSUP;
        pr_err("Unexpected ioctl request\n");
        break;
    }
    }
    return err;
}

FILE *fopen_common_handle(const char *__filename, const char *__modes, bool is64)
{
    int err;
    char subsys[128];
    char eventname[128];
#define REAL_KPROBE_TYPE_FILE "/sys/bus/event_source/devices/kprobe/type"
// It does not matter let libbpf read tracepoint type.
#define FAKE_KPROBE_TYPE_FILE "/sys/bus/event_source/devices/tracepoint/type"
#define TRACEPOINT_TYPE_FILE_PREFIX "/sys/kernel/debug/tracing/events"

    pr_dbg("fopen%s :filename: %s\n", is64 ? "64" : "", __filename);
   
    err = env_init();
    if (err < 0)
    {
        pr_err("env init error, error %d, error string %s\n", err, strerror(err));
        return NULL;
    }

    if (strncmp(__filename, REAL_KPROBE_TYPE_FILE, sizeof(REAL_KPROBE_TYPE_FILE) - 1) == 0)
    {
        if (!is64)
            return fopen_p(FAKE_KPROBE_TYPE_FILE, __modes);
        else
            return fopen64_p(FAKE_KPROBE_TYPE_FILE, __modes);
    }

    if (strncmp(TRACEPOINT_TYPE_FILE_PREFIX, __filename, sizeof(TRACEPOINT_TYPE_FILE_PREFIX) - 1) == 0)
    {
        sscanf(__filename, "/sys/kernel/debug/tracing/events/%[^/]/%[^/]/id", subsys, eventname);
        pr_dbg("subsys:%s, eventname:%s\n", subsys, eventname);
        ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_FUNCNAME, eventname);
    }
    if (!is64)
        return fopen_p(__filename, __modes);
    else
        return fopen64_p(__filename, __modes);
}

// Just let sucessfully open file but not used.
#if 1
FILE *fopen(const char *__filename, const char *__modes)
{
    return fopen_common_handle(__filename, __modes, false);
}

// Just let sucessfully open file but not used.
FILE *fopen64(const char *__filename, const char *__modes)
{
    return fopen_common_handle(__filename, __modes, true);
}

#endif
