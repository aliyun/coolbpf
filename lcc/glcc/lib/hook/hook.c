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
    int ebpfdrv_fd;
} env = {
    .init_done = false,
};

#define __NR_perf_event_open 298
#define __NR_bpf 321

static int env_init()
{
    int err;
    err = 0;
    if (env.init_done)
        return 0;

    ioctl_p = (ioctl_t)dlsym(RTLD_NEXT, "ioctl");
    if (ioctl_p == NULL)
        return -ENOTSUP;
#if 0
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

    env.init_done = true;

#define EBPFDRV_PATH "/dev/ebpfdrv"
#define F_OK 0 /* Test for existence.  */
    env.ebpfdrv_fd = open(EBPFDRV_PATH, O_RDWR);
    if (env.ebpfdrv_fd < 0)
    {
        err = -errno;
        pr_err("Open %s error.\n", EBPFDRV_PATH);
    }
    else
    {
        pr_dbg("Open %s, fd is %d\n", EBPFDRV_PATH, env.ebpfdrv_fd);
    }
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

static int poke_kprobe_events(bool add, const char *name, bool retprobe, uint64_t offset)
{
    int fd, ret = 0;
    char cmd[192] = {}, probename[128] = {}, probefunc[128] = {};
    const char *file = "/sys/kernel/debug/tracing/kprobe_events";
    pid_t p = getpid();

    if (retprobe)
        snprintf(probename, sizeof(probename), "kretprobes/%s_lcc_%u", name, p);
    else
        snprintf(probename, sizeof(probename), "kprobes/%s_lcc_%u", name, p);

    if (offset)
        snprintf(probefunc, sizeof(probefunc), "%s+%lu", name, offset);

    if (add)
    {
        snprintf(cmd, sizeof(cmd), "%c:%s %s",
                 retprobe ? 'r' : 'p',
                 probename,
                 offset ? probefunc : name);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "-:%s", probename);
    }

    fd = open(file, O_WRONLY | O_APPEND, 0);
    if (!fd)
        return -errno;
    ret = write(fd, cmd, strlen(cmd));
    if (ret < 0)
        ret = -errno;
    close(fd);

    return ret;
}

static inline int add_kprobe_event(const char *name, bool retprobe, uint64_t offset)
{
    return poke_kprobe_events(true, name, retprobe, offset);
}

/*
 * this function is expected to parse integer in the range of [0, 2^31-1] from
 * given file using scanf format string fmt. If actual parsed value is
 * negative, the result might be indistinguishable from error
 */
static int parse_uint_from_file(const char *file, const char *fmt)
{
    int err, ret;
    FILE *f;

    f = fopen_p(file, "r");
    if (!f)
    {
        err = -errno;
        pr_err("failed to open '%s': %s\n", file, strerror(err));
        return err;
    }
    err = fscanf(f, fmt, &ret);
    if (err != 1)
    {
        err = err == EOF ? -EIO : -errno;
        pr_err("failed to parse '%s': %s\n", file, strerror(err));
        fclose(f);
        return err;
    }
    fclose(f);
    return ret;
}

static int determine_kprobe_perf_type(const char *func_name, bool is_retprobe)
{
    char file[192];
    const char *fname = "/sys/kernel/debug/tracing/events/%s/%s_lcc_%d/id";

    snprintf(file, sizeof(file), fname,
             is_retprobe ? "kretprobes" : "kprobes",
             func_name, getpid());

    return parse_uint_from_file(file, "%d\n");
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
    else
    {
        pr_dbg("perf_event_open create perf event\n");
        if (old_attr->config1 == 0)
        {
            pfd = syscall_p(__NR_perf_event_open, old_attr, pid, /* pid */ cpu, /* cpu */ group_fd /* group_fd */, flags);
            if (pfd < 0)
            {
                err = -errno;
                pr_err("tracepoint perf_event_open() failed: %s\n", strerror(err));
                return err;
            }
        }
        else
        {
            err = add_kprobe_event(name, false, old_attr->config2);
            if (err < 0)
            {
                pr_err("add kprobe events failed for %s:%d\n", old_attr->config1, old_attr->config2);
                return err;
            }

            type = determine_kprobe_perf_type(name, false);
            if (type < 0)
            {
                pr_err("failed to determine legacy kprobe event id: %s\n", strerror(type));
                return type;
            }
            attr.size = sizeof(attr);
            attr.config = type;
            attr.type = PERF_TYPE_TRACEPOINT;

            err = ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_FUNCNAME, old_attr->config1);
            if (err < 0)
            {
                pr_err("IOCTL_BPF_PROG_FUNCNAME set func name error %d\n", err);
                return err;
            }
            else
            {
                pfd = syscall_p(__NR_perf_event_open, &attr, pid, /* pid */ cpu, /* cpu */ group_fd /* group_fd */, flags);
                if (pfd < 0)
                {
                    err = -errno;
                    pr_err("legacy kprobe perf_event_open() failed: %s\n", strerror(err));
                    return err;
                }
            }
        }
    }
    pr_dbg("perf event sys call return %d\n", pfd);
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
        pr_dbg("PERF_EVENT_IOC_ENABLE\n");
        // err = ioctl_p(__fd, PERF_EVENT_IOC_ENABLE, 0);
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

// Just let sucessfully open file but not used.
#if 0
FILE *fopen(const char *__filename, const char *__modes)
{
    int err;
    char subsys[128];
    char eventname[128];
#define REAL_KPROBE_TYPE_FILE "/sys/bus/event_source/devices/kprobe/type"
#define FAKE_KPROBE_TYPE_FILE "./kprobe_type"
#define TRACEPOINT_TYPE_FILE_PREFIX "/sys/kernel/debug/tracing/events"

    err = env_init();
    if (err < 0)
    {
        pr_err("env init error, error %d, error string %s\n", err, strerror(err));
        return NULL;
    }

    pr_dbg("fopen in\n");

    if (strncmp(__filename, REAL_KPROBE_TYPE_FILE, sizeof(REAL_KPROBE_TYPE_FILE) - 1) == 0)
    {
        return fopen_p(FAKE_KPROBE_TYPE_FILE, __modes);
    }

    if (strncmp(TRACEPOINT_TYPE_FILE_PREFIX, __filename, sizeof(TRACEPOINT_TYPE_FILE_PREFIX) - 1) == 0)
    {
        sscanf(__filename, "/sys/kernel/debug/tracing/events/%[^/]/%[^/]/id", subsys, eventname);
        pr_dbg("subsys:%s, eventname:%s\n", subsys, eventname);
        ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_FUNCNAME, eventname);
    }
    return fopen_p(__filename, __modes);
}

// Just let sucessfully open file but not used.
FILE *fopen64(const char *__filename, const char *__modes)
{
    int err;
    char subsys[128];
    char eventname[128];
#if 0
// libbpf support legacy kprobe now.
#define REAL_KPROBE_TYPE_FILE "/sys/bus/event_source/devices/kprobe/type"
#define FAKE_KPROBE_TYPE_FILE "./kprobe_type"
#endif
#define TRACEPOINT_TYPE_FILE_PREFIX "/sys/kernel/debug/tracing/events"

    err = env_init();
    if (err < 0)
    {
        pr_err("env init error, error %d, error string %s\n", err, strerror(err));
        return NULL;
    }

    pr_dbg("fopen64 in\n");
#if 0
    if (strncmp(__filename, REAL_KPROBE_TYPE_FILE, sizeof(REAL_KPROBE_TYPE_FILE) - 1) == 0)
    {
        return fopen64_p(FAKE_KPROBE_TYPE_FILE, __modes);
    }
#endif

    if (strncmp(TRACEPOINT_TYPE_FILE_PREFIX, __filename, sizeof(TRACEPOINT_TYPE_FILE_PREFIX) - 1) == 0)
    {
        sscanf(__filename, "/sys/kernel/debug/tracing/events/%[^/]/%[^/]/id", subsys, eventname);
        pr_dbg("subsys:%s, eventname:%s\n", subsys, eventname);
        ioctl_p(env.ebpfdrv_fd, IOCTL_BPF_PROG_FUNCNAME, eventname);
    }
    return fopen64_p(__filename, __modes);
}

#endif 
