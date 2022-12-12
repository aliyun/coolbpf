
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <sys/ioctl.h> 
#include <fcntl.h>
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

#define IOCTL_BPF_MAP_CREATE _IOW(';', 0, union bpf_attr *)
#define IOCTL_BPF_MAP_LOOKUP_ELEM _IOWR(';', 1, union bpf_attr *)
#define IOCTL_BPF_MAP_UPDATE_ELEM _IOW(';', 2, union bpf_attr *)
#define IOCTL_BPF_MAP_DELETE_ELEM _IOW(';', 3, union bpf_attr *)
#define IOCTL_BPF_MAP_GET_NEXT_KEY _IOW(';', 4, union bpf_attr *)
#define IOCTL_BPF_PROG_LOAD _IOW(';', 5, union bpf_attr *)
#define IOCTL_BPF_PROG_ATTACH _IOW(';', 6, __u32)
#define IOCTL_BPF_PROG_FUNCNAME _IOW(';', 7, char *)
#define IOCTL_BPF_OBJ_GET_INFO_BY_FD _IOWR(';', 8, union bpf_attr *)

#define EBPFDRV_PATH "/dev/ebpfdrv"

static struct bpf_drv_env
{
    uint8_t needed;
    int ebpfdrv_fd;
} env = {
    .needed = false,
    .ebpfdrv_fd = 0,
};

struct ebpfdrv_attr
{
    uint32_t prog_fd;
    union
    {
        struct
        {
            bool is_return;
            uint64_t name;
        } kprobe;

        struct
        {
            uint64_t category;
            uint64_t name;
        } tracepoint;

        struct 
        {
            int pfd;
        } perf_events;
    };
};

bool bpf_drv_loaded()
{
    return env.ebpfdrv_fd != 0;
}

bool bpf_drv_needed()
{
    return env.needed;
}

bool bpf_drv_enabled()
{
    return bpf_drv_loaded() && bpf_drv_needed();
}

void bpf_drv_init()
{
    int err;
    
    if (getenv("ENABLE_BPF_DRV"))
    {
        pr_debug("You have set ENABLE_BPF_DRV environment variable.\n");
        err = syscall(__NR_bpf, 0);
        if (err < 0 && errno == ENOSYS) {
            pr_debug("Your machine doesn't support bpf syscall.\n");
            env.needed = true;
        }
    }
}

int bpf_drv_open()
{
    int fd;
    
    fd = open(EBPFDRV_PATH, O_RDWR);
    if (fd < 0)
    {
        pr_warn("failed to open ebpf driver: %s, error: %s\n", EBPFDRV_PATH, strerror(errno));
        return -errno;
    }
    pr_debug("open %s sucessfully.\n", EBPFDRV_PATH);
    env.ebpfdrv_fd = fd;
    
    return 0;
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int sys_bpf_ioctl(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    unsigned long int request;

    switch (cmd)
    {
    case BPF_MAP_CREATE:
        request = IOCTL_BPF_MAP_CREATE;
        break;
    case BPF_MAP_LOOKUP_ELEM:
        request = IOCTL_BPF_MAP_LOOKUP_ELEM;
        break;
    case BPF_MAP_UPDATE_ELEM:
        request = IOCTL_BPF_MAP_UPDATE_ELEM;
        break;
    case BPF_MAP_DELETE_ELEM:
        request = IOCTL_BPF_MAP_DELETE_ELEM;
        break;
    case BPF_MAP_GET_NEXT_KEY:
        request = IOCTL_BPF_MAP_GET_NEXT_KEY;
        break;
    case BPF_PROG_LOAD:
        request = IOCTL_BPF_PROG_LOAD;
        break;
    case BPF_OBJ_GET_INFO_BY_FD:
        request = IOCTL_BPF_OBJ_GET_INFO_BY_FD;
        break;
    default:
        pr_warn("bpf_drv doesn't support bpf cmd: %d\n", cmd);
        return -EINVAL;
    }

    return ioctl(env.ebpfdrv_fd, request, attr);
}

int bpf_drv_attach_kprobe(const struct bpf_program *prog, bool retprobe, const char *func_name)
{
    struct ebpfdrv_attr attr = {};
    int prog_fd;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
		pr_warn("prog '%s': can't attach BPF program w/o FD (did you load it?)\n",
			bpf_program__name(prog));
		return -EINVAL;
	}
    attr.prog_fd = prog_fd;
    attr.kprobe.is_return = retprobe;
    attr.kprobe.name = ptr_to_u64(func_name);
    return ioctl(env.ebpfdrv_fd, IOCTL_BPF_PROG_ATTACH, &attr);
}

int bpf_drv_attach_tracepoint(const struct bpf_program *prog, const char *tp_category, const char *tp_name)
{
    struct ebpfdrv_attr attr = {};
    int prog_fd;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
		pr_warn("prog '%s': can't attach BPF program w/o FD (did you load it?)\n",
			bpf_program__name(prog));
		return -EINVAL;
	}
    attr.prog_fd = prog_fd;
    attr.tracepoint.category = ptr_to_u64(tp_category);
    attr.tracepoint.name = ptr_to_u64(tp_name);
    return ioctl(env.ebpfdrv_fd, IOCTL_BPF_PROG_ATTACH, &attr);
}

int bpf_drv_attach_perf_events(const struct bpf_program *prog, int pfd)
{
    struct ebpfdrv_attr attr = {};

    attr.prog_fd = bpf_program__fd(prog);
    attr.perf_events.pfd = pfd;
    return ioctl(env.ebpfdrv_fd, IOCTL_BPF_PROG_ATTACH, &attr);
}