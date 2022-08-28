#ifndef __EBPF_H
#define __EBPF_H

#include <linux/ioctl.h>

#define IOCTL_BPF_MAP_CREATE _IOW(';', 0, union bpf_attr *)
#define IOCTL_BPF_MAP_LOOKUP_ELEM _IOWR(';', 1, union bpf_attr *)
#define IOCTL_BPF_MAP_UPDATE_ELEM _IOW(';', 2, union bpf_attr *)
#define IOCTL_BPF_MAP_DELETE_ELEM _IOW(';', 3, union bpf_attr *)
#define IOCTL_BPF_MAP_GET_NEXT_KEY _IOW(';', 4, union bpf_attr *)
#define IOCTL_BPF_PROG_LOAD _IOW(';', 5, union bpf_attr *)
#define IOCTL_BPF_PROG_ATTACH _IOW(';', 6, __u32)
#define IOCTL_BPF_PROG_FUNCNAME _IOW(';', 7, char *)
#define IOCTL_BPF_OBJ_GET_INFO_BY_FD _IOWR(';', 8, union bpf_attr *)


struct ebpfdrv_attr {
    uint32_t prog_fd;
    char name[80];
    bool is_return;
};


static __always_inline dump_ebpfdrv_attr(struct ebpfdrv_attr *attr)
{
    printk("ebpfdrv_attr: prog_fd - %u, name - %s, is_return: %u\n", attr->prog_fd, attr->name, attr->is_return);
}
#endif