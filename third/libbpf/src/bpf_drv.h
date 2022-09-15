
#ifndef __BPF_DRV_H
#define __BPF_DRV_H


#define CONFIG_BPF_DRV


// 
void bpf_drv_init();

// open bpf driver.
int bpf_drv_open();


bool bpf_drv_enabled();
// bpf driver is needed when ENABLE_BPF_DRV is set in environment 
// and kernel doesn't support bpf syscall.
bool bpf_drv_needed();
bool bpf_drv_loaded();

int bpf_drv_attach_kprobe(struct bpf_program *prog, bool retprobe, const char *func_name);
int bpf_drv_attach_tracepoint(struct bpf_program *prog, const char *tp_category, const char *tp_name);
int bpf_drv_attach_perf_events(struct bpf_program *prog, int pfd);
int sys_bpf_ioctl(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size);

#endif

