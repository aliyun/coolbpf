#include <linux/filter.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <coolbpf/coolbpf.h>

int main(void)
{
    bump_memlock_rlimit();
    LIBBPF_OPTS(bpf_prog_load_opts, load_opts, .kern_version = get_kernel_version());
    char bpf_func_name[] = "kprobe_tcp_sendmsg";
    char func_name[] = "tcp_sendmsg";
    
    struct bpf_insn insns[] = {
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 96),
        BPF_EMIT_CALL(BPF_FUNC_get_current_pid_tgid),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 32),
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, -16),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
        BPF_MOV64_IMM(BPF_REG_2, 16),
        BPF_EMIT_CALL(BPF_FUNC_get_current_comm),
        BPF_MOV64_IMM(BPF_REG_1, 175334772),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -24),
        BPF_LD_IMM64(BPF_REG_1, 0x796220642520646e),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -32),
        BPF_LD_IMM64(BPF_REG_1, 0x65732073252f6425),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -40),
        BPF_MOV64_IMM(BPF_REG_1, 0),
        BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -20),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -40),
        BPF_MOV64_IMM(BPF_REG_2, sizeof("%d/%s send %d bytes\n")),
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_8),
        BPF_MOV64_REG(BPF_REG_5, BPF_REG_6),
        BPF_EMIT_CALL(BPF_FUNC_trace_printk),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    int progfd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, bpf_func_name, "GPL", insns, sizeof(insns) / sizeof(struct bpf_insn), &load_opts);
    if (progfd < 0)
    {
        printf("failed to load bpf program\n");
        return 0;
    }

    struct perf_event_attr attr = {0};
    attr.size = sizeof(attr);
    attr.type = 6;
    attr.config1 = (__u64)(unsigned long)func_name;
    attr.config2 = 0;

    int pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (pfd < 0)
    {
        printf("failed to create kprobe event\n");
        close(progfd);
        return 0;
    }

    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0)
    {
        printf("failed to attach ebpf program\n");
        close(pfd);
        close(progfd);
        return 0;
    }

    if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0)
    {
        printf("failed to enable ebpf program\n");
        close(pfd);
        close(progfd);
        return 0;
    }

    while (1)
        sleep(3);

    return 0;
}
