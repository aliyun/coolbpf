

#include <vmlinux.h>
#include <coolbpf/coolbpf.h>

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    int pid = pid();
    char command[16];
    comm(command);
    bpf_printk("%d/%s send %d bytes\n", pid, command, size);
    return 0;
}