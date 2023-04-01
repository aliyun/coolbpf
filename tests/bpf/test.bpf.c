



#include "vmlinux.h"
#include <coolbpf/coolbpf.h>

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg) {
    return 0;
}

