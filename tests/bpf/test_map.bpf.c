



#include "vmlinux.h"
#include <coolbpf/coolbpf.h>

BPF_HASH(sock_map, u64, u64, 1024);

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg) {
    return 0;
}

