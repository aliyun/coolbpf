#include <vmlinux.h>
#include "coolbpf.h"

struct
{
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, u64);
        __uint(max_entries, 1);
} reusemap SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
        int key = 0;
        u64 val = 0xffff;
        bpf_map_update_elem(&reusemap, &key, &val, BPF_ANY);
        return 0;
}