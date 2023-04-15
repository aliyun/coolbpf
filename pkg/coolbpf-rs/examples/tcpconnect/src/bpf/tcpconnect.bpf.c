

#include <coolbpf/vmlinux.h>
#include <coolbpf/coolbpf.h>

#include "tcpconnect.h"


BPF_HASH(sockets, u32, struct sock *, 102400);
BPF_PERF_OUTPUT(perf, 1024);


SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
    u32 tid = tid();
    struct sock *sk;
    struct sock **skp;
    struct event event = {};

    if (ret)
        goto out;

    skp = bpf_map_lookup_elem(&sockets, &tid);
    if (skp) {
        sk = *skp;
        event.ns = ns();
        event.cpu = cpu();
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
        event.dport = bpf_ntohs(event.dport);
        bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, &event, sizeof(struct event));
    }
out:
    bpf_map_delete_elem(&sockets, &tid);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sk_buff *skb)
{
    u32 tid = tid();
    bpf_map_update_elem(&sockets, &tid, &sk, BPF_ANY);
    return 0;
}