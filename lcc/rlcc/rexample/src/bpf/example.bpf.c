
#include "lbc.h"
#include "example.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
    struct example e;
    struct inet_sock *inet = (struct inet_sock *)sk;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, TASK_COMM_LEN);
    BPF_CORE_READ_INTO(&e.daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e.dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&e.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e.sport, inet, inet_sport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
