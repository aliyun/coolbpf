//
// Created by 廖肇燕 on 2021/7/15.
//
#include "lbc.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

#define CON_NAME_LEN 80
#define TASK_COMM_LEN 16

struct liphdr {
    __u8 ver_hdl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

struct data_t {
    char con[CON_NAME_LEN];
    char comm[TASK_COMM_LEN];
    u32 pid;
    u32 type;
    u32 ip_src;
    u32 ip_dst;
    u16 sport;
    u16 dport;
    u16 sk_state;
    u16 stack_id;

    u32 rcv_nxt;
    u32 rcv_wup;
    u32 snd_nxt;
    u32 snd_una;
    u32 copied_seq;
    u32 snd_wnd;
    u32 rcv_wnd;

    u32 lost_out;
    u32 packets_out;
    u32 retrans_out;
    u32 sacked_out;
    u32 reordering;
} ;

LBC_PERF_OUTPUT(net_map, struct data_t, 1024);
LBC_STACK(callStack,128);
LBC_PERCPU_HASH(sock_task, u64, u64, 256*1024);

static inline int get_tcp_info(struct data_t* pdata, struct tcp_sock *ts)
{
    pdata->rcv_nxt = BPF_CORE_READ(ts, rcv_nxt);
    pdata->rcv_wup = BPF_CORE_READ(ts, rcv_wup);
    pdata->snd_nxt = BPF_CORE_READ(ts, snd_nxt);
    pdata->snd_una = BPF_CORE_READ(ts, snd_una);
    pdata->copied_seq = BPF_CORE_READ(ts, copied_seq);
    pdata->snd_wnd = BPF_CORE_READ(ts, snd_wnd);
    pdata->rcv_wnd = BPF_CORE_READ(ts, rcv_wnd);

    pdata->lost_out = BPF_CORE_READ(ts, lost_out);
    pdata->packets_out = BPF_CORE_READ(ts, packets_out);
    pdata->retrans_out = BPF_CORE_READ(ts, retrans_out);
    pdata->sacked_out = BPF_CORE_READ(ts, sacked_out);
    pdata->reordering = BPF_CORE_READ(ts, reordering);
    return 0;
}

static inline int get_skb_info(struct data_t* pdata, struct sk_buff *skb, u32 type)
{
    u16 offset;
    u8 ihl;
    void* head;
    struct liphdr *piph;
    struct tcphdr *ptcph;

    pdata->type = type;
    pdata->sk_state = 0;

    head = (void*)BPF_CORE_READ(skb, head);
    offset = BPF_CORE_READ(skb, network_header);
    piph = (struct liphdr *)(head + offset);
    ihl = _(piph->ver_hdl) & 0x0f;
    ptcph = (struct tcphdr *)((void *)piph + ihl * 4);

    pdata->ip_dst = _(piph->daddr);
    pdata->dport = BPF_CORE_READ(ptcph, dest);
    pdata->ip_src = _(piph->daddr);
    pdata->sport = BPF_CORE_READ(ptcph, source);
    return 0;
}

static inline void store_con(char* con, struct task_struct *p)
{
    struct cgroup_name *cname;
    cname = BPF_CORE_READ(p, cgroups, subsys[0], cgroup, name);
    if (cname != NULL) {
        bpf_core_read(con, CON_NAME_LEN, &cname->name[0]);
    } else {
        con[0] = '\0';
    }
}

static inline void get_task(struct data_t* pdata, struct sock *sk)
{
    u64 k = (u64)sk;
    if (k == 0) {
        goto clear_task;
    }
    u64 *pv = bpf_map_lookup_elem(&sock_task, &k);
    if (pv && *pv) {
        struct task_struct *p = (struct task_struct *)*pv;
        struct cgroup_name *cname;
        pdata->pid = BPF_CORE_READ(p, tgid);
        bpf_probe_read(&pdata->comm[0], TASK_COMM_LEN, &p->comm[0]);
        store_con(&pdata->con[0], p);
//        bpf_printk("con: %s, comm:%s, pid:%d\n", pdata->con, pdata->comm, pdata->pid);
        return;
    }
clear_task:
    pdata->pid = 0;
    pdata->comm[0] = '\0';
    pdata->con[0] = '\0';
}

static inline int get_info(struct data_t* pdata, struct sock *sk, u32 type)
{
    struct inet_sock *inet = (struct inet_sock *)sk;

    pdata->type = type;
    pdata->ip_dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pdata->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    pdata->ip_src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pdata->sport = BPF_CORE_READ(inet, inet_sport);
    pdata->sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    return 0;
}

SEC("kretprobe/sk_alloc")
int BPF_KRETPROBE(r_sk_alloc, struct sock *sk)
{
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    u64 k, v = 0;
    k = (u64)sk;
    v = (u64)p;
    bpf_map_update_elem(&sock_task, &k, &v, BPF_ANY);
    return 0;
}

SEC("kprobe/sk_free")
int j_sock_release(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (BPF_CORE_READ(sk, sk_wmem_alloc.counter)) {
        return 0;
    }
    u64 k = (u64)sk;
    bpf_map_delete_elem(&sock_task, &k);
    return 0;
}

SEC("kprobe/tcp_enter_loss")
int j_tcp_enter_loss(struct pt_regs *ctx)
{
    struct sock *sk;
    struct data_t data = {};
    u32 stat;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    stat = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (stat == 0 || stat == 2) {
        return 0;
    }
    get_task(&data, sk);
    get_info(&data, sk, 0);
    data.stack_id = 0;
    get_tcp_info(&data, (struct tcp_sock *)sk);

    bpf_perf_event_output(ctx, &net_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/tcp_send_probe0")
int j_tcp_send_probe0(struct pt_regs *ctx)
{
    struct sock *sk;
    struct data_t data = {};
    u32 stat;

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    stat = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (stat == 0) {
        return 0;
    }

    get_info(&data, sk, 1);
    data.stack_id = 0;
    get_task(&data, sk);
    get_tcp_info(&data, (struct tcp_sock *)sk);

    bpf_perf_event_output(ctx, &net_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/tcp_v4_send_reset")
int j_tcp_v4_send_reset(struct pt_regs *ctx)
{
    struct sock *sk;
    struct data_t data = {};

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        get_skb_info(&data, skb, 2);
        get_task(&data, NULL);
        data.stack_id = 0;
    }
    else {
        get_info(&data, sk, 3);
        get_task(&data, sk);
        data.stack_id = bpf_get_stackid(ctx, &callStack, KERN_STACKID_FLAGS);
    }
    bpf_perf_event_output(ctx, &net_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/tcp_send_active_reset")
int j_tcp_send_active_reset(struct pt_regs *ctx)
{
    struct sock *sk;
    struct data_t data = {};

    sk = (struct sock *)PT_REGS_PARM1(ctx);
    get_info(&data, sk, 4);
    data.stack_id = bpf_get_stackid(ctx, &callStack, KERN_STACKID_FLAGS);

     get_task(&data, sk);
    bpf_perf_event_output(ctx, &net_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
