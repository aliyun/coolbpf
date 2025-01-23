#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"

#include "int_maps.h"
#include "filter.h"
#include "type.h"
#include "process.h"
#include "addr_lpm_maps.h"
#include "string_maps.h"
#include "bpf_exit.h"
#include "tailcall_stack.h"

BPF_PERCPU_ARRAY(sock_secure_data_heap, struct tcp_data_t, 1);
BPF_PERCPU_ARRAY(tailcall_stack, struct secure_tailcall_stack, 1);

struct
{
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 3);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} secure_tailcall_map SEC(".maps");

static __always_inline u16 bpf_core_sock_sk_protocol_ak(struct sock *sk)
{
  return (u16)BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
}

static __always_inline u32 get_netns(struct sock *sk) {
  return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    bpf_printk("[kprobe][kprobe_tcp_sendmsg] pid:%u never enter. skip collect", pid);
    return 0;
  }
  bpf_printk("[kprobe][kprobe_tcp_sendmsg] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  // define event
  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_SENDMSG;
  data->key = enter->key;
  data->pkey = enter->pkey;

  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);
  data->bytes = size;

  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_SENDMSG;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_SENDMSG;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  stack->tcp_data.bytes = size;
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] saddr:%u, daddr:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.daddr, data->family);
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] daddr:%u, sport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.sport, data->state);


  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

// void tcp_close(struct sock *sk, long timeout);
SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    bpf_printk("[kprobe][kprobe_tcp_close] pid:%u never enter. skip collect", pid);
    return 0;
  }
  bpf_printk("[kprobe][kprobe_tcp_close] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_CLOSE;
  data->key = enter->key;
  data->pkey = enter->pkey;
  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);

  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_CLOSE;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_CLOSE;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] saddr:%u, sport:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.sport, data->family);
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] daddr:%u, dport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.dport, data->state);


  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}

//
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct execve_map_value *enter;
  enter = execve_map_get_noinit(pid);
  if (!enter || enter->key.ktime == 0) {
    bpf_printk("[kprobe][kprobe_tcp_connect] pid:%u never enter. skip collect", pid);
    return 0;
  }
  bpf_printk("[kprobe][kprobe_tcp_connect] pid:%u ktime:%llu already enter.", pid, enter->key.ktime);

  __u32 zero = 0;
  struct tcp_data_t* data = NULL;
  data = bpf_map_lookup_elem(&sock_secure_data_heap, &zero);
  if (!data) return 0;
  memset(data, 0, sizeof(data));

  data->func = TRACEPOINT_FUNC_TCP_CONNECT;
  data->key = enter->key;
  data->pkey = enter->pkey;

  struct inet_sock *inet = (struct inet_sock *)sk;
  data->timestamp = bpf_ktime_get_ns();
  unsigned int daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  data->daddr = bpf_htonl(daddr);
  unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  data->dport = bpf_htons(dport);
  unsigned int saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  data->saddr = bpf_htonl(saddr);
  unsigned short sport = BPF_CORE_READ(inet, inet_sport);
  data->sport = bpf_htons(sport);
  data->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  data->family = BPF_CORE_READ(sk, __sk_common.skc_family);
  data->net_ns = get_netns(sk);
  data->protocol = bpf_core_sock_sk_protocol_ak(sk);


  struct secure_tailcall_stack* stack = NULL;
  stack = bpf_map_lookup_elem(&tailcall_stack, &zero);
  if (!stack) return 0;
  memset(stack, 0, sizeof(stack));
  stack->func = SECURE_FUNC_TRACEPOINT_FUNC_TCP_CONNECT;
  stack->tcp_data.func = TRACEPOINT_FUNC_TCP_CONNECT;
  stack->tcp_data.key = enter->key;
  stack->tcp_data.pkey = enter->pkey;
  stack->tcp_data.timestamp = bpf_ktime_get_ns();
  stack->tcp_data.daddr = daddr;
  stack->tcp_data.dport = bpf_htons(dport);
  stack->tcp_data.saddr = saddr;
  stack->tcp_data.sport = bpf_htons(sport);
  stack->tcp_data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
  stack->tcp_data.family = BPF_CORE_READ(sk, __sk_common.skc_family);
  stack->tcp_data.net_ns = get_netns(sk);
  stack->tcp_data.protocol = bpf_core_sock_sk_protocol_ak(sk);
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] saddr:%u, sport:%u, family:%u",
             stack->tcp_data.saddr, stack->tcp_data.sport, data->family);
  bpf_printk("[kprobe][kprobe_tcp_sendmsg][dump] daddr:%u, dport:%u, state:%u",
             stack->tcp_data.daddr, stack->tcp_data.dport, data->state);


  bpf_tail_call(ctx, &secure_tailcall_map, TAILCALL_FILTER_PROG);
  return 0;
}
