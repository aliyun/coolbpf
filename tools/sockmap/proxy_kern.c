#include <uapi/linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned short),
	.value_size = sizeof(int),
	.max_entries = 1024,
};

SEC("sk_skb/stream_parser")
int bpf_skb_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_skb_verdict(struct __sk_buff *skb)
{
	__u16 remoteport = (__u16) bpf_ntohl(skb->remote_port);
	__u32 *type = 0;
	__u32 to = 0;
	char info_fmt[] = "remote port %d,mark %d\n";

	type = bpf_map_lookup_elem(&proxy_map, &remoteport);

	if (type == NULL) {	// origin echo
		bpf_trace_printk(info_fmt, sizeof(info_fmt), remoteport, 0);
		return bpf_sk_redirect_map(skb, &sock_map, to, 0);
	} else if (*type == 1) {	// clien -> proxy ->echo server
		bpf_trace_printk(info_fmt, sizeof(info_fmt), remoteport, *type);
		if (skb->len % 2 == 1) {
			to = 1;
		} else {
			to = 2;
		}
		return bpf_sk_redirect_map(skb, &sock_map, to, 0);
	} else if (*type == 2) {	// echo server -> proxy -> client
		bpf_trace_printk(info_fmt, sizeof(info_fmt), remoteport, *type);
		return bpf_sk_redirect_map(skb, &sock_map, to, 0);
	}
}

char _license[] SEC("license") = "GPL";
