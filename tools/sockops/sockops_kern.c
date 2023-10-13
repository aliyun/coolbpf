#include <uapi/linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

struct sock_key {
	uint32_t sip4;
	uint32_t dip4;
	uint8_t family;
	uint8_t pad1;
	uint16_t pad2;
	uint32_t pad3;
	uint32_t sport;
	uint32_t dport;
} __attribute__((packed));

struct bpf_map_def SEC("maps") sock_ops_map = {
	.type = BPF_MAP_TYPE_SOCKHASH,
	.key_size = sizeof(struct sock_key),
	.value_size = sizeof(int),
	.max_entries = 65535,
	.map_flags = 0,
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, __u64);
} socket_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sock_key);
	 __type(value, __u64);
	 __uint(max_entries, 1024);
} peer_stamp SEC(".maps");

static inline void sk_msg_c2s_key(struct sk_msg_md *msg, struct sock_key *key)
{
	key->dip4 = msg->local_ip4;
	key->sip4 = msg->remote_ip4;
	key->family = 1;
	key->dport = msg->local_port;
	key->sport = bpf_ntohl(msg->remote_port);
}

static inline void sk_msg_s2c_key(struct sk_msg_md *msg, struct sock_key *key)
{
	key->dip4 = msg->remote_ip4;
	key->sip4 = msg->local_ip4;
	key->family = 1;
	key->dport = bpf_ntohl(msg->remote_port);
	key->sport = msg->local_port;
}

static inline void skops_c2s_key(struct bpf_sock_ops *ops, struct sock_key *key)
{
	key->dip4 = ops->local_ip4;
	key->sip4 = ops->remote_ip4;
	key->family = 1;
	key->dport = bpf_ntohl(ops->remote_port);
	key->sport = ops->local_port;
}

static inline void skops_s2c_key(struct bpf_sock_ops *ops, struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	key->dport = ops->local_port;
	key->sport = bpf_ntohl(ops->remote_port);
}

SEC("sk_msg")
int bpf_skmsg_func(struct sk_msg_md *msg)
{
	void *data_end = (void *)(long)msg->data_end;
	void *data = (void *)(long)msg->data;
	struct sock_key key = { };

	__u64 *sk_ns;
	__u64 *peer_sk_ns;
	__u64 delta = 0;

	char info_fmt[] = ">>> sendmsg port %d->%d,delta:%ld\n";

	if (data + 8 > data_end)
		return SK_DROP;

	sk_ns = bpf_sk_storage_get(&socket_storage, msg->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (sk_ns == NULL)
		return SK_DROP;

	if (msg->local_port != 8001) {	// client -> server
		*sk_ns = bpf_ktime_get_ns();	// 记录最近一次client发送数据给server的时间
		sk_msg_c2s_key(msg, &key);
		bpf_map_update_elem(&peer_stamp, &key, sk_ns, BPF_ANY);
		return SK_PASS;
	} else {		//server -> client
		*sk_ns = bpf_ktime_get_ns();	// 记录最近一次server发送数据给client的时间
		sk_msg_s2c_key(msg, &key);
		peer_sk_ns = bpf_map_lookup_elem(&peer_stamp, &key);	//找到上次client发送数据给server的时间
		if (!peer_sk_ns)
			return SK_PASS;
		delta = *sk_ns - *peer_sk_ns;
		if (delta > 100000000)
			bpf_trace_printk(info_fmt, sizeof(info_fmt), msg->local_port, bpf_ntohl(msg->remote_port), delta);
	}

	return SK_PASS;
}

static inline void sk_extractv4_key(struct bpf_sock_ops *ops, struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = (ops->remote_port) >> 16;
}

SEC("sockops")
int bpf_sockops_func(struct bpf_sock_ops *skops)
{
	uint32_t family, op;
	struct sock_key key = { };
	family = skops->family;
	op = skops->op;
	int ret = 0;
	char info_fmt[] = "closing %d->%d\n";

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == 2) {	//AF_INET
			sk_extractv4_key(skops, &key);

			ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

			if (ret != 0) {
				bpf_printk("FAILED: sock_hash_update ret: %d\n", ret);
			}
		}
		break;
	case BPF_SOCK_OPS_STATE_CB:
		if ((skops->args[1] == BPF_TCP_CLOSE)) {
			memset(&key, 0, sizeof(struct sock_key));
			skops_s2c_key(skops, &key);
			ret = bpf_map_delete_elem(&peer_stamp, &key);
			if (ret != 0) {
				//bpf_printk("FAILED: bpf_map_delete_elem ret: %d\n", ret);
			}

			memset(&key, 0, sizeof(struct sock_key));
			skops_c2s_key(skops, &key);
			ret = bpf_map_delete_elem(&peer_stamp, &key);
			if (ret != 0) {
				//bpf_printk("FAILED: bpf_map_delete_elem ret: %d\n", ret);
			}
		}
		break;
	default:
		break;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
