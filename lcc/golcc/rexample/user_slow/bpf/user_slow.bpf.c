/*
 * Author: Chen Tao
 * Create: Wed Nov 30 10:10:08 2022
 */
 #include "lbc.h"

struct space_rx_args {
	u64 pad;
	void * skaddr;
	u16 sport;
	u16 dport;
	u8 saddr[4];
	u8 daddr[4];
};

struct probe_args {
	u64 pad;
	u8 saddr[28];
	u8 daddr[28];
	u16 sport;
	u16 dport;
	u32 mark;
	u16 data_len;
	u32 snd_nxt;
	u32 snd_una;
	u32 snd_cwnd;
	u32 ssthresh;
	u32 snd_wnd;
	u32 srtt;
	u32 rcv_wnd;
	u64 sock_cookie;
};

struct trace_args {
	int port;
	int delay;
};

struct trace_info {
	u64 ts;
	u32 pid;
	u32 cpu1;
	u32 cpu2;
	u16 sport;
	u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
} perf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct trace_info);
} trace_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct trace_args);
} trace_args_map SEC(".maps");

//LBC_HASH(trace_map, int, struct trace_info, 1024);
//LBC_PERF_OUTPUT(e_out, struct trace_info, 128);

/*
#define OFFSET_OF(type, member) (unsigned long)(&(((type*)0)->member))
#define SKB_OFFSET_HEAD OFFSET_OF(struct sk_buff, head)
#define SKB_OFFSET_NETWORK_HEADER OFFSET_OF(struct sk_buff, network_header)

#define ntohs(x) (u16)__builtin_bswap16((u16)x)
#define ntohl(x) (u32)__builtin_bswap32((u16)x)

#define fib_bpf_printk(fmt, ...) 			\
({ 							\
	char ____fmt[] = fmt; 				\
	bpf_trace_printk(____fmt, sizeof(____fmt), 	\
			##__VA_ARGS__); 		\
}) 							\
*/

__attribute__((always_inline)) static inline struct trace_info * get_trace_info(void *map, int key) {
	struct trace_info *ret;

	ret = bpf_map_lookup_elem(map, &key);
	if (!ret) {
		return NULL;
	}
	return ret;
}

__attribute__((always_inline)) static void set_trace_info(void *map, int key, struct probe_args *probe) {

	struct trace_info info = {0};
	info.ts = bpf_ktime_get_ns();
	info.cpu1 = bpf_get_smp_processor_id();

	bpf_map_update_elem(map, &key, &info, 0);
}

SEC("tracepoint/tcp/tcp_probe")
int tcp_probe_hook(struct probe_args *args)
{
	u64 ts = bpf_ktime_get_ns();
	int key = 0;
	struct trace_args *trace_port = bpf_map_lookup_elem(&trace_args_map, &key);

	if (!trace_port)
		return 0;

	if (args->dport == trace_port->port)
		set_trace_info(&trace_map, 0, args);	

	return 0;
}

SEC("tracepoint/tcp/tcp_rcv_space_adjust")
int tcp_space_adjust_hook(struct space_rx_args *args)
{
	struct trace_info *info;
	struct trace_info old_info = {0};
	int key = 0;
	struct trace_args *trace_port = bpf_map_lookup_elem(&trace_args_map, &key);

	if (!trace_port)
		return 0;

	if (args->dport == trace_port->port) {
		info = get_trace_info(&trace_map, 0);	
		if (info != NULL) {
			// in case the value update 
			old_info = *info;
			u64 ts = bpf_ktime_get_ns();
			if (ts > old_info.ts) {
				old_info.ts = (ts - old_info.ts) / 1000;
			} else {
				old_info.ts = 0;
			}
			if (old_info.ts > trace_port->delay) {
				old_info.dport = args->dport;
				old_info.sport = args->sport;
				old_info.pid = bpf_get_current_pid_tgid() >> 32;
				old_info.cpu2 = bpf_get_smp_processor_id();
				bpf_perf_event_output(args, &perf_map, BPF_F_CURRENT_CPU, &old_info,
					sizeof(struct trace_info));
			}
		}
		bpf_map_delete_elem(&trace_map, &key);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
