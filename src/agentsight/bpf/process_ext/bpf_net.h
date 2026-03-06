/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_NEW_BPF_NET_H
#define __PROCESS_NEW_BPF_NET_H

/*
 * Network tracepoints: bind, listen, connect.
 * Extract addr:port for bind/connect, fd for listen.
 * Uses format_ipv4_port() and format_fd_detail() from bpf_common.h.
 */

/* Read sockaddr_in from userspace and format as "A.B.C.D:PORT" */
static __always_inline void read_and_format_sockaddr(struct trace_event_raw_sys_enter *ctx,
						     char *detail, int detail_len)
{
	struct sockaddr_in addr = {};
	const void *user_addr = (const void *)ctx->args[1];

	if (bpf_probe_read_user(&addr, sizeof(addr), user_addr) < 0) {
		detail[0] = '?';
		detail[1] = '\0';
		return;
	}

	u32 ip = addr.sin_addr.s_addr;
	u16 port = __builtin_bswap16(addr.sin_port);
	format_ipv4_port(detail, detail_len, ip, port);
}

/* Write "family=N" into buf */
static __always_inline void format_family(char *buf, int buf_len, u16 family)
{
	/* "family=" prefix */
	if (buf_len < 8) return;
	__builtin_memcpy(buf, "family=", 7);
	/* Use format_fd_detail trick for the number */
	int pos = 7;
	char digits[6];
	int dlen = 0;
	unsigned int f = family;
	if (f == 0) {
		digits[dlen++] = '0';
	} else {
		while (f > 0 && dlen < 5) {
			digits[dlen++] = '0' + (f % 10);
			f /= 10;
		}
	}
	for (int i = dlen - 1; i >= 0 && pos < buf_len - 1; i--)
		buf[pos++] = digits[i];
	buf[pos] = '\0';
}

SEC("tp/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_network)
		return 0;
	if (!is_event_tracked())
		return 0;

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_NET_BIND;

	u16 family = 0;
	const void *user_addr = (const void *)ctx->args[1];
	bpf_probe_read_user(&family, sizeof(family), user_addr);

	if (family == 2) /* AF_INET */
		read_and_format_sockaddr(ctx, key.detail, sizeof(key.detail));
	else
		format_family(key.detail, sizeof(key.detail), family);

	update_agg_map(&key, 1, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_network)
		return 0;
	if (!is_event_tracked())
		return 0;

	int fd = (int)ctx->args[0];

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_NET_LISTEN;
	format_fd_detail(key.detail, sizeof(key.detail), fd);

	update_agg_map(&key, 1, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_network)
		return 0;
	if (!is_event_tracked())
		return 0;

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_NET_CONNECT;

	u16 family = 0;
	const void *user_addr = (const void *)ctx->args[1];
	bpf_probe_read_user(&family, sizeof(family), user_addr);

	if (family == 2)
		read_and_format_sockaddr(ctx, key.detail, sizeof(key.detail));
	else
		format_family(key.detail, sizeof(key.detail), family);

	update_agg_map(&key, 1, 0);
	return 0;
}

#endif /* __PROCESS_NEW_BPF_NET_H */
