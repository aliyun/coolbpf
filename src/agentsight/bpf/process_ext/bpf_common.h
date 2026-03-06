/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_NEW_BPF_COMMON_H
#define __PROCESS_NEW_BPF_COMMON_H

/*
 * Common BPF helpers for process_new: PID filtering + unified map update.
 * Included by process_new.bpf.c BEFORE all feature modules.
 * References maps and flags defined in the glue file.
 */

static __always_inline bool is_pid_tracked(void)
{
	if (!filter_pids)
		return true;  /* no filter mode: trace all */
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

static __always_inline bool is_cgroup_tracked(void)
{
	if (!filter_cgroup)
		return true;
	u64 cgroup_id = bpf_get_current_cgroup_id();
	if (cgroup_id == target_cgroup_id)
		return true;
	if (!filter_cgroup_children)
		return false;
	return bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id) != NULL;
}

static __always_inline bool is_event_tracked(void)
{
	return is_cgroup_tracked() && is_pid_tracked();
}

static __always_inline void update_agg_map(struct agg_key *key, u64 count, u64 bytes)
{
	struct agg_value *val = bpf_map_lookup_elem(&event_agg_map, key);
	if (val) {
		__sync_fetch_and_add(&val->count, count);
		if (bytes)
			__sync_fetch_and_add(&val->total_bytes, bytes);
		val->last_ts = bpf_ktime_get_ns();
		bpf_get_current_comm(val->comm, sizeof(val->comm));
	} else {
		struct agg_value new_val = {};
		new_val.count = count;
		new_val.total_bytes = bytes;
		new_val.first_ts = bpf_ktime_get_ns();
		new_val.last_ts = new_val.first_ts;
		bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));

		if (bpf_map_update_elem(&event_agg_map, key, &new_val, BPF_NOEXIST) < 0) {
			/* map full: bump overflow counter */
			u32 zero = 0;
			u64 *overflow = bpf_map_lookup_elem(&agg_overflow_count, &zero);
			if (overflow)
				__sync_fetch_and_add(overflow, 1);
		}
	}
}

/* Format "fd=N" into a detail buffer without bpf_snprintf */
static __always_inline void format_fd_detail(char *buf, int buf_len, int fd)
{
	/* "fd=" prefix */
	if (buf_len < 4) return;
	buf[0] = 'f'; buf[1] = 'd'; buf[2] = '=';

	/* Convert fd to decimal string */
	int pos = 3;
	bool neg = false;
	unsigned int ufd;
	if (fd < 0) {
		neg = true;
		ufd = (unsigned int)(-fd);
	} else {
		ufd = (unsigned int)fd;
	}

	/* Write digits in reverse */
	char digits[12];
	int dlen = 0;
	if (ufd == 0) {
		digits[dlen++] = '0';
	} else {
		while (ufd > 0 && dlen < 11) {
			digits[dlen++] = '0' + (ufd % 10);
			ufd /= 10;
		}
	}

	if (neg && pos < buf_len - 1)
		buf[pos++] = '-';

	for (int i = dlen - 1; i >= 0 && pos < buf_len - 1; i--)
		buf[pos++] = digits[i];

	buf[pos] = '\0';
}

/* Format "N.N.N.N:PORT" for IPv4 addresses without bpf_snprintf */
static __always_inline void format_ipv4_port(char *buf, int buf_len, u32 ip, u16 port)
{
	int pos = 0;
	u8 octets[4];
	octets[0] = ip & 0xFF;
	octets[1] = (ip >> 8) & 0xFF;
	octets[2] = (ip >> 16) & 0xFF;
	octets[3] = (ip >> 24) & 0xFF;

	/* Write each octet */
	for (int o = 0; o < 4 && pos < buf_len - 2; o++) {
		if (o > 0 && pos < buf_len - 1)
			buf[pos++] = '.';
		u8 val = octets[o];
		if (val >= 100 && pos < buf_len - 1) buf[pos++] = '0' + val / 100;
		if (val >= 10 && pos < buf_len - 1) buf[pos++] = '0' + (val / 10) % 10;
		if (pos < buf_len - 1) buf[pos++] = '0' + val % 10;
	}

	/* :PORT */
	if (pos < buf_len - 1) buf[pos++] = ':';
	char pdigits[6];
	int plen = 0;
	unsigned int p = port;
	if (p == 0) {
		pdigits[plen++] = '0';
	} else {
		while (p > 0 && plen < 5) {
			pdigits[plen++] = '0' + (p % 10);
			p /= 10;
		}
	}
	for (int i = plen - 1; i >= 0 && pos < buf_len - 1; i--)
		buf[pos++] = pdigits[i];

	buf[pos] = '\0';
}

#endif /* __PROCESS_NEW_BPF_COMMON_H */
