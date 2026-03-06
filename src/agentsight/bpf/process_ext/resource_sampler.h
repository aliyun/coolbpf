/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_NEW_RESOURCE_SAMPLER_H
#define __PROCESS_NEW_RESOURCE_SAMPLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include "process.h"

/* ========== Data structures ========== */

struct proc_resource {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	long rss_pages;
	unsigned long long utime_ticks;  /* raw ticks from /proc/pid/stat */
	unsigned long long stime_ticks;
};

struct cgroup_resource {
	bool valid;
	long long memory_bytes;       /* memory.current */
	long long memory_peak_bytes;  /* memory.peak (if available) */
	long long cpu_usage_usec;     /* cpu.stat usage_usec */
};

/* ========== /proc/<pid>/stat reader ========== */

static inline bool read_proc_resource(pid_t pid, struct proc_resource *res)
{
	char path[64];
	FILE *f;

	memset(res, 0, sizeof(*res));
	res->pid = pid;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return false;

	char buf[512];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return false;
	}
	fclose(f);

	/* Parse /proc/pid/stat:
	 * pid (comm) state ppid pgrp session tty_nr tpgid flags
	 * minflt cminflt majflt cmajflt utime stime cutime cstime
	 * priority nice num_threads itrealvalue starttime vsize rss ...
	 *
	 * Fields: 1=pid, 2=(comm), 14=utime, 15=stime, 24=rss
	 * comm can contain spaces/parens, so find closing ')' first.
	 */
	char *comm_start = strchr(buf, '(');
	char *comm_end = strrchr(buf, ')');
	if (!comm_start || !comm_end)
		return false;

	/* Extract comm */
	size_t comm_len = comm_end - comm_start - 1;
	if (comm_len >= TASK_COMM_LEN)
		comm_len = TASK_COMM_LEN - 1;
	memcpy(res->comm, comm_start + 1, comm_len);
	res->comm[comm_len] = '\0';

	/* Parse fields after ')': state(3) ppid(4) ... utime(14) stime(15) ... rss(24) */
	char *p = comm_end + 2;  /* skip ') ' */
	int field = 3;  /* starting at field 3 (state) */
	unsigned long long utime = 0, stime = 0;
	long rss = 0;

	while (*p && field <= 24) {
		/* skip whitespace */
		while (*p == ' ') p++;
		if (!*p) break;

		if (field == 14)
			utime = strtoull(p, NULL, 10);
		else if (field == 15)
			stime = strtoull(p, NULL, 10);
		else if (field == 24)
			rss = strtol(p, NULL, 10);

		/* advance to next field */
		while (*p && *p != ' ') p++;
		field++;
	}

	res->utime_ticks = utime;
	res->stime_ticks = stime;
	res->rss_pages = rss;

	return true;
}

/* ========== Cgroup v2 detection and reading ========== */

static inline bool detect_cgroup_path(pid_t pid, char *buf, size_t buf_len)
{
	char path[64];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
	f = fopen(path, "r");
	if (!f)
		return false;

	char line[512];
	bool found = false;
	while (fgets(line, sizeof(line), f)) {
		/* cgroup v2 line: "0::<path>\n" */
		if (line[0] == '0' && line[1] == ':' && line[2] == ':') {
			char *cg_path = line + 3;
			/* strip newline */
			size_t len = strlen(cg_path);
			if (len > 0 && cg_path[len - 1] == '\n')
				cg_path[len - 1] = '\0';

			/* Build full path: /sys/fs/cgroup + <cg_path> */
			snprintf(buf, buf_len, "/sys/fs/cgroup%s", cg_path);
			found = true;
			break;
		}
	}

	fclose(f);
	return found;
}

static inline bool read_cgroup_resource(const char *cgroup_path, struct cgroup_resource *res)
{
	char path[512];
	FILE *f;

	memset(res, 0, sizeof(*res));

	/* Read memory.current */
	snprintf(path, sizeof(path), "%s/memory.current", cgroup_path);
	f = fopen(path, "r");
	if (f) {
		char buf[64];
		if (fgets(buf, sizeof(buf), f))
			res->memory_bytes = strtoll(buf, NULL, 10);
		fclose(f);
		res->valid = true;
	}

	/* Read memory.peak (optional, may not exist on older kernels) */
	snprintf(path, sizeof(path), "%s/memory.peak", cgroup_path);
	f = fopen(path, "r");
	if (f) {
		char buf[64];
		if (fgets(buf, sizeof(buf), f))
			res->memory_peak_bytes = strtoll(buf, NULL, 10);
		fclose(f);
	}

	/* Read cpu.stat */
	snprintf(path, sizeof(path), "%s/cpu.stat", cgroup_path);
	f = fopen(path, "r");
	if (f) {
		char line[128];
		while (fgets(line, sizeof(line), f)) {
			if (strncmp(line, "usage_usec ", 11) == 0) {
				res->cpu_usage_usec = strtoll(line + 11, NULL, 10);
				break;
			}
		}
		fclose(f);
		res->valid = true;
	}

	return res->valid;
}

/* ========== Read ppid from /proc/<pid>/stat ========== */

static inline pid_t sampler_read_ppid(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	char buf[512];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);

	/* Find closing ')' then parse ppid (field 4) */
	char *p = strrchr(buf, ')');
	if (!p)
		return -1;
	p += 2;  /* skip ') ' */

	/* Skip field 3 (state) */
	while (*p == ' ') p++;
	while (*p && *p != ' ') p++;

	/* Field 4 = ppid */
	return (pid_t)strtol(p, NULL, 10);
}

/* ========== Process tree walker via /proc ========== */

#define MAX_SAMPLE_PIDS 4096

/*
 * Collect target_pid and all its descendants by scanning /proc.
 * Returns count of PIDs found.
 */
static inline int collect_process_tree(pid_t target_pid, pid_t *out, int max_out)
{
	if (target_pid <= 0)
		return 0;

	/* Start with target PID in the set */
	int count = 0;
	out[count++] = target_pid;

	/* Scan /proc for children: any PID whose ppid is in our set */
	DIR *proc_dir = opendir("/proc");
	if (!proc_dir)
		return count;

	struct dirent *entry;
	/* Multiple passes to find nested children (max depth ~10) */
	bool found_new = true;
	int pass = 0;
	while (found_new && pass < 10) {
		found_new = false;
		pass++;
		rewinddir(proc_dir);
		while ((entry = readdir(proc_dir)) != NULL) {
			if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
				continue;
			pid_t pid = (pid_t)strtol(entry->d_name, NULL, 10);
			if (pid <= 0)
				continue;

			/* Already in set? */
			bool already = false;
			for (int i = 0; i < count; i++) {
				if (out[i] == pid) { already = true; break; }
			}
			if (already)
				continue;

			pid_t ppid = sampler_read_ppid(pid);
			if (ppid <= 0)
				continue;

			/* Check if parent is in our set */
			for (int i = 0; i < count; i++) {
				if (out[i] == ppid) {
					if (count < max_out) {
						out[count++] = pid;
						found_new = true;
					}
					break;
				}
			}
		}
	}

	closedir(proc_dir);
	return count;
}

/* ========== Main sampling function ========== */

static inline void sample_resources(pid_t target_pid,
                                    long page_size_kb,
                                    bool detail,
                                    const char *cgroup_path)
{
	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) clk_tck = 100;

	/* Get timestamp */
	uint64_t timestamp_ns = 0;
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	/* Collect target PID's process tree */
	pid_t pids[MAX_SAMPLE_PIDS];
	int num_pids = collect_process_tree(target_pid, pids, MAX_SAMPLE_PIDS);

	/* Sample each PID */
	long total_rss_kb = 0;
	unsigned long long total_utime_ticks = 0, total_stime_ticks = 0;
	int num_sampled = 0;

	for (int i = 0; i < num_pids; i++) {
		struct proc_resource res;
		if (!read_proc_resource(pids[i], &res))
			continue;

		long rss_kb = res.rss_pages * page_size_kb;
		total_rss_kb += rss_kb;
		total_utime_ticks += res.utime_ticks;
		total_stime_ticks += res.stime_ticks;
		num_sampled++;

		if (detail) {
			printf("{\"timestamp\":%llu,\"event\":\"RESOURCE_DETAIL\","
			       "\"pid\":%d,\"comm\":\"%s\","
			       "\"rss_kb\":%ld,"
			       "\"cpu_user_ms\":%llu,"
			       "\"cpu_sys_ms\":%llu}\n",
			       (unsigned long long)timestamp_ns,
			       pids[i], res.comm,
			       rss_kb,
			       (unsigned long long)(res.utime_ticks * 1000 / clk_tck),
			       (unsigned long long)(res.stime_ticks * 1000 / clk_tck));
		}
	}

	/* Output aggregate RESOURCE_SAMPLE */
	printf("{\"timestamp\":%llu,\"event\":\"RESOURCE_SAMPLE\","
	       "\"target_pid\":%d,"
	       "\"total_rss_kb\":%ld,"
	       "\"total_cpu_user_ms\":%llu,"
	       "\"total_cpu_sys_ms\":%llu,"
	       "\"num_processes\":%d",
	       (unsigned long long)timestamp_ns,
	       target_pid,
	       total_rss_kb,
	       (unsigned long long)(total_utime_ticks * 1000 / clk_tck),
	       (unsigned long long)(total_stime_ticks * 1000 / clk_tck),
	       num_sampled);

	/* Append cgroup stats if available */
	struct cgroup_resource cg_res = {};
	if (cgroup_path && cgroup_path[0] && read_cgroup_resource(cgroup_path, &cg_res)) {
		printf(",\"cgroup_memory_bytes\":%lld", cg_res.memory_bytes);
		if (cg_res.memory_peak_bytes > 0)
			printf(",\"cgroup_memory_peak_bytes\":%lld", cg_res.memory_peak_bytes);
		if (cg_res.cpu_usage_usec > 0)
			printf(",\"cgroup_cpu_usage_usec\":%lld", cg_res.cpu_usage_usec);
	}

	printf("}\n");
	fflush(stdout);
}

#endif /* __PROCESS_NEW_RESOURCE_SAMPLER_H */
