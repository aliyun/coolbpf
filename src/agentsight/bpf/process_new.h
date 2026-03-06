/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_NEW_H
#define __PROCESS_NEW_H

#include "process.h"

/* Aggregation key detail length */
#define DETAIL_LEN 64
#define MAX_TRACKED_CGROUPS 16384

/* Aggregation key: group by (pid, event_type, detail) */
struct agg_key {
	__u32 pid;
	__u32 event_type;
	char detail[DETAIL_LEN];
};

/* Aggregation value: count + bytes + timestamps + extra info */
struct agg_value {
	__u64 count;
	__u64 total_bytes;         /* only used by write/mmap, 0 otherwise */
	__u64 first_ts;
	__u64 last_ts;
	char comm[TASK_COMM_LEN];
	char extra[MAX_FILENAME_LEN];
};

/* Per-process memory info collected in BPF at exit time.
 * Stored in exit_mem BPF hash map, read by userspace in handle_event. */
struct exit_mem_info {
	__u64 hiwater_rss;  /* peak RSS in pages (from signal->maxrss) */
};

/* New event type IDs (existing 0-2 unchanged in process.h) */
enum event_type_new {
	/* filesystem mutations */
	EVENT_TYPE_FILE_DELETE = 10,
	EVENT_TYPE_FILE_RENAME = 11,
	EVENT_TYPE_DIR_CREATE = 12,
	EVENT_TYPE_FILE_TRUNCATE = 13,
	EVENT_TYPE_CHDIR = 14,
	EVENT_TYPE_WRITE = 15,
	/* network */
	EVENT_TYPE_NET_BIND = 20,
	EVENT_TYPE_NET_LISTEN = 21,
	EVENT_TYPE_NET_CONNECT = 22,
	/* process coordination */
	EVENT_TYPE_PGRP_CHANGE = 30,
	EVENT_TYPE_SESSION_CREATE = 31,
	EVENT_TYPE_SIGNAL_SEND = 32,
	EVENT_TYPE_PROC_FORK = 33,
	/* memory */
	EVENT_TYPE_MMAP_SHARED = 40,
	EVENT_TYPE_COW_FAULT = 41,
};

#endif /* __PROCESS_NEW_H */
