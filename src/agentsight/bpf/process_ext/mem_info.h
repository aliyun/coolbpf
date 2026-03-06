/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_NEW_MEM_INFO_H
#define __PROCESS_NEW_MEM_INFO_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>

struct proc_mem_info {
	long rss_pages;
	long shared_pages;
	long text_pages;
	long data_pages;
	long vm_hwm_kb;  /* VmHWM from /proc/pid/status */
};

static inline bool read_proc_mem_info(pid_t pid, struct proc_mem_info *info)
{
	char path[64];
	FILE *f;

	memset(info, 0, sizeof(*info));

	snprintf(path, sizeof(path), "/proc/%d/statm", pid);
	f = fopen(path, "r");
	if (!f)
		return false;

	/* statm fields: size resident shared text lib data dt */
	long size_pages, lib_pages;
	if (fscanf(f, "%ld %ld %ld %ld %ld %ld",
		   &size_pages, &info->rss_pages, &info->shared_pages,
		   &info->text_pages, &lib_pages, &info->data_pages) < 4) {
		fclose(f);
		return false;
	}
	fclose(f);

	/* Read VmHWM from /proc/pid/status */
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (f) {
		char line[256];
		while (fgets(line, sizeof(line), f)) {
			if (strncmp(line, "VmHWM:", 6) == 0) {
				sscanf(line + 6, " %ld", &info->vm_hwm_kb);
				break;
			}
		}
		fclose(f);
	}

	return true;
}

#endif /* __PROCESS_NEW_MEM_INFO_H */
