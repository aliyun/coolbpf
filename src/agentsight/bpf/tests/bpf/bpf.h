/* Stub bpf/bpf.h for unit tests — provides minimal BPF map API stubs */
#ifndef __LIBBPF_BPF_H
#define __LIBBPF_BPF_H

#include <stdint.h>

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#ifndef LIBBPF_API
#define LIBBPF_API
#endif

static inline int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	(void)fd; (void)key; (void)next_key;
	return -1;
}
static inline int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	(void)fd; (void)key; (void)value;
	return -1;
}
static inline int bpf_map_delete_elem(int fd, const void *key)
{
	(void)fd; (void)key;
	return -1;
}
static inline int bpf_map_update_elem(int fd, const void *key,
				      const void *value, uint64_t flags)
{
	(void)fd; (void)key; (void)value; (void)flags;
	return -1;
}

#endif /* __LIBBPF_BPF_H */
