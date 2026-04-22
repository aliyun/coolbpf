#ifndef INT_MAPS_H__
#define INT_MAPS_H__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"
#include "type.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, INT_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, INT_MAPS_INNER_MAX_ENTRIES);
			__type(key, __u32);
			__type(value, __u8);
		});
} port_maps SEC(".maps");


// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, INT_MAPS_OUTER_MAX_ENTRIES);
// 	__uint(key_size, sizeof(__u32));
// 	__array(
// 		values, struct {
// 			__uint(type, BPF_MAP_TYPE_HASH);
// 			__uint(max_entries, 1);
// 			__type(key, __u32);
// 			__type(value, __u8);
// 		});
// } dport_maps SEC(".maps");

#endif // INT_MAPS_H__
