#pragma once
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"
#include "type.h"


// #define POLICY_FILTER_MAX_FILTERS 128
// #define FILTER_SIZE 4096


// struct filter_map_value {
// 	unsigned char buf[FILTER_SIZE];
// };

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SECURE_FUNCS_MAX);
	__type(key, int);
	__type(value, struct selector_filters);
} filter_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, POLICY_FILTER_MAX_FILTERS);
// 	__uint(key_size, sizeof(u32)); /* call name id */
// 	__array(
// 		values, struct {
// 			__uint(type, BPF_MAP_TYPE_ARRAY);
// 			__uint(max_entries, 1);
// 			__type(key, __u64);
// 			__type(value, __u8);
// 		});
// } filter_maps SEC(".maps");