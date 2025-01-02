// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../coolbpf.h"
#include "type.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[8]); // Need to specify as byte array as wouldn't take struct as key type
			__type(value, __u8);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} addr4lpm_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[20]); // Need to specify as byte array as wouldn't take struct as key type
			__type(value, __u8);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} addr6lpm_maps SEC(".maps");


// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES);
// 	__uint(key_size, sizeof(__u32));
// 	__array(
// 		values, struct {
// 			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
// 			__uint(max_entries, 16);
// 			__type(key, __u8[8]); // Need to specify as byte array as wouldn't take struct as key type
// 			__type(value, __u8);
// 			__uint(map_flags, BPF_F_NO_PREALLOC);
// 		});
// } daddr4lpm_maps SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES);
// 	__uint(key_size, sizeof(__u32));
// 	__array(
// 		values, struct {
// 			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
// 			__uint(max_entries, 16);
// 			__type(key, __u8[20]); // Need to specify as byte array as wouldn't take struct as key type
// 			__type(value, __u8);
// 			__uint(map_flags, BPF_F_NO_PREALLOC);
// 		});
// } daddr6lpm_maps SEC(".maps");
