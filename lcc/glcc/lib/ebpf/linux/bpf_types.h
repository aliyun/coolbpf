/* internal file - do not include directly */

// BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter)

// BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_CLS, tc_cls_act)
// BPF_PROG_TYPE(BPF_PROG_TYPE_SCHED_ACT, tc_cls_act)

// #ifdef CONFIG_BPF_EVENTS
BPF_PROG_TYPE(BPF_PROG_TYPE_KPROBE, kprobe)
BPF_PROG_TYPE(BPF_PROG_TYPE_TRACEPOINT, tracepoint)
// BPF_PROG_TYPE(BPF_PROG_TYPE_PERF_EVENT, perf_event)
// #endif

BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY, array_map_ops)
// BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_ARRAY, percpu_array_map_ops)
// BPF_MAP_TYPE(BPF_MAP_TYPE_PROG_ARRAY, prog_array_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PERF_EVENT_ARRAY, perf_event_array_map_ops)
// #ifdef CONFIG_SOCK_CGROUP_DATA
// BPF_MAP_TYPE(BPF_MAP_TYPE_CGROUP_ARRAY, cgroup_array_map_ops)
// #endif
BPF_MAP_TYPE(BPF_MAP_TYPE_HASH, htab_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_PERCPU_HASH, htab_percpu_map_ops)
BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_HASH, htab_lru_map_ops)
// BPF_MAP_TYPE(BPF_MAP_TYPE_LRU_PERCPU_HASH, htab_lru_percpu_map_ops)
// BPF_MAP_TYPE(BPF_MAP_TYPE_LPM_TRIE, trie_map_ops)
// #ifdef CONFIG_PERF_EVENTS
// BPF_MAP_TYPE(BPF_MAP_TYPE_STACK_TRACE, stack_map_ops)
// #endif
// BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY_OF_MAPS, array_of_maps_map_ops)
// BPF_MAP_TYPE(BPF_MAP_TYPE_HASH_OF_MAPS, htab_of_maps_map_ops)
// #ifdef CONFIG_NET
// BPF_MAP_TYPE(BPF_MAP_TYPE_DEVMAP, dev_map_ops)
// #endif
