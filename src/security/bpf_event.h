//
// Created by qianlu on 2024/6/16.
//

#ifndef SYSAK_BPF_EVENT_H
#define SYSAK_BPF_EVENT_H

#include "../coolbpf.h"
#include <bpf/bpf_helpers.h>

struct event {
  int event;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, int);
  __type(value, struct event);
} tcpmon_map SEC(".maps");

#endif //SYSAK_BPF_EVENT_H
