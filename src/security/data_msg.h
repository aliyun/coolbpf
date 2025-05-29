//
// Created by qianlu on 2024/6/16.
//

#ifndef SYSAK_DATA_MSG_H
#define SYSAK_DATA_MSG_H

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpf_common.h"

#define MSG_DATA_ARG_LEN 32736

struct data_event_id {
  __u64 pid;
  __u64 time;
} __attribute__((packed));

struct data_event_desc {
  __s32 error;
  __u32 pad;
  __u32 leftover;
  __u32 size;
  struct data_event_id id;
} __attribute__((packed));

struct msg_data {
  struct msg_common common;
  struct data_event_id id;
  /* To have a fast way to check buffer size we use 32736 (MSG_DATA_ARG_LEN)
   * as arg size, which is:
   *   0x8000 - offsetof(struct msg_kprobe_arg, arg)
   * so we can make verifier happy with:
   *   'size &= 0x7fff' check
   */
  char arg[MSG_DATA_ARG_LEN];
} __attribute__((packed));


#endif //SYSAK_DATA_MSG_H
