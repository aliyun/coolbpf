//
// Created by qianlu on 2024/6/12.
//

#ifndef SYSAK_TYPE_H
#define SYSAK_TYPE_H

#ifdef __cplusplus
#include <linux/types.h>
#endif

#include "bpf_process_event_type.h"

#ifndef AF_INET
#define AF_INET	 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#define IPV4LEN 4
#define IPV6LEN 16

#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008
#define MAY_ACCESS		0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK		0x00000080

struct tuple_type {
  __u64 saddr[2];
  __u64 daddr[2];
  __u16 sport;
  __u16 dport;
  __u16 protocol;
  __u16 family;
};

/// network etc
enum sock_secure_ctrl_type {
  INVALID,
  PID,
  CONTAINER_ID,
  SOURCE_IP,
  SOURCE_PORT,
  DEST_IP,
  DEST_PORT,
  /* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
  NET_NS,
  MAX,
};

enum secure_funcs {

  // file
  SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION,
  SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_MMAP_FILE,
  SECURE_FUNC_TRACEPOINT_FUNC_SECURITY_PATH_TRUNCATE,
  SECURE_FUNC_TRACEPOINT_FUNC_SYS_WRITE,
  SECURE_FUNC_TRACEPOINT_FUNC_SYS_READ,
  
  // network
  SECURE_FUNC_TRACEPOINT_FUNC_TCP_CLOSE,
  SECURE_FUNC_TRACEPOINT_FUNC_TCP_CONNECT,
  SECURE_FUNC_TRACEPOINT_FUNC_TCP_SENDMSG,


  // process

  SECURE_FUNCS_MAX,
};

enum sock_secure_func {
  TRACEPOINT_FUNC_TCP_CLOSE,
  TRACEPOINT_FUNC_TCP_CONNECT,
  TRACEPOINT_FUNC_TCP_SENDMSG,
  TRACEPOINT_FUNC_MAX,
};

struct addr_port {
  __u32 addr;
  __u16 port;
};

struct ns_key_t {
  __u32 net_ns_inum;
};

struct tcp_data_t {
  struct msg_execve_key key;
  struct msg_execve_key pkey;
  enum sock_secure_func func;
  __u16 protocol;
  __u16 state;
  __u16 family;
  __u32 pid;
  __u32 saddr; // Source address
  __u32 daddr; // Destination address
  __u16 sport; // Source port
  __u16 dport; // Destination port
  __u32 net_ns; // Network namespace
  __u64 timestamp;
  __u64 bytes;
};

#define SYSAK_SECURE_MAX_CIDR_LIMIT 20
#define SYSAK_SECURE_MAX_CIDR_LIMIT_HALF 10
#define SYSAK_SECURE_MAX_PORT_LIMIT 20
#define SYSAK_SECURE_MAX_PORT_LIMIT_HALF 10

#define SYSAK_SECURE_MAX_PATH_LIMIT 2
#define SYSAK_SECURE_MAX_PATH_LENGTH_LIMIT 256

#define INT_MAPS_OUTER_MAX_ENTRIES 20
#define INT_MAPS_INNER_MAX_ENTRIES 8
#define STRING_MAPS_OUTER_MAX_ENTRIES 20
#define STRING_MAPS_INNER_MAX_ENTRIES 8

struct cidr_entry {
  int inited;
  int  black; // black list or not
  __u32 net;    // Network part of CIDR
  __u32 mask;   // Network mask
};

struct port_entry {
  int inited;
  int black; // is black list or not
  __u16 port; // is src port or not
};



/// process etc

// file
enum file_secure_func
{
  TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION,
  TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION_WRITE,
  TRACEPOINT_FUNC_SECURITY_FILE_PERMISSION_READ,
  TRACEPOINT_FUNC_SECURITY_MMAP_FILE,
  TRACEPOINT_FUNC_SECURITY_PATH_TRUNCATE,
  TRACEPOINT_FUNC_SYS_WRITE,
  TRACEPOINT_FUNC_SYS_READ,
};
struct file_data_t
{
  struct msg_execve_key key;
  struct msg_execve_key pkey;
  enum file_secure_func func;
  __u64 timestamp;
  __u32 size;
  char path[2000];
};
struct path_entry
{
  // todo need updates
  int inited;
  int length;
  char path[2000];
};


#define STRING_MAPS_KEY_INC_SIZE 24
#define STRING_MAPS_SIZE_0	 (1 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_1	 (2 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_2	 (3 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_3	 (4 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_4	 (5 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_5	 (6 * STRING_MAPS_KEY_INC_SIZE + 1)
#define STRING_MAPS_SIZE_6	 (256 + 2)
#ifdef __LARGE_MAP_KEYS
#define STRING_MAPS_SIZE_7  (512 + 2)
#define STRING_MAPS_SIZE_8  (1024 + 2)
#define STRING_MAPS_SIZE_9  (2048 + 2)
#define STRING_MAPS_SIZE_10 (4096 + 2)
#else
#define STRING_MAPS_SIZE_7 (512)
#endif
#define STRING_MAPS_HEAP_SIZE 16384
#define STRING_MAPS_HEAP_MASK (8192 - 1)
#define STRING_MAPS_COPY_MASK 4095

#define STRING_PREFIX_MAX_LENGTH 256

struct string_prefix_lpm_trie {
	__u32 prefixlen;
	__u8 data[STRING_PREFIX_MAX_LENGTH];
};

#define STRING_POSTFIX_MAX_LENGTH 128
#define STRING_POSTFIX_MAX_MASK	  (STRING_POSTFIX_MAX_LENGTH - 1)
#ifdef __LARGE_BPF_PROG
#define STRING_POSTFIX_MAX_MATCH_LENGTH STRING_POSTFIX_MAX_LENGTH
#else
#define STRING_POSTFIX_MAX_MATCH_LENGTH 95
#endif

struct string_postfix_lpm_trie {
	__u32 prefixlen;
	__u8 data[STRING_POSTFIX_MAX_LENGTH];
};


#define ADDR_LPM_MAPS_OUTER_MAX_ENTRIES 20
#define ADDR_LPM_MAPS_INNER_MAX_ENTRIES 8


struct addr4_lpm_trie {
	__u32 prefix;
	__u32 addr;
};

struct addr6_lpm_trie {
	__u32 prefix;
	__u32 addr[4];
};

enum tailcall_func {
  TAILCALL_FILTER_PROG,
  TAILCALL_SEND,
};


enum filter_type {
    FILTER_TYPE_UNKNOWN,
    FILTER_TYPE_SADDR,
    FILTER_TYPE_DADDR,
    FILTER_TYPE_NOT_SADDR,
    FILTER_TYPE_NOT_DADDR,
    FILTER_TYPE_SPORT,
    FILTER_TYPE_DPORT,
    FILTER_TYPE_NOT_SPORT,
    FILTER_TYPE_NOT_DPORT,
    FILTER_TYPE_FILE_PREFIX,
};

enum op_type {
  OP_TYPE_IN,
  OP_TYPE_NOT_IN,
};

#define MAX_FILTER_FOR_PER_CALLNAME 8

struct selector_filter {
	// __u32 index;
	// __u32 op;
	__u32 vallen;
	enum filter_type filter_type;
  enum op_type op_type;
    __u32 map_idx[2];
	// __u8 value;
} __attribute__((packed));

struct selector_filters {
  int filter_count;
	struct selector_filter filters[MAX_FILTER_FOR_PER_CALLNAME];
} __attribute__((packed));


#endif //SYSAK_TYPE_H
