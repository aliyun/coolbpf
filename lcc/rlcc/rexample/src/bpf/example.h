#ifndef __EXAMPLE_H
#define __EXAMPLE_H

#define TASK_COMM_LEN 16

#ifndef u8
typedef unsigned char __u8;
#endif

#ifndef u16
typedef unsigned short int __u16;
#endif

#ifndef u32
typedef unsigned int __u32;
#endif

#ifndef u64
typedef long long unsigned int __u64;
#endif

struct example
{
    int pid;
    __u8 comm[TASK_COMM_LEN]; // command (task_comm_len)
    __u16 sport;     // source port
    __u16 dport;     // destination port
    __u32 saddr;     // source address
    __u32 daddr;     // destination address
};

#endif
