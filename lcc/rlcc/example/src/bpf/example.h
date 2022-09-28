#ifndef __EXAMPLE_H
#define __EXAMPLE_H

#define TASK_COMM_LEN 16

#ifndef u8
typedef unsigned char u8;
#endif

#ifndef u16
typedef unsigned short int u16;
#endif

#ifndef u32
typedef unsigned int u32;
#endif

#ifndef u64
typedef long long unsigned int u64;
#endif

struct example
{
    int pid;
    u8 comm[TASK_COMM_LEN]; // command (task_comm_len)
    u16 sport;     // source port
    u16 dport;     // destination port
    u32 saddr;     // source address
    u32 daddr;     // destination address
};

#endif 
