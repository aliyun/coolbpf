#ifndef __EXAMPLE_H
#define __EXAMPLE_H

#define TASK_COMM_LEN 16

struct example
{
    int pid;
    char comm[TASK_COMM_LEN]; // command (task_comm_len)
    __u16 sport;     // source port
    __u16 dport;     // destination port
    __u32 saddr;     // source address
    __u32 daddr;     // destination address
};

#endif 
