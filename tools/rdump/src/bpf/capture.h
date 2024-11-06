#ifndef __TC_CAPTURE_H
#define __TC_CAPTURE_H

#define INGRESS_PACKET 0
#define EGRESS_PACKET 1

// tcp recv输出到User space
struct recv_timestamp_event_t {
    unsigned long tc;
    unsigned long net_recv;
    unsigned long ip_recv;
    unsigned long tcp_recv;
};

struct timestamp_key {
    unsigned int seq;
    unsigned int ack;
};

struct process_meta_t {
    unsigned int ppid;
    unsigned int pid;
    unsigned int pidns_id;
    unsigned int mntns_id;
    unsigned int netns_id;
    char cgroup_name[128];
};

// TC hook 传输到User space
struct packet_event_t {
    unsigned char packet_type;
    unsigned int  ifindex;
    unsigned long payload_len;
    unsigned long tc_timestamp;

    struct process_meta_t process;
};

struct l2_t {
    unsigned short h_protocol;
};

struct l3_t {
    unsigned char protocol;
    unsigned long saddr[2];
    unsigned long daddr[2];
};

struct l4_t {
    unsigned short sport;
    unsigned short dport;
    unsigned int   seq;
    unsigned int   ack;
};

struct packet_meta_t {
    unsigned int ifindex;

    struct l2_t l2;
    struct l3_t l3;
    struct l4_t l4;

    unsigned int offset;
};
#endif