#ifndef TCPCONNECT_H
#define TCPCONNECT_H


struct event {
    long long ns;
    int cpu;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
};

#endif 
