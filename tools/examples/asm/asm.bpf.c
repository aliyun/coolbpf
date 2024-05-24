

#include <vmlinux.h>
#include "coolbpf.h"

#define __clobber_all "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"

SEC("kprobe/tcp_sendmsg")
__attribute__((naked)) void kprobe_tcp_sendmsg(void)
{
    
    asm volatile(" \
    r6 = *(u64 *)(r1 +96); \
    call %[pid]; \
    r7 = r0; \
    r7 >>= 32; \
    r8 = r10; \
    r8 += -16; \
    r1 = r8; \
    r2 = 16; \
    call %[comm]; \
    r1 = 175334772; \
    *(u32 *)(r10 -24) = r1; \
    r1 = %[str1] ll; \
    *(u64 *)(r10 -32) = r1; \
    r1 = %[str2] ll; \
    *(u64 *)(r10 -40) = r1; \
    r1 = 0; \
    *(u8 *)(r10 -20) = r1; \
    r1 = r10; \
    r1 += -40; \
    r2 = %[fmt_size]; \
    r3 = r7; \
    r4 = r8; \
    r5 = r6; \
    call %[print]; \
    r0 = 0; \
    exit; \
"
    :
    : [pid] "i"(bpf_get_current_pid_tgid),
      [comm] "i"(bpf_get_current_comm),
      [print] "i"(bpf_trace_printk),
      [fmt_size] "i"(sizeof("%d/%s send %d bytes\n")),
      [str1] "i"(0x796220642520646e),
      [str2] "i"(0x65732073252f6425)
    : __clobber_all);
}