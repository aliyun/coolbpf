



#include "vmlinux.h"
#include <coolbpf/coolbpf.h>


SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, u64 sk) {
    // doesn't matter if parameter is 'struct task_struct *' type, we just check if compilation is ok.
    bpf_core_task_struct_thread_info_exist(sk);
    return 0;
}

