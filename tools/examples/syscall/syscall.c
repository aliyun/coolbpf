



#include <coolbpf/coolbpf.h>
#include "syscall.skel.h"


int main() {
    bump_memlock_rlimit();
    coolbpf_set_loglevel(LOG_DEBUG);
    struct coolbpf_object *cb = coolbpf_object_new(syscall);
    return 0;
}