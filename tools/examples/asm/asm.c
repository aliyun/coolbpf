
#include <unistd.h>
#include <coolbpf/coolbpf.h>
#include "asm.skel.h"

int main()
{
    bump_memlock_rlimit();
    coolbpf_set_loglevel(LOG_DEBUG);
    struct coolbpf_object *cb = coolbpf_object_new(asm);
    while (1)
        sleep(3);
    return 0;
}