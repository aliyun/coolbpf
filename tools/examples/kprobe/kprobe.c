
#include <unistd.h>
#include "coolbpf.h"
#include "kprobe.skel.h"

int main()
{
    bump_memlock_rlimit();
    coolbpf_set_loglevel(LOG_INFO);
    struct coolbpf_object *cb = coolbpf_object_new(kprobe);
    while (1)
        sleep(3);
    return 0;
}