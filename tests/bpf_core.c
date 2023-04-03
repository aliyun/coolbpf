#include <coolbpf/coolbpf.h>
#include <criterion/criterion.h>
#include <coolbpf/log.h>
#include "bpf_core.skel.h"

Test(bpf, bpf_core)
{
    bump_memlock_rlimit();
    struct coolbpf_object  *cb = coolbpf_object_new(bpf_core);
    cr_assert_not_null(cb);
}