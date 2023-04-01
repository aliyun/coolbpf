#include <coolbpf/coolbpf.h>
#include <criterion/criterion.h>
#include <coolbpf/log.h>
#include "test.skel.h"
#include "test_map.skel.h"

Test(bpf, object_new)
{
    bump_memlock_rlimit();
    struct coolbpf_object  *cb = coolbpf_object_new(test);
    cr_assert_not_null(cb);
}

Test(bpf, find_map)
{
    bump_memlock_rlimit();
    struct coolbpf_object  *cb = coolbpf_object_new(test_map);
    cr_assert_gt(coolbpf_object_find_map(cb, "sock_map"), 0);
}