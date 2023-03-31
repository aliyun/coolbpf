
#include <coolbpf/coolbpf.h>
#include <criterion/criterion.h>
#include <coolbpf/log.h>



Test(api, version)
{
    cr_assert_eq(coolbpf_major_version(), COOLBPF_MAJOR_VERSION);
    cr_assert_eq(coolbpf_minor_version(), COOLBPF_MINOR_VERSION);
    cr_assert_str_not_empty(coolbpf_version_string());
}

Test(api, log_setlevel)
{
    coolbpf_set_loglevel(LOG_DEBUG);
}