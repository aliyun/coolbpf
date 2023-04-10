#include <coolbpf/coolbpf.h>
#include <coolbpf/btfparse.h>
#include <criterion/criterion.h>

Test(btfparse, btf_load)
{
    cr_assert_not_null(btf_load(NULL));
}

Test(btfparse, btf_find_struct_member)
{
    struct btf *btf = btf_load(NULL);
    char struct_name[] = "sock";
    char member_name[] = "sk_sndbuf";
    struct member_attribute *ma = btf_find_struct_member(btf, struct_name, member_name);
    cr_assert(ma->offset != 0);
    cr_assert(ma->size != 0);
    cr_assert(ma->real_size != 0);
}
