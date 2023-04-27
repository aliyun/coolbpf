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


Test(btfparse, btf_type_size)
{
    struct btf *btf = btf_load(NULL);
    cr_assert_gt(btf_type_size(btf, "struct sock"), 0);
}

Test(btfparse, btf_get_member_offset)
{
    struct btf *btf = btf_load(NULL);
    cr_assert_eq(btf_get_member_offset(btf, "struct sock", "__sk_common"), 0);
    cr_assert_gt(btf_get_member_offset(btf, "struct sock", "sk_sndbuf"), 0);
}