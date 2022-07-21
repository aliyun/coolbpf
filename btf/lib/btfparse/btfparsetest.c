#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "btfparse.h"


int main()
{
    struct btf *btf = btf_load(NULL);
    assert(btf != NULL);

    char struct_name[] = "sock";
    char member_name[] = "sk_sndbuf";
    struct member_attribute *ma = btf_find_struct_member(btf, struct_name, member_name);
    assert(btf != NULL);
    assert(ma->offset != 0);
    assert(ma->size != 0);
    assert(ma->real_size != 0);

    printf("offset: %u, size: %u, realsize: %u\n", ma->offset, ma->size, ma->real_size);
    free(ma);
    return 0;
}