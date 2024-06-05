
#include "coolbpf.h"
#include "first.skel.h"
#include "second.skel.h"
#include <unistd.h>

int load_first()
{
    struct coolbpf_object *first = coolbpf_object_new(first);
    coolbpf_object_pin_maps(first);
    sleep(3);
    return coolbpf_object_find_map(first, "reusemap");
}

int load_second()
{
    struct coolbpf_object *second = coolbpf_object_new(second);
    return coolbpf_object_find_map(second, "reusemap");
}

int main()
{
    bump_memlock_rlimit();
    coolbpf_set_loglevel(LOG_DEBUG);

    int first_map = load_first();
    int second_map = load_second();
    int key = 0;
    uint64_t val1 = 0, val2 = 0;
    bpf_map_lookup_elem(first_map, &key, &val1);
    bpf_map_lookup_elem(second_map, &key, &val2);
    printf("first map value: %x, second map value: %x\n", val1, val2);
    return 0;
}