#include <vmlinux.h>
#include "coolbpf.h"

struct
{
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, u64);
        __uint(max_entries, 1);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} reusemap SEC(".maps");
