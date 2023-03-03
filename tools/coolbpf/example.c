


#include <coolbpf.h>
#include "example.h"
#include "example.skel.h"


int main() {
    bump_memlock_rlimit();
    struct coolbpf_object *cb = coolbpf_object_new(example);
    if (!cb) {
        printf("Failed to create coolbpf object\n");
        return 0;
    }
    printf("Sucessfully to create coolbpf object\n");
    return 0;
}

