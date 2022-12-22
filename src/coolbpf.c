

#ifdef __VMLINUX_H__

#else

#include <stdint.h>
#include "coolbpf.h"
uint32_t coolbpf_major_version(void)
{
    return COOLBPF_MAJOR_VERSION;
}

uint32_t coolbpf_minor_version(void)
{
    return COOLBPF_MINOR_VERSION;
}

const char *coolbpf_version_string(void)
{
#define __S(X) #X
#define _S(X) __S(X)
    return "v" _S(COOLBPF_MAJOR_VERSION) "." _S(COOLBPF_MINOR_VERSION);
#undef _S
#undef __S
}

#endif
