/**
 * @file coolbpf.c
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief 
 * @version 0.1
 * @date 2022-12-22
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifdef __VMLINUX_H__

#else

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <asm/unistd.h>

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
