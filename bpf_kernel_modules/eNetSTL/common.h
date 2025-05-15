#ifndef __ENETSTL_COMMON_H__
#define __ENETSTL_COMMON_H__
#include <linux/types.h>
#include <asm/rwonce.h>
#include <asm/fpu/api.h>

// This macro is required to include <immtrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#include <immintrin.h>

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

#endif 