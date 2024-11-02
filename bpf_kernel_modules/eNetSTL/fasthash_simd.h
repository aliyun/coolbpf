#ifndef __ENETSTL__FASTHASH_SIMD_H__
#define __ENETSTL__FASTHASH_SIMD_H__

#if defined(__x86_64) || defined(__i386)
#include "fasthash_x86.h"
#else
#error "Unsupported architecture"
#endif

#endif /* __ENETSTL__FASTHASH_SIMD_H__ */
