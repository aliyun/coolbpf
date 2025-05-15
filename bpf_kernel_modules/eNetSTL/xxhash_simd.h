/**
 * @author Hanlin Yang (hlyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_XXHASH_SIMD_H__
#define __ENETSTL_XXHASH_SIMD_H__

#if defined(__x86_64) || defined(__i386)
#include "xxhash_x86.h"
#else
#error "Unsupported architecture"
#endif

#endif /* __ENETSTL_XXHASH_SIMD_H__ */
