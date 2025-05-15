/**
 * @author Lunqi Zhao (lunqi.zhao@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_CMP_ALG_H__
#define __ENETSTL_CMP_ALG_H__

#include "common.h"
#include <asm-generic/int-ll64.h>
#include <linux/bitops.h>

#define _mm256_loadu_si256_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm256_loadu_si256((__m256i_u *)(ptr)) : \
				      (*(__m256i *)(ptr))

#define _mm_loadu_si128_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm_loadu_si128((__m128i_u *)(ptr)) : \
				      *(__m128i *)(ptr)

static inline u32 __find_mask_u16(const void *arr, size_t arr__sz, u16 val)
{
	u32 mask;
	__m256i arr_vec, val_vec, cmp;
	if (arr__sz != 32)
		return 0;
	kernel_fpu_begin();
	arr_vec = _mm256_loadu_si256_optional((const __m256i_u *)arr),
		val_vec = _mm256_set1_epi16(val);
	cmp = _mm256_cmpeq_epi16(arr_vec, val_vec);
	mask = _mm256_movemask_epi8(cmp);
	kernel_fpu_end();
	return mask;
}

static inline u32 __find_u16(const void *arr, size_t arr__sz, u16 val)
{
	u32 mask = __find_mask_u16(arr, arr__sz, val);
	return __tzcnt_u32(mask) >> 1;
}

/* return 0 if equals, compare multiple 16keys*/
static inline int __cmp_eq(const void *key1, size_t key1_sz,
			       const void *key2, size_t key2_sz)
{
	if (key1_sz != key2_sz)
		return -22;
	
	size_t left_bytes = key1_sz;
	char * __key1 = (char*)key1, *__key2 =  (char*)key2; 

	kernel_fpu_begin();
	while (left_bytes >= 16) {
		const __m128i k1 = _mm_loadu_si128((const __m128i *)__key1);
		const __m128i k2 = _mm_loadu_si128((const __m128i *)__key2);
		const __m128i x = _mm_xor_si128(k1, k2);
		if (!_mm_test_all_zeros(x, x))
			return 1;
		__key1 += 16;
		__key2 += 16;
		left_bytes -= 16;
	}
	kernel_fpu_end();
	if (left_bytes == 0)
		return 0;
	else
		return !!memcmp(key1, key2, left_bytes);
}

#endif