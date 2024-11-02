/**
 * @author Bin Yang (binyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_POST_HASH_ALG_H__
#define __ENETSTL_POST_HASH_ALG_H__

#include "common.h"

#include <linux/xxhash.h>

#include "fasthash.h"
#include "fasthash_simd.h"
#include "xxhash_simd.h"

static const uint32_t _HASH_ALG_POST_SEEDS_DATA[] = {
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3,
	0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7,
	0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f,
	0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861,
	0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859,
	0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853,
	0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1,
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1,
};

static __always_inline void fasthash32_cnt32(const void *input,
					     const size_t len, uint32_t *table,
					     const size_t table_size,
					     const uint32_t column_shift)
{
	uint32_t _column_shift, column_count;
	uint32_t hash_count, *hashes, hash;
	__m128i hashes_vec;
	uint32_t i = 0, target_index;

	_column_shift = column_shift & 0x1f;
	column_count = 1 << _column_shift;
	hash_count = table_size >> _column_shift >> 2;

	kernel_fpu_begin();
	for (; i + 4 <= hash_count; i += 4) {
		hashes_vec = __fasthash32_4hashes(
			input, len,
			_mm_loadu_si128((
				__m128i_u *)((uint32_t *)
						     _HASH_ALG_POST_SEEDS_DATA +
					     i)));
		hashes = (uint32_t *)&hashes_vec;
		for (int j = 0; j < 4; j++) {
			target_index = hashes[j] & (column_count - 1);
			*(table + (i + j) * column_count + target_index) += 1;
		}
	}
	kernel_fpu_end();

	for (; i < hash_count; i++) {
		hash = fasthash32(input, len,
				  *((uint32_t *)_HASH_ALG_POST_SEEDS_DATA + i));
		target_index = hash & (column_count - 1);
		*(table + i * column_count + target_index) += 1;
	}
}

#define fasthash32_pkt(input, seed) fasthash32(input, 13, seed)

static __always_inline void fasthash32_pkt_cnt32(const void *input,
						 uint32_t *table,
						 const size_t table_size,
						 const uint32_t column_shift)
{
	uint32_t _column_shift, column_count;
	uint32_t hash_count, *hashes, hash;
	__m128i hashes_vec;
	uint32_t i = 0, target_index;

	_column_shift = column_shift & 0x1f;
	column_count = 1 << _column_shift;
	hash_count = table_size >> _column_shift >> 2;

	kernel_fpu_begin();
	for (; i + 4 <= hash_count; i += 4) {
		hashes_vec = __fasthash32_pkt_4hashes(
			input,
			_mm_loadu_si128((
				__m128i_u *)((uint32_t *)
						     _HASH_ALG_POST_SEEDS_DATA +
					     i)));
		hashes = (uint32_t *)&hashes_vec;
		for (int j = 0; j < 4; j++) {
			target_index = hashes[j] & (column_count - 1);
			*(table + (i + j) * column_count + target_index) += 1;
		}
	}
	kernel_fpu_end();

	for (; i < hash_count; i++) {
		hash = fasthash32_pkt(
			input, *((uint32_t *)_HASH_ALG_POST_SEEDS_DATA + i));
		target_index = hash & (column_count - 1);
		*(table + i * column_count + target_index) += 1;
	}
}

static __always_inline void xxh32_cnt32(const void *input, const size_t len,
					uint32_t *table,
					const size_t table_size,
					const uint32_t column_shift)
{
	uint32_t _column_shift, column_count;
	uint32_t hash_count, *hashes, hash;
	__m256i hashes_vec;
	uint32_t i = 0, target_index;

	_column_shift = column_shift & 0x1f;
	column_count = 1 << _column_shift;
	hash_count = table_size >> _column_shift >> 2;

	kernel_fpu_begin();
	for (; i + 8 <= hash_count; i += 8) {
		hashes_vec = __xxh32_8hashes(
			input, len,
			_mm256_loadu_si256((
				__m256i_u *)((uint32_t *)
						     _HASH_ALG_POST_SEEDS_DATA +
					     i)));
		hashes = (uint32_t *)&hashes_vec;
		for (int j = 0; j < 8; j++) {
			target_index = hashes[j] & (column_count - 1);
			*(table + (i + j) * column_count + target_index) += 1;
		}
	}
	kernel_fpu_end();

	for (; i < hash_count; i++) {
		hash = xxh32(input, len,
			     *((uint32_t *)_HASH_ALG_POST_SEEDS_DATA + i));
		target_index = hash & (column_count - 1);
		*(table + i * column_count + target_index) += 1;
	}
}

#define xxh32_pkt(input, seed) xxh32(input, 13, seed)

static __always_inline void xxh32_pkt_cnt32(const void *input, uint32_t *table,
					    const size_t table_size,
					    const uint32_t column_shift)
{
	uint32_t _column_shift, column_count;
	uint32_t hash_count, *hashes, hash;
	__m256i hashes_vec;
	uint32_t i = 0, target_index;

	_column_shift = column_shift & 0x1f;
	column_count = 1 << _column_shift;
	hash_count = table_size >> _column_shift >> 2;

    kernel_fpu_begin();
	for (; i + 8 <= hash_count; i += 8) {
		hashes_vec = __xxh32_pkt_8hashes(
			input,
			_mm256_loadu_si256((
				__m256i_u *)((uint32_t *)
						     _HASH_ALG_POST_SEEDS_DATA +
					     i)));
		hashes = (uint32_t *)&hashes_vec;
		for (int j = 0; j < 8; j++) {
			target_index = hashes[j] & (column_count - 1);
			*(table + (i + j) * column_count + target_index) += 1;
		}
	}
	kernel_fpu_end();

	for (; i < hash_count; i++) {
		hash = xxh32_pkt(input,
				 *((uint32_t *)_HASH_ALG_POST_SEEDS_DATA + i));
		target_index = hash & (column_count - 1);
		*(table + i * column_count + target_index) += 1;
	}
}

#endif /* __ENETSTL_POST_HASH_ALG_H__ */