/**
 * @author Hanlin Yang (hlyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_XXHASH_X86_H__
#define __ENETSTL_XXHASH_X86_H__

#include "common.h"

static const uint32_t _XXH_X86_PRIME32_1 = 2654435761U;
static const uint32_t _XXH_X86_PRIME32_2 = 2246822519U;
static const uint32_t _XXH_X86_PRIME32_3 = 3266489917U;
static const uint32_t _XXH_X86_PRIME32_4 = 668265263U;
static const uint32_t _XXH_X86_PRIME32_5 = 374761393U;

#define __xxh32_rotl32_256b(x, r)                    \
	_mm256_or_si256(_mm256_slli_epi32((x), (r)), \
			_mm256_srli_epi32((x), 32 - (r)))

static __always_inline __m256i __xxh32_round_256b(__m256i seeds_vec,
						  const uint32_t input)
{
	seeds_vec = _mm256_add_epi32(
		seeds_vec, _mm256_set1_epi32(input * _XXH_X86_PRIME32_2));
	seeds_vec = __xxh32_rotl32_256b(seeds_vec, 13);
	seeds_vec = _mm256_mullo_epi32(seeds_vec,
				       _mm256_set1_epi32(_XXH_X86_PRIME32_1));
	return seeds_vec;
}

static __always_inline __m256i __xxh32_8hashes(const void *input,
					       const size_t len,
					       __m256i seeds_vec)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *b_end = p + len;
	__m256i h32_vec;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		__m256i v1_vec = _mm256_add_epi32(
			seeds_vec, _mm256_set1_epi32(_XXH_X86_PRIME32_1 +
						     _XXH_X86_PRIME32_2));
		__m256i v2_vec = _mm256_add_epi32(
			seeds_vec, _mm256_set1_epi32(_XXH_X86_PRIME32_2));
		__m256i v3_vec = seeds_vec;
		__m256i v4_vec = _mm256_sub_epi32(
			seeds_vec, _mm256_set1_epi32(_XXH_X86_PRIME32_1));

		do {
			v1_vec = __xxh32_round_256b(v1_vec, *(uint32_t *)p);
			p += 4;
			v2_vec = __xxh32_round_256b(v2_vec, *(uint32_t *)p);
			p += 4;
			v3_vec = __xxh32_round_256b(v3_vec, *(uint32_t *)p);
			p += 4;
			v4_vec = __xxh32_round_256b(v4_vec, *(uint32_t *)p);
			p += 4;
		} while (p <= limit);

		h32_vec = _mm256_add_epi32(
			__xxh32_rotl32_256b(v1_vec, 1),
			_mm256_add_epi32(
				__xxh32_rotl32_256b(v2_vec, 7),
				_mm256_add_epi32(
					__xxh32_rotl32_256b(v3_vec, 12),
					__xxh32_rotl32_256b(v4_vec, 18))));
	} else {
		h32_vec = _mm256_add_epi32(
			seeds_vec, _mm256_set1_epi32(_XXH_X86_PRIME32_5));
	}

	h32_vec = _mm256_add_epi32(h32_vec, _mm256_set1_epi32(len));

	while (p + 4 <= b_end) {
		h32_vec = _mm256_add_epi32(
			h32_vec,
			_mm256_set1_epi32(*(uint32_t *)p * _XXH_X86_PRIME32_3));
		h32_vec = _mm256_mullo_epi32(
			__xxh32_rotl32_256b(h32_vec, 17),
			_mm256_set1_epi32(_XXH_X86_PRIME32_4));
		p += 4;
	}

	while (p < b_end) {
		h32_vec = _mm256_add_epi32(
			h32_vec, _mm256_set1_epi32(*p * _XXH_X86_PRIME32_5));
		h32_vec = _mm256_mullo_epi32(
			__xxh32_rotl32_256b(h32_vec, 11),
			_mm256_set1_epi32(_XXH_X86_PRIME32_1));
		p++;
	}

	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 15));
	h32_vec = _mm256_mullo_epi32(h32_vec,
				     _mm256_set1_epi32(_XXH_X86_PRIME32_2));
	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 13));
	h32_vec = _mm256_mullo_epi32(h32_vec,
				     _mm256_set1_epi32(_XXH_X86_PRIME32_3));
	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 16));

	return h32_vec;
}

/**
 * xxh32_8hashes() - same as xxh32() but takes 8 seeds and returns 8 hashes.
 *
 * Requires AVX2.
 *
 * @input: The data to hash.
 * @len: The length of the data to hash.
 * @seeds: The seeds to use for each hash; must be at least 8 elements long.
 * @hashes: The output buffer to store the 8 hashes.
 */
static inline void xxh32_8hashes(const void *input, const size_t len,
				 const uint32_t *seeds, uint32_t *hashes)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i h32_vec = __xxh32_8hashes(input, len, seeds_vec);
	_mm256_storeu_si256((__m256i_u *)hashes, h32_vec);
}

static __always_inline __m256i __xxh32_pkt_8hashes(const void *input,
						   __m256i seeds_vec)
{
	const uint8_t *p = (const uint8_t *)input;
	__m256i h32_vec;
	uint8_t i;

	h32_vec = _mm256_add_epi32(seeds_vec,
				   _mm256_set1_epi32(_XXH_X86_PRIME32_5 + 13));

#pragma unroll(3)
	for (i = 0; i < 3; i++) {
		h32_vec = _mm256_add_epi32(
			h32_vec,
			_mm256_set1_epi32(*(uint32_t *)p * _XXH_X86_PRIME32_3));
		h32_vec = _mm256_mullo_epi32(
			__xxh32_rotl32_256b(h32_vec, 17),
			_mm256_set1_epi32(_XXH_X86_PRIME32_4));
		p += 4;
	}

	h32_vec = _mm256_add_epi32(h32_vec,
				   _mm256_set1_epi32(*p * _XXH_X86_PRIME32_5));
	h32_vec = _mm256_mullo_epi32(__xxh32_rotl32_256b(h32_vec, 11),
				     _mm256_set1_epi32(_XXH_X86_PRIME32_1));
	/* p++; */

	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 15));
	h32_vec = _mm256_mullo_epi32(h32_vec,
				     _mm256_set1_epi32(_XXH_X86_PRIME32_2));
	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 13));
	h32_vec = _mm256_mullo_epi32(h32_vec,
				     _mm256_set1_epi32(_XXH_X86_PRIME32_3));
	h32_vec = _mm256_xor_si256(h32_vec, _mm256_srli_epi32(h32_vec, 16));

	return h32_vec;
}

/**
 * xxh32_pkt_8hashes() - same as xxh32() but takes 8 seeds and returns 8 hashes;
 *                       specialized for 13-byte packet 5-tuples.
 *
 * Requires AVX2.
 *
 * @input: The data to hash; must be at least 13 bytes long.
 * @seeds: The seeds to use for each hash; must be at least 8 elements long.
 * @hashes: The output buffer to store the 8 hashes.
 */
static inline void xxh32_pkt_8hashes(const void *input, const uint32_t *seeds,
				     uint32_t *hashes)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i h32_vec = __xxh32_pkt_8hashes(input, seeds_vec);
	_mm256_storeu_si256((__m256i_u *)hashes, h32_vec);
}

#endif /* __ENETSTL_XXHASH_X86_H__ */