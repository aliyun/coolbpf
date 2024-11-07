/**
 * @author Lunqi Zhao (lunqi.zhao@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __ENETSTL_FASTHASH_X86_H__
#define __ENETSTL_FASTHASH_X86_H__

#include "common.h"
#include <immintrin.h>

static const uint64_t _FASTHASH_X86_M = 0x880355f21e6d1965ULL;

#if defined(__AVX512DQ__) && defined(__AVX512VL__)
#define _mm256_mullo_epi64_emulated _mm256_mullo_epi64
#else
#define _mm256_mullo_epi64_emulated(a, b)                                     \
	({                                                                    \
		__m256i lo = _mm256_mul_epu32((a), (b));                      \
		__m256i hi = _mm256_and_si256(                                \
			_mm256_add_epi32(                                     \
				_mm256_mullo_epi32(_mm256_slli_si256((a), 4), \
						   (b)),                      \
				_mm256_mullo_epi32(                           \
					(a), _mm256_slli_si256((b), 4))),     \
			_mm256_set_epi32(0xffffffff, 0, 0xffffffff, 0,        \
					 0xffffffff, 0, 0xffffffff, 0));      \
		_mm256_add_epi32(lo, hi);                                     \
	})
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__)
#define _mm256_cvtepi64_epi32_emulated _mm256_cvtepi64_epi32
#else
#define _mm256_cvtepi64_epi32_emulated(a)                               \
	({                                                              \
		__m256i tmp = _mm256_permutevar8x32_epi32(              \
			(a), _mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0)); \
		_mm256_extracti128_si256(tmp, 0);                       \
	})
#endif

#define __fasthash_mix_256b(hashes_vec)                                     \
	({                                                                  \
		(hashes_vec) = _mm256_xor_si256(                            \
			(hashes_vec), _mm256_srli_epi64((hashes_vec), 23)); \
		(hashes_vec) = _mm256_mullo_epi64_emulated(                 \
			(hashes_vec),                                       \
			_mm256_set1_epi64x(0x2127599bf4325c37ULL));         \
		(hashes_vec) = _mm256_xor_si256(                            \
			(hashes_vec), _mm256_srli_epi64((hashes_vec), 47)); \
	})

static __always_inline __m256i __fasthash64_4hashes(const void *input,
						    size_t len,
						    __m256i seeds_vec)
{
	const uint64_t *pos = (const uint64_t *)input;
	const uint64_t *end = pos + (len / 8);
	const unsigned char *pos2;
	__m256i hashes_vec = _mm256_xor_si256(
		seeds_vec, _mm256_set1_epi64x(len * _FASTHASH_X86_M));
	__m256i v_vec;

	while (pos != end) {
		v_vec = _mm256_set1_epi64x(*pos++);
		hashes_vec = _mm256_xor_si256(hashes_vec,
					      __fasthash_mix_256b(v_vec));
		hashes_vec = _mm256_mullo_epi64_emulated(
			hashes_vec, _mm256_set1_epi64x(_FASTHASH_X86_M));
	}

	pos2 = (const unsigned char *)pos;
	v_vec = _mm256_setzero_si256();

	switch (len & 7) {
	case 7:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[6] << 48));
		/* pass through */
	case 6:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[5] << 40));
		/* pass through */
	case 5:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[4] << 32));
		/* pass through */
	case 4:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[3] << 24));
		/* pass through */
	case 3:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[2] << 16));
		/* pass through */
	case 2:
		v_vec = _mm256_xor_si256(
			v_vec, _mm256_set1_epi64x((uint64_t)pos2[1] << 8));
		/* pass through */
	case 1:
		v_vec = _mm256_xor_si256(v_vec,
					 _mm256_set1_epi64x((uint64_t)pos2[0]));
		hashes_vec = _mm256_xor_si256(hashes_vec,
					      __fasthash_mix_256b(v_vec));
		hashes_vec = _mm256_mullo_epi64_emulated(
			hashes_vec, _mm256_set1_epi64x(_FASTHASH_X86_M));
	}

	hashes_vec = __fasthash_mix_256b(hashes_vec);

	return hashes_vec;
}

/**
 * fasthash64_4hashes() - same as fasthash64() but takes 4 seeds and returns 4
 *                        hashes.
 *
 * Requires AVX2 or AVX512DQ/VL/F.
 *
 * @input: The data to hash.
 * @len: The length of the data to hash.
 * @seeds: The seeds to use for each hash; must be at least 4 elements long.
 * @hashes: The output buffer for the hashes; must be at least 4 elements long.
 */
static inline void fasthash64_4hashes(const void *input, size_t len,
				      const uint64_t *seeds, uint64_t *hashes)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i hashes_vec = __fasthash64_4hashes(input, len, seeds_vec);
	_mm256_storeu_si256((__m256i_u *)hashes, hashes_vec);
}

static __always_inline __m128i __fasthash32_4hashes(const void *input,
						    size_t len,
						    __m128i seeds_vec)
{
	__m256i seeds_vec_256b, hashes_vec_256b;
	__m128i hashes_vec;

	seeds_vec_256b = _mm256_cvtepi32_epi64(seeds_vec);
	hashes_vec_256b = __fasthash64_4hashes(input, len, seeds_vec_256b);
	hashes_vec_256b = _mm256_sub_epi64(
		hashes_vec_256b, _mm256_srli_epi64(hashes_vec_256b, 32));
	hashes_vec = _mm256_cvtepi64_epi32_emulated(hashes_vec_256b);

	return hashes_vec;
}

/**
 * fasthash32_4hashes() - same as fasthash32() but takes 4 seeds and returns 4
 *                        hashes.
 *
 * Requires AVX2 or AVX512DQ/VL/F.
 *
 * @input: The data to hash.
 * @len: The length of the data to hash.
 * @seeds: The seeds to use for each hash; must be at least 4 elements long.
 * @hashes: The output buffer for the hashes; must be at least 4 elements long.
 */
static inline void fasthash32_4hashes(const void *input, size_t len,
				      const uint32_t *seeds, uint32_t *hashes)
{
	__m128i seeds_vec = _mm_loadu_si128((const __m128i_u *)seeds);
	__m128i hashes_vec = __fasthash32_4hashes(input, len, seeds_vec);
	_mm_storeu_si128((__m128i_u *)hashes, hashes_vec);
}

static __always_inline __m256i __fasthash64_pkt_4hashes(const void *input,
							__m256i seeds_vec)
{
	const uint64_t *pos = (const uint64_t *)input;
	const unsigned char *pos2;
	__m256i hashes_vec = _mm256_xor_si256(
		seeds_vec, _mm256_set1_epi64x(_FASTHASH_X86_M * 13));
	__m256i v_vec;

	v_vec = _mm256_set1_epi64x(*pos++);
	hashes_vec = _mm256_xor_si256(hashes_vec, __fasthash_mix_256b(v_vec));
	hashes_vec = _mm256_mullo_epi64_emulated(
		hashes_vec, _mm256_set1_epi64x(_FASTHASH_X86_M));

	pos2 = (const unsigned char *)pos;
	v_vec = _mm256_set1_epi64x(
		((uint64_t)pos2[4] << 32) ^ ((uint64_t)pos2[3] << 24) ^
		((uint64_t)pos2[2] << 16) ^ ((uint64_t)pos2[1] << 8) ^
		(uint64_t)pos2[0]);
	hashes_vec = _mm256_xor_si256(hashes_vec, __fasthash_mix_256b(v_vec));
	hashes_vec = _mm256_mullo_epi64_emulated(
		hashes_vec, _mm256_set1_epi64x(_FASTHASH_X86_M));

	hashes_vec = __fasthash_mix_256b(hashes_vec);

	return hashes_vec;
}

/**
 * fasthash64_pkt_4hashes() - same as fasthash64() but takes 4 seeds and returns
 *                            4 hashes; specialized for 13-byte packet 5-tuples.
 *
 * Requires AVX2 or AVX512DQ/VL/F.
 *
 * @input: The data to hash; must be 13 bytes long.
 * @seeds: The seeds to use for each hash; must be at least 4 elements long.
 * @hashes: The output buffer for the hashes; must be at least 4 elements long.
 */
static inline void fasthash64_pkt_4hashes(const void *input,
					  const uint64_t *seeds,
					  uint64_t *hashes)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i hashes_vec = __fasthash64_pkt_4hashes(input, seeds_vec);
	_mm256_storeu_si256((__m256i_u *)hashes, hashes_vec);
}

static __always_inline __m128i __fasthash32_pkt_4hashes(const void *input,
							__m128i seeds_vec)
{
	__m256i seeds_vec_256b, hashes_vec_256b;
	__m128i hashes_vec;

	seeds_vec_256b = _mm256_cvtepi32_epi64(seeds_vec);
	hashes_vec_256b = __fasthash64_pkt_4hashes(input, seeds_vec_256b);
	hashes_vec_256b = _mm256_sub_epi64(
		hashes_vec_256b, _mm256_srli_epi64(hashes_vec_256b, 32));
	hashes_vec = _mm256_cvtepi64_epi32_emulated(hashes_vec_256b);

	return hashes_vec;
}

/**
 * fasthash32_pkt_4hashes() - same as fasthash32() but takes 4 seeds and returns
 *                            4 hashes; specialized for 13-byte packet 5-tuples.
 *
 * Requires AVX2 or AVX512DQ/VL/F.
 *
 * @input: The data to hash; must be 13 bytes long.
 * @seeds: The seeds to use for each hash; must be at least 4 elements long.
 * @hashes: The output buffer for the hashes; must be at least 4 elements long.
 */
static inline void fasthash32_pkt_4hashes(const void *input,
					  const uint32_t *seeds,
					  uint32_t *hashes)
{
	__m128i seeds_vec = _mm_loadu_si128((const __m128i_u *)seeds);
	__m128i hashes_vec = __fasthash32_pkt_4hashes(input, seeds_vec);
	_mm_storeu_si128((__m128i_u *)hashes, hashes_vec);
}

#endif /* __ENETSTL_FASTHASH_X86_H__ */