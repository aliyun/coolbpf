/*
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2012-2016, Yann Collet.
 *
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. This program is dual-licensed; you may select
 * either version 2 of the GNU General Public License ("GPL") or BSD license
 * ("BSD").
 *
 * You can contact the author at:
 * - xxHash homepage: https://cyan4973.github.io/xxHash/
 * - xxHash source repository: https://github.com/Cyan4973/xxHash
 *
 * Adapted from lib/xxhash.c in the Linux kernel source tree.
 */

/* vmlinux.h should be included first */

/*-*************************************
 * Macros
 **************************************/
#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))
#define xxh_rotl64(x, r) ((x << r) | (x >> (64 - r)))

/*-*************************************
 * Constants
 **************************************/
static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 = 668265263U;
static const uint32_t PRIME32_5 = 374761393U;

static const uint64_t PRIME64_1 = 11400714785074694791ULL;
static const uint64_t PRIME64_2 = 14029467366897019727ULL;
static const uint64_t PRIME64_3 = 1609587929392839161ULL;
static const uint64_t PRIME64_4 = 9650029242287828579ULL;
static const uint64_t PRIME64_5 = 2870177450012600261ULL;

/*-***************************
 * Simple Hash Functions
 ****************************/
static inline uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

static inline uint32_t xxh32(const void *input, const size_t len,
			     const uint32_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *b_end = p + len;
	uint32_t h32;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
		uint32_t v2 = seed + PRIME32_2;
		uint32_t v3 = seed + 0;
		uint32_t v4 = seed - PRIME32_1;

		do {
			v1 = xxh32_round(v1, *(uint32_t *)p);
			p += 4;
			v2 = xxh32_round(v2, *(uint32_t *)p);
			p += 4;
			v3 = xxh32_round(v3, *(uint32_t *)p);
			p += 4;
			v4 = xxh32_round(v4, *(uint32_t *)p);
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
		      xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (uint32_t)len;

	while (p + 4 <= b_end) {
		h32 += *(uint32_t *)p * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}

static inline uint64_t xxh64_round(uint64_t acc, const uint64_t input)
{
	acc += input * PRIME64_2;
	acc = xxh_rotl64(acc, 31);
	acc *= PRIME64_1;
	return acc;
}

static inline uint64_t xxh64_merge_round(uint64_t acc, uint64_t val)
{
	val = xxh64_round(0, val);
	acc ^= val;
	acc = acc * PRIME64_1 + PRIME64_4;
	return acc;
}

static inline uint64_t xxh64(const void *input, const size_t len,
			     const uint64_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *const b_end = p + len;
	uint64_t h64;

	if (len >= 32) {
		const uint8_t *const limit = b_end - 32;
		uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
		uint64_t v2 = seed + PRIME64_2;
		uint64_t v3 = seed + 0;
		uint64_t v4 = seed - PRIME64_1;

		do {
			v1 = xxh64_round(v1, *(uint64_t *)p);
			p += 8;
			v2 = xxh64_round(v2, *(uint64_t *)p);
			p += 8;
			v3 = xxh64_round(v3, *(uint64_t *)p);
			p += 8;
			v4 = xxh64_round(v4, *(uint64_t *)p);
			p += 8;
		} while (p <= limit);

		h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) +
		      xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
		h64 = xxh64_merge_round(h64, v1);
		h64 = xxh64_merge_round(h64, v2);
		h64 = xxh64_merge_round(h64, v3);
		h64 = xxh64_merge_round(h64, v4);

	} else {
		h64 = seed + PRIME64_5;
	}

	h64 += (uint64_t)len;

	while (p + 8 <= b_end) {
		const uint64_t k1 = xxh64_round(0, *(uint64_t *)p);

		h64 ^= k1;
		h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
		p += 8;
	}

	if (p + 4 <= b_end) {
		h64 ^= (uint64_t)(p)*PRIME64_1;
		h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
		p += 4;
	}

	while (p < b_end) {
		h64 ^= (*p) * PRIME64_5;
		h64 = xxh_rotl64(h64, 11) * PRIME64_1;
		p++;
	}

	h64 ^= h64 >> 33;
	h64 *= PRIME64_2;
	h64 ^= h64 >> 29;
	h64 *= PRIME64_3;
	h64 ^= h64 >> 32;

	return h64;
}
