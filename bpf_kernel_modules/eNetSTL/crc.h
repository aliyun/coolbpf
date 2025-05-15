/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 *
 * Adapted from DPDK lib/hash/rte_crc_x86.h, lib/hash/rte_hash_crc.h
 */

#ifndef _CRC_H
#define _CRC_H

#include <linux/types.h>

// This macro is required to include <immintrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#include <immintrin.h>

static inline uint32_t crc32c_sse42_u8(uint8_t data, uint32_t init_val)
{
	__asm__ volatile("crc32b %[data], %[init_val];"
			 : [init_val] "+r"(init_val)
			 : [data] "rm"(data));
	return init_val;
}

static inline uint32_t crc32c_sse42_u16(uint16_t data, uint32_t init_val)
{
	__asm__ volatile("crc32w %[data], %[init_val];"
			 : [init_val] "+r"(init_val)
			 : [data] "rm"(data));
	return init_val;
}

static inline uint32_t crc32c_sse42_u32(uint32_t data, uint32_t init_val)
{
	__asm__ volatile("crc32l %[data], %[init_val];"
			 : [init_val] "+r"(init_val)
			 : [data] "rm"(data));
	return init_val;
}

static inline uint32_t crc32c_sse42_u64(uint64_t data, uint64_t init_val)
{
	__asm__ volatile("crc32q %[data], %[init_val];"
			 : [init_val] "+r"(init_val)
			 : [data] "rm"(data));
	return (uint32_t)init_val;
}

/**
 * crc32c() - Calculate CRC32 hash on user-supplied byte array.
 *
 * @data: Data to perform hash on.
 * @data_len: How many bytes to use to calculate hash value.
 * @init_val: Value to initialise hash generator.
 * 
 * Return: 32bit calculated hash value.
 */
static inline uint32_t crc32c(const void *data, uint32_t data_len,
			      uint32_t init_val)
{
	unsigned i;
	uintptr_t pd = (uintptr_t)data;

	for (i = 0; i < data_len / 8; i++) {
		init_val = crc32c_sse42_u64(*(const uint64_t *)pd, init_val);
		pd += 8;
	}

	if (data_len & 0x4) {
		init_val = crc32c_sse42_u32(*(const uint32_t *)pd, init_val);
		pd += 4;
	}

	if (data_len & 0x2) {
		init_val = crc32c_sse42_u16(*(const uint16_t *)pd, init_val);
		pd += 2;
	}

	if (data_len & 0x1)
		init_val = crc32c_sse42_u8(*(const uint8_t *)pd, init_val);

	return init_val;
}

#endif
