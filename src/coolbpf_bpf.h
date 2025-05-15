/**
 * @file coolbpf_bpf.h
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief
 * @version 0.1
 * @date 2022-12-26
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef COOLBPF_BPF_H
#define COOLBPF_BPF_H
#define BPF_NO_GLOBAL_DATA
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_core.h"

#define MAX_STACK_DEPTH 20

// from linux/icmp.h
#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4   /* Source Quench		*/
#define ICMP_REDIRECT 5        /* Redirect (change route)	*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIME_EXCEEDED 11  /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12  /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/
#define NR_ICMP_TYPES 18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable		*/
#define ICMP_HOST_UNREACH 1 /* Host Unreachable		*/
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH 3 /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED 5    /* Source Route failed		*/
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13   /* Packet filtered */
#define ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define ICMP_PREC_CUTOFF 15    /* Precedence cut off */
#define NR_ICMP_UNREACH 15     /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET 0     /* Redirect Net			*/
#define ICMP_REDIR_HOST 1    /* Redirect Host		*/
#define ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL 0      /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME 1 /* Fragment Reass time exceeded	*/

/**
 * @brief bpf helper function: get timestamp
 *
 */
#define ns() bpf_ktime_get_ns()
/**
 * @brief bpf helper function: get pid
 *
 */
#define pid() (bpf_get_current_pid_tgid() >> 32)
/**
 * @brief bpf helper function: get tid
 *
 */
#define tid() ((u32)bpf_get_current_pid_tgid())
/**
 * @brief bpf helper function: get comm of current
 *
 */
#define comm(c) bpf_get_current_comm(c, sizeof(c))
/**
 * @brief bpf helper function: get cpu number
 *
 */
#define cpu() bpf_get_smp_processor_id()

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct                                                          \
    {                                                               \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

/**
 * @brief One line of code to create BPF_MAP_TYPE_HASH
 *
 */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_LRU_HASH
 *
 */
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_ARRAY
 *
 */
#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_PERCPU_ARRAY
 *
 */
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

/**
 * @brief One line of code to create BPF_MAP_TYPE_PERF_EVENT_ARRAY
 *
 */
#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

static inline int fast_log2(long value)
{
    int n = 0;
    int i;

    if (value < 1)
    {
        goto end;
    }

#pragma unroll
    for (i = 32; i > 0; i /= 2)
    {
        long v = 1ULL << i;
        if (value >= v)
        {
            n += i;
            value = value >> i;
        }
    }
end:
    return n;
}

#define NUM_E16 10000000000000000ULL
#define NUM_E8 100000000ULL
#define NUM_E4 10000ULL
#define NUM_E2 100ULL
#define NUM_E1 10ULL
static inline int fast_log10(long v)
{
    int n = 0;
    if (v >= NUM_E16)
    {
        n += 16;
        v /= NUM_E16;
    }
    if (v >= NUM_E8)
    {
        n += 8;
        v /= NUM_E8;
    }
    if (v >= NUM_E4)
    {
        n += 4;
        v /= NUM_E4;
    }
    if (v >= NUM_E2)
    {
        n += 2;
        v /= NUM_E2;
    }
    if (v >= NUM_E1)
    {
        n += 1;
    }
    return n;
}

static inline void add_hist(struct bpf_map_def *maps, int k, int v)
{
    u64 *pv = bpf_map_lookup_elem(maps, &k);
    if (pv)
    {
        __sync_fetch_and_add(pv, v);
    }
}

#define incr_hist(maps, k) add_hist(maps, k, 1)

static inline void hist2_push(struct bpf_map_def *maps, long v)
{
    int k = fast_log2(v);
    incr_hist(maps, k);
}

static inline void hist10_push(struct bpf_map_def *maps, long v)
{
    int k = fast_log10(v);
    incr_hist(maps, k);
}

/* eNetSTL APIs */
/**
 * bpf_crc32_hash() - Calculate CRC32 hash on user-supplied byte array.
 *
 * @data: Data to perform hash on.
 * @data__sz: How many bytes to use to calculate hash value.
 * @init_val: Value to initialise hash generator.
 * 
 * Return: 32bit calculated hash value.
 */
extern __u32 bpf_crc32_hash(const void *data, __u32 data__sz, __u32 init_val) __ksym;

/**
 * bpf_xxh32_cnt32 - Calculate multiple xxhash on given input and increase u32 counters based on hash results.
 *
 * @input: Data to perform hash on.
 * @input__sz: How many bytes to use to calculate hash value.
 * @table: Table of counters 
 * @table__sz: How many bytes of the total counter table
 * @column_shift: The table has (1 << column_shift) columns
 * 
 * The number of hash functions (HASH_NUM) is table__sz / (1 << colunm_shift)
 * Perform HASH_NUM xxhash calcualtions over input, for each results hashes[i], perform: 
 *    j = hashes[i] & (COL_NUM - 1);
 *	  *((u32*)table + i * column_count + j) += 1;
 */
extern void bpf_xxh32_cnt32(const void *input, __u64 input__sz,
				                  void *table, __u64 table__sz,
				                  __u32 column_shift) __ksym;

/**
 * bpf_fasthash32_cnt32 - Calculate multiple fasthash on given input and increase u32 counters based on hash results.
 *
 * @input: Data to perform hash on.
 * @input__sz: How many bytes to use to calculate hash value.
 * @table: Table of counters 
 * @table__sz: How many bytes of the total counter table
 * @column_shift: The table has (1 << column_shift) columns
 * 
 * The number of hash functions (HASH_NUM) is table__sz / (1 << colunm_shift)
 * Perform HASH_NUM xxhash calcualtions over input, for each results hashes[i], perform: 
 *    j = hashes[i] & (COL_NUM - 1);
 *	  *((u32*)table + i * column_count + j) += 1;
 */
extern void bpf_fasthash32_cnt32(const void *input, size_t input__sz,
				                       void *table, size_t table__sz,
				                       __u32 column_shift) __ksym;

/**
 * bpf_cmp_eq() - Compare two values for equality.
 *
 * @key1: Pointer to first value.
 * @key1__sz: Size of first value
 * @key2: Pointer to second value.
 * @key2__sz: Size of second value (should be greater or equal to key1__sz).
 *
 * Return: 0 if equal, 1 otherwise, -EINVAL, invalid key1_sz
 */
extern int bpf_cmp_eq(const void *key1, size_t key1_sz,
			             const void *key2, size_t key2_sz) __ksym;

/**
 * bpf_find_mask_u16_avx() - Find 16-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @arr__sz: number of bytes of arr.
 * @val: Value to find in the array.
 *
 * Return: 32-bit mask, if ith u16 equals val, the 2*i and 2*i + 1 bit are set to one 
 */
extern __u32 bpf_find_mask_u16(void *arr, size_t arr__sz, __u16 val) __ksym;

/**
 * bpf_find_u16() - Find 16-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @arr__sz: number of bytes of arr.
 * @val: Value to find in the array.
 *
 * Return: index of first value found; 16 if not found
 */
extern __u32 bpf_find_u16(void *arr, size_t arr__sz, __u16 val) __ksym;

/**
 * bpf_tzcnt_u32() - Count trailing zero bits in 32-bit value.
 *
 * @val: 32-bit value
 *
 * Return: number of trailing zero bits
 */
extern __u32 bpf_tzcnt_u32(__u32 val) __ksym;

/**
 * bpf_ffs() - find the first set bit in a word.
 *
 * @val: bitmap word.
 *
 * Return: the first set bit
 */
extern u64 bpf_ffs(unsigned long val) __ksym;

char _license[] SEC("license") = "GPL";

#endif