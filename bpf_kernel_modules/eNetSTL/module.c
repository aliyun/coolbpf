/**
 * @author Bin Yang (binyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/filter.h>
#include "common.h"
#include "hash_post_alg.h"
#include "cmp_alg.h"
#include "crc.h"

#define ADAPT_COUNTMIN 1

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

struct key_type_16 {
	char data[16];
};

__bpf_kfunc int bpf_cmp_eq(const void *key1, size_t key1__sz,
			   const void *key2, size_t key2__sz)
{
	return __cmp_eq(key1, key1__sz, key2, key2__sz);
}

__bpf_kfunc u32 bpf_find_mask_u16(void *arr, size_t arr__sz, u16 val)
{
	return __find_mask_u16(arr, arr__sz, val);
}
EXPORT_SYMBOL_GPL(bpf_find_mask_u16);

__bpf_kfunc u32 bpf_find_u16(void *arr, size_t arr__sz, u16 val)
{
	return __find_u16(arr, arr__sz, val);
}
EXPORT_SYMBOL_GPL(bpf_find_u16);

/*library of hashes*/
__bpf_kfunc void bpf_fasthash32_cnt32(const void *input, size_t input__sz,
				      void *table, size_t table__sz,
				      uint32_t column_shift)
{
	return fasthash32_cnt32(input, input__sz, (uint32_t *)table, table__sz,
				column_shift);
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_cnt32);

/*library of hashes*/
__bpf_kfunc void bpf_fasthash32_pkt_cnt32(const struct pkt_5tuple *input,
					  void *table, size_t table__sz,
					  uint32_t column_shift)
{
	return fasthash32_pkt_cnt32(input, (uint32_t *)table, table__sz,
				    column_shift);
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_pkt_cnt32);

/*library of hashes*/
__bpf_kfunc void bpf_xxh32_cnt32(const void *input, size_t input__sz,
				 void *table, size_t table__sz,
				 uint32_t column_shift)
{
	return xxh32_cnt32(input, input__sz, (uint32_t *)table, table__sz,
			   column_shift);
}
EXPORT_SYMBOL_GPL(bpf_xxh32_cnt32);

/*library of hashes*/
__bpf_kfunc void bpf_xxh32_pkt_cnt32(const struct pkt_5tuple *input,
				     void *table, size_t table__sz,
				     uint32_t column_shift)
{
	return xxh32_pkt_cnt32(input, (uint32_t *)table, table__sz,
			       column_shift);
}
EXPORT_SYMBOL_GPL(bpf_xxh32_pkt_cnt32);

__bpf_kfunc u32 bpf_crc32_hash(const void *key, u32 key__sz, u32 seed)
{
	return crc32c(key, key__sz, seed);
}
EXPORT_SYMBOL_GPL(bpf_crc32_hash);

__bpf_kfunc u64 bpf_ffs(u64 val)
{
	return __ffs(val);
}
EXPORT_SYMBOL_GPL(bpf_ffs);

__bpf_kfunc u32 bpf_tzcnt_u32(u32 val)
{
	return __tzcnt_u32(val);
}
EXPORT_SYMBOL_GPL(bpf_tzcnt_u32);

BTF_SET8_START(eNetSTL_kfunc_ids)
BTF_ID_FLAGS(func, bpf_crc32_hash)
BTF_ID_FLAGS(func, bpf_fasthash32_cnt32)
BTF_ID_FLAGS(func, bpf_fasthash32_pkt_cnt32)
BTF_ID_FLAGS(func, bpf_xxh32_cnt32)
BTF_ID_FLAGS(func, bpf_xxh32_pkt_cnt32)
BTF_ID_FLAGS(func, bpf_cmp_eq)
BTF_ID_FLAGS(func, bpf_find_mask_u16)
BTF_ID_FLAGS(func, bpf_find_u16)
BTF_ID_FLAGS(func, bpf_ffs)
BTF_ID_FLAGS(func, bpf_tzcnt_u32)
BTF_SET8_END(eNetSTL_kfunc_ids)

static const struct btf_kfunc_id_set eNetSTL_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &eNetSTL_kfunc_ids,
};

static int register_kfuncs(void)
{
	int ret;
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					     &eNetSTL_kfunc_set)) != 0) {
		return ret;
	}
	return 0;
}

static int __init eNetSTL_init(void)
{
	int ret = register_kfuncs();
	if (ret != 0) {
		pr_err("eNetSTL: failed to register kfunc set: %d\n", ret);
		return ret;
	} else {
		pr_info("eNetSTL: registered kfunc set\n");
	}

	return 0;
}

static void __exit eNetSTL_exit(void)
{
	pr_info("eNetSTL: exiting\n");
}

/* Register module functions */
module_init(eNetSTL_init);
module_exit(eNetSTL_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Yang && Yang Hanlin && Lunqi Zhao");
MODULE_DESCRIPTION("eNetSTL Library");
MODULE_VERSION("1.0.0");