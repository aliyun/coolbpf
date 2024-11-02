/**
 * @author Bin Yang (binyang@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#include "enetstl_common.bpf.h"
#include "xxhash.h"

#define HASHFN_N 8
#define COLUNM_SHIFT 8
#define COLUNMS (1 << COLUNM_SHIFT)

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

struct countmin {
	__u32 values[HASHFN_N][COLUNMS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

static void __always_inline countmin_add_eNetSTL(struct countmin *cm, struct pkt_5tuple *element)
{
	bpf_xxh32_cnt32((struct pkt_5tuple *) element, sizeof(*element), (void*)cm, sizeof(*cm), COLUNM_SHIFT);  //COLUNM_SHIT 8
}

static __u32 __always_inline countmin_query(struct countmin *cm, struct pkt_5tuple *element)
{
	__u32 min_count = ~0;
	int i; 
	for (i = 0; i < HASHFN_N; i++) {
		__u32 hash = xxh32((void*)element, sizeof(*element), _HASH_ALG_POST_SEEDS_DATA[i]);
		min_count = min(min_count, cm->values[i][hash & (COLUNMS - 1)]);
	}
	return min_count;
}

SEC("xdp") int test_countmin(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct pkt_5tuple pkt;
	uint32_t zero = 0;
	struct countmin *cm;
	int ret = 0;
	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0) {
		bpf_printk(" failed to parse packet: %d", ret);
		goto err;
	}

	cm = bpf_map_lookup_elem(&countmin, &zero);
	if (!cm) {
		bpf_printk(" invalid entry in the countmin sketch");
		goto err;
	}
	countmin_add_eNetSTL(cm, &pkt);

	/* testing */
	__u32 curr_cnt = countmin_query(cm,  &pkt);

	if (curr_cnt != 1) {
		bpf_printk("quert count does not equals to 1");
		goto err;
	}
	return XDP_PASS;
err:
	return XDP_DROP;
}