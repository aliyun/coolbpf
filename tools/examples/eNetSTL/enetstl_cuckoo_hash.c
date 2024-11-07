#include "test_helpers.h"
#include "enetstl_cuckoo_hash.skel.h"

void test() {
        BPF_PROG_TEST_RUNNER("enetstl_cuckoo_hash_bpf", enetstl_cuckoo_hash_bpf, enetstl_pkt_v4, test_cuckoo_hash, 1, XDP_PASS);
}

int main() {
	test();
}