
#include "test_helpers.h"
#include "enetstl_countmin_sketch.skel.h"

void test() {
        BPF_PROG_TEST_RUNNER("enetstl_countmin_sketch_bpf", enetstl_countmin_sketch_bpf, enetstl_pkt_v4, test_countmin, 1, XDP_PASS);
}

int main() {
	test();
}