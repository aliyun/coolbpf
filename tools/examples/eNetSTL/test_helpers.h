/**
 * @author Lunqi Zhao (lunqi.zhao@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __BPF_TEST_HELPERS_H
#define __BPF_TEST_HELPERS_H

#include <linux/types.h>
typedef __u16 __bitwise __sum16;  
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <stdio.h>

#define MAGIC_BYTES 123
struct ipv4_packet {
	struct ethhdr eth;
	struct iphdr iph;
	struct tcphdr tcp;
} __attribute__((packed));

struct ipv4_packet enetstl_pkt_v4 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
	.iph.ihl = 5,
	.iph.protocol = IPPROTO_TCP,
	.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
	.tcp.urg_ptr = 123,
	.tcp.doff = 5,
};

static inline void set_prog_flags_test(struct bpf_program* prog) {
    	__u32 flags = bpf_program__flags(prog) | BPF_F_TEST_RND_HI32;
		bpf_program__set_flags(prog, flags);
}

#define CHECK_FAIL(condition) ({					\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%d\n", __func__, __LINE__);	\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%s ", __func__, tag);		\
		fprintf(stdout, ##format);				\
	} else {							\
		fprintf(stdout, "%s:PASS:%s %d nsec\n",			\
		       __func__, tag, duration);			\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)
	
#define ASSERT_EQ(actual, expected, name) ({				\
	static int duration = 0;					\
	typeof(actual) ___act = (actual);				\
	typeof(expected) ___exp = (expected);				\
	bool ___ok = ___act == ___exp;					\
	CHECK(!___ok, (name),						\
	      "unexpected %s: actual %lld != expected %lld\n",		\
	      (name), (long long)(___act), (long long)(___exp));	\
	___ok;								\
})

#define ASSERT_OK(res, name) ({						\
	static int duration = 0;					\
	long long ___res = (res);					\
	bool ___ok = ___res == 0;					\
	CHECK(!___ok, (name), "unexpected error: %lld (errno %d)\n",	\
	      ___res, errno);						\
	___ok;								\
})

static int __default_test_callback_after_load(void *skel)
{
	return 0;
}

static int __default_test_callback_before_load(void *skel)
{
		return 0;
}

#define BPF_PROG_TEST_RUNNER_WITH_CALLBACK(_name, __skel, pkt, _prog, _repeat, \
					   _callback_before_load,              \
					   _callback_after_load, expected_res) \
	char buf[128];                                                         \
	LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = &(pkt),                 \
		    .data_size_in = sizeof((pkt)), .data_out = buf,              \
		    .data_size_out = sizeof(buf), .repeat = _repeat, );        \
	struct __skel *skel = NULL;                                            \
	struct bpf_program *prog;                                              \
	int res = 0, prog_fd;                                                  \
	skel = __skel##__open();                                               \
	if (skel == NULL) {                                                    \
		fprintf(stdout, "faild to open and load %s\n", #__skel);       \
		return;                                                        \
	}                                                                      \
	if ((res = _callback_before_load(skel)) != 0) {                        \
		fprintf(stdout, "failed to invoke callback before load: %d\n", \
			res);                                                  \
		goto clean;                                                    \
	}                                                                      \
	prog = skel->progs._prog;                                              \
	set_prog_flags_test(prog);                                             \
	res = __skel##__load(skel);                                            \
	if (CHECK_FAIL(res)) {                                                 \
		goto clean;                                                    \
	}                                                                      \
	if ((res = _callback_after_load(skel)) != 0) {                         \
		fprintf(stdout, "failed to invoke callback after load: %d\n",  \
			res);                                                  \
		goto clean;                                                    \
	}                                                                      \
	res = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);           \
	ASSERT_OK(res, "bpf_prog_test_run_opts res");                          \
	ASSERT_EQ(topts.retval, expected_res, _name ":" #_prog);               \
clean:;                                                                        \
	__skel##__destroy(skel);                                               \
	return;

#define BPF_PROG_TEST_RUNNER(_name, __skel, pkt, _prog, _repeat, expected_res) \
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK(                                    \
		_name, __skel, pkt, _prog, _repeat,                            \
		__default_test_callback_before_load,                           \
		__default_test_callback_after_load, expected_res)

#endif 