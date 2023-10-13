
sockops:sockops_user.c sockops_kern.h client server
	gcc -Wp,-MD,.sockops_user.o.d -Wall -O2 -g -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I../../tools/testing/selftests/bpf/ -I../../tools/lib/ -I../../tools/include -I../../tools/perf -DHAVE_ATTR_TEST=0  -c -o sockops_user.o sockops_user.c
	gcc -Wp,-MD,.sockops.d -Wall -O2 -g -Wmissing-prototypes -Wstrict-prototypes -I../../usr/include -I../../tools/testing/selftests/bpf/ -I../../tools/lib/ -I../../tools/include -I../../tools/perf -DHAVE_ATTR_TEST=0   -o sockops sockops_user.o ../../tools/testing/selftests/bpf/cgroup_helpers.o ../../tools/lib/bpf/libbpf.a -lelf -lz -pthread


sockops_kern.o:sockops_kern.c
	clang -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/10/include -I../../arch/x86/include -I../../arch/x86/include/generated  -I../../include -I../../arch/x86/include/uapi -I../../arch/x86/include/generated/uapi -I../../include/uapi -I../../include/generated/uapi -include ../../include/linux/kconfig.h -fno-stack-protector -g \
        -I. -I../../tools/testing/selftests/bpf/ \
        -I../../tools/lib/ \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -I../bpf/ -include asm_goto_workaround.h \
        -O2 -emit-llvm -Xclang -disable-llvm-passes -c sockops_kern.c -o - | \
        opt -O2 -mtriple=bpf-pc-linux | llvm-dis | \
        llc -march=bpf  -filetype=obj -o sockops_kern.o

sockops_kern.h:sockops_kern.o
	bpftool gen skeleton sockops_kern.o > sockops_kern.h

server:server.c
	gcc server.c -g -o server

client:client.c
	gcc client.c -g -lpthread -o client

clean:
	@find . -type f -name '*.o' -delete
	@rm -f sockops sockops_kern.h client server
