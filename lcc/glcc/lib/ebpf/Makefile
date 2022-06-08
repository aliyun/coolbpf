ifneq ($(KERNELRELEASE),)
	obj-m := ebpfdrv.o
	EXTRA_CFLAGS += -I$(src)
	ebpfdrv-objs := ebpf.o allsyms.o core.o verifier.o disasm.o tnum.o bpf_trace.o helpers.o bpf_jit_comp.o bpf_jit.o trace_bpf_jit_comp.o trace_bpf_jit.o  \
					hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o map_in_map.o \
					stackmap.o \
					ebpf_kprobe.o ebpf_tracepoint.o
else
	KERN_DIR ?= /usr/src/kernels/3.10.0-327.ali2017.alios7.x86_64/
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers modules.order