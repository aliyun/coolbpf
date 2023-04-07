ROOT := $(abspath $(shell pwd)../../../)
OUTPUT ?= $(ROOT)/build/apps
BPFTOOL ?= $(abspath bpftool)
INCLUDES := -I$(ROOT)/build/third -I$(ROOT)/build/third/libbpf -I${ROOT}/arch/x86_64
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CORE_SRC ?= $(wildcard $(ROOT)/apps/*.bpf.c)

CLANG = clang
LLVM_STRIP = llvm-strip

.PHONY: all
all:gen_skel

gen_skel:
	$(shell mkdir -p $(OUTPUT))
	$(foreach src,$(BPF_CORE_SRC),\
		$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(src) -o $(OUTPUT)/$(patsubst %.c,%.o,$(notdir $(src))); \
		$(LLVM_STRIP) -g $(OUTPUT)/$(patsubst %.c,%.o,$(notdir $(src))); \
		$(BPFTOOL) gen skeleton  $(OUTPUT)/$(patsubst %.c,%.o,$(notdir $(src))) > $(OUTPUT)/$(patsubst %.bpf.c,%.skel.h,$(notdir $(src))); \
		)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: