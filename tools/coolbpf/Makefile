

ROOT = $(abspath ../../)
BUILD = $(abspath ./build)
BUILD_COOLBPF = $(abspath ./build/coolbpf)
BUILD_OBJECT = $(abspath ./build/object)
BUILD_TARGET = $(abspath ./build/target)

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(ROOT)/compile/local-compile/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
COOLBPF_OBJ += $(BUILD_COOLBPF)/coolbpf.a $(BUILD_COOLBPF)/libbpf.a

CFLAGS := -g -O2 -Wall
LDFLAGS := -g -O2 -Wall
INCLUDES += -I$(BUILD_COOLBPF) -I$(ROOT)/third/libbpf/include/uapi -I$(ROOT)/third/ -I$(BUILD_OBJECT)

BPF_APPS = example

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'                                   \
		"$(1)"                                            \
		"$(patsubst $(abspath $(TARGET_PATH))/%,%,$(2))"       \
		"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(BPF_APPS)

$(patsubst %,$(BUILD_OBJECT)/%.o,$(BPF_APPS)): %.o: %.skel.h

$(BPF_APPS): %: $(BUILD_OBJECT)/%.o $(COOLBPF_OBJ) | $(BUILD_OBJECT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -pthread -o $@
	$(Q)mv $@ $(BUILD)/$@

$(BUILD_OBJECT)/%.o: %.c $(wildcard %.h) $(COOLBPF_OBJ) | $(BUILD_OBJECT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(BUILD_OBJECT)/%.skel.h: $(BUILD_OBJECT)/%.bpf.o | $(BUILD_OBJECT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(BUILD_OBJECT)/%.bpf.o: %.bpf.c $(COOLBPF_OBJ) $(wildcard %.h) | $(BUILD_OBJECT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@ && $(LLVM_STRIP) -g $@

$(COOLBPF_OBJ):
	$(Q)make -C ${ROOT}/third/libbpf/src OBJDIR=$(BUILD_COOLBPF)/object DESTDIR=$(BUILD_COOLBPF) INCLUDEDIR= LIBDIR= UAPIDIR= install
	$(Q)make -C ${ROOT}/src OBJDIR=$(BUILD_COOLBPF)/object DESTDIR=$(BUILD_COOLBPF) INCLUDEDIR= LIBDIR= UAPIDIR= install 

$(BUILD_OBJECT):
	$(call msg,MKDIR,$@)
	$(Q) mkdir -p $@


.PHONY: clean

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(BUILD)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
