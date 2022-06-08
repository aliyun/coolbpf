VMLINUX_VERSION ?= `uname -r`

SRC = $(abspath src)
INC = $(abspath include)

OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath tool/bpftool)
LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OBJ := $(abspath libbpf.a)
INCLUDES := -I$(OUTPUT) -I$(INC) -Iinclude -Ibpf -Ilibbpf/include/uapi
CFLAGS := -g $(INCLUDES)
ARCH := $(shell uname -m)
CARCH := $(shell uname -m | sed 's/x86_64/x86/')

SO = bpf.so
APP = main
SOURCE = $(wildcard ${SRC}/*.c)
OBJECT = $(patsubst %.c,${OUTPUT}/%.o,$(notdir ${SOURCE}))

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-I \1|p }')

SKEL := $(addprefix $(OUTPUT)/,$(notdir $(patsubst %.bpf.c, %.skel.h, $(wildcard bpf/*.bpf.c))))

.PHONY: all
all: $(SO)

.PHONY: clean
clean:
	rm -rf *.o $(SO) $(APP) $(OUTPUT) bpf/vmlinux.h ${SRC}/bpf_init.c
	$(MAKE) -C $(LIBBPF_SRC) clean

$(OUTPUT) $(OUTPUT)/libbpf:
	mkdir -p $@

# build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1
	cp $(LIBBPF_SRC)/libbpf.a ./

bpf/vmlinux.h: $(wildcard vmlinux/*.h)
	ln -sf ../../hive/header/$(ARCH)/vmlinux-$(VMLINUX_VERSION).h bpf/vmlinux.h

.PRECIOUS: $(OUTPUT)/%.bpf.o

.PRECIOUS: $(OUTPUT)/%.skel.h

# compile bpf program
$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard bpf/%.h) bpf/vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(CARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(CLFLAG) -c $(filter %.c,$^) -o $@
#	$(CC) $(CFLAGS) -c $(filter %.c,$^) -w
#	$(LLVM_STRIP) -g $@ # strip useless DWARF info

# gen skeleton header file
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

$(SRC)/bpf_init.c: $(SKEL)
	python tool/generateUser.py $(VMLINUX_VERSION) $(ARCH) $(CLFLAG)

# $(OUTPUT)/%.o: ${SRC}/%.c
#	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

$(SRC)/bpf_init.o: ${SRC}/bpf_init.c $(wildcard %.h) $(SKEL) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -fPIC $(INCLUDES) -c $(filter %.c,$^) -o $@

# link pingtrace elf
touch: $(SKEL)
	python tool/generateUser.py

$(SO): %: $(SRC)/bpf_init.o $(LIBBPF_OBJ) $(wildcard $(INC)/%.h) | $(OUTPUT)
	$(CC) $(CFLAGS) -shared -fPIC -lelf -lz -o $@ $^ $(LIBBPF_OBJ)

$(APP): %: ${OBJECT} $(wildcard $(INC)/%.h) | $(OUTPUT)
	$(CC) $(CFLAGS) $^ -lelf -lz -lpthread -lbpf -Ibpf -o $@

