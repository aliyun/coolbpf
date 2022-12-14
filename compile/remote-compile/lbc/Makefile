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
CFLAGS := -g -fPIC $(INCLUDES)
ARCH := $(shell uname -m)
CARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIB_Z_ELF_BFD_OBJ := /root/staticlib/x86_64/libz.a /root/staticlib/x86_64/libelf.a

SO = bpf.so
SOURCE = $(wildcard ${SRC}/*.c)
OBJECT = $(patsubst %.c,${SRC}/%.o,$(notdir ${SOURCE}))

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
	touch src/bpf_init.c
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1
	cp $(LIBBPF_SRC)/libbpf.a ./

bpf/vmlinux.h: $(wildcard vmlinux/*.h)
	ln -sf ../../hive/header/$(ARCH)/vmlinux-$(VMLINUX_VERSION).h bpf/vmlinux.h
	python tool/replaceHead.py bpf/lbc.org.h bpf/vmlinux.h bpf/lbc.h

.PRECIOUS: $(OUTPUT)/lbc.bpf.o

.PRECIOUS: $(OUTPUT)/lbc.skel.h

# compile bpf program
$(OUTPUT)/lbc.bpf.o: bpf/lbc.bpf.c $(LIBBPF_OBJ) $(wildcard bpf/lbc.h) bpf/vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(CARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(CLFLAG) -c $(filter %.c,$^) -o $@
#	$(CC) $(CFLAGS) -c $(filter %.c,$^) -w
#	$(LLVM_STRIP) -g $@ # strip useless DWARF info

# gen skeleton header file
$(OUTPUT)/lbc.skel.h: $(OUTPUT)/lbc.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(SRC)/bpf_init.c: $(OUTPUT)/lbc.skel.h
	python3 tool/generateUser.py $(VMLINUX_VERSION) $(ARCH) $(CLFLAG)

# link pingtrace elf
touch: $(SKEL)
	python tool/generateUser.py

$(SRC)/bpf_init.o: $(SRC)/bpf_init.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(SRC)/perf_event_attr.o: $(SRC)/perf_event_attr.c $(SRC)/perf_event_attr.h $(SRC)/cJSON.h
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(SRC)/cJSON.o: $(SRC)/cJSON.c $(SRC)/cJSON.h
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(SRC)/lbc_static.o: $(SRC)/lbc_static.c $(SKEL) $(SRC)/perf_event_attr.h
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

OBJS=$(SRC)/bpf_init.o $(SRC)/perf_event_attr.o $(SRC)/cJSON.o $(SRC)/lbc_static.o

$(SO): %: $(OBJS) $(LIBBPF_OBJ) $(LIB_Z_ELF_BFD_OBJ)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^
