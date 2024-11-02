OBJ_NAME := eNetSTL
GCC_VERSION ?= $(shell gcc --version | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+" | head -1) 
CLANG_VERSION ?= $(shell clang --version | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+")
CC_SIMD_OPTS ?= -mavx2 -mbmi

obj-m := ${OBJ_NAME}.o

${OBJ_NAME}-objs := module.o

ifeq ($(LLVM),1)
ccflags-y += -I/usr/lib/llvm-$(shell echo $(CLANG_VERSION) | cut -d. -f1)/lib/clang/$(CLANG_VERSION)/include $(CC_SIMD_OPTS)
else
ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(shell echo $(GCC_VERSION) | cut -d. -f1)/include $(CC_SIMD_OPTS)
endif

KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
