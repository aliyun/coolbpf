

ifneq ($(KERNELRELEASE),)
	obj-m := ringbuffer.o
	EXTRA_CFLAGS += -I$(src)
	ringbuffer-objs := main.o ringbuffer.o 
else
	KERN_DIR ?= /usr/src/kernels/3.10.0-327.ali2017.alios7.x86_64/
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers modules.order