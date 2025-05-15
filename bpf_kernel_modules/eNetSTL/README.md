## Configuring Module BTF

eNetSTL relies on the eBPF subsystem to add new kfunc through kernel modules, which require support for the module BTF functionality. To generate module BTF for kernel modules:

* Copy the current kernel's vmlinux to  `/usr/lib/modules/$(uname -r)/build`
Copy the tools directory from the kernel source to `/usr/lib/modules/$(uname -r)/build`

At this point, running `ls /usr/lib/modules/$(uname -r)/build` should yield something similar to:

`arch include Makefile Module.symvers scripts tools vmlinux`

## Compiling and Loading the Kernel Module

To compile the kernel module, 

* run `cd bpf_kernel_modules/eNetSTL && make`. If the kernel was compiled with clang, run `bpf_kernel_modules/eNetSTL && make LLVM=1`.
* To load the kernel module, run `sudo insmod eNetSTL.ko`.

Note: If issues arise during module compilation, consider adjusting the gcc or clang version in the Makefile or updating the pahole tool used to generate BTF.