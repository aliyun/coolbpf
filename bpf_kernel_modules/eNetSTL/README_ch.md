## 配置module btf

eNetSTL依赖于eBPF子系统的用内核模块增加新的kfunc特性，该特性依赖于module btf功能的支持。为了生成内核模块的module btf

* 将当前内核的 vmlinux 复制到 `/usr/lib/modules/$(uname -r)/build`
* 将内核源码目录下的 tools 复制到 `/usr/lib/modules/$(uname -r)/build`

此时 `ls /usr/lib/modules/$(uname -r)/build` 会得到类似

`arch  include  Makefile  Module.symvers  scripts  tools  vmlinux`

## 编译并加载内核模块

* 编译内核模块 `cd bpf_kernel_modules/eNetSTL && make` 如果使用clang编译的内核 `cd bpf_kernel_modules/eNetSTL && make  LLVM=1`
* 加载内核模块 `sudo insmod eNetSTL.ko`

ps: 如果编译内核模块出现问题，可以修改Makefile中的gcc或者clang版本，或者升级生成btf的pahole工具