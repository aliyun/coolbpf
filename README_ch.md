coolbpf项目，以CO-RE（Compile Once-Run Everywhere）为基础实现，
保留了资源占用低、可移植性强等优点，还融合了BCC动态编译的特性，
适合在生产环境批量部署所开发的应用。coolbpf开创了一个新的思路，
利用远程编译的思想，把用户的BPF程序推送到远端的服务器并返回给
用户.o或.so，提供高级语言如python/rust/go/c等进行加载，然后在
全量内核版本安全运行。用户只需专注自己的功能开发，不用关心底层
库（如LLVM、python等）安装、环境搭建，给广大BPF爱好者提供一种
新的探索和实践。
另外，coolbpf还支持在3.10内核通过kernel module的方式支持BPF程
序的运行，这样原来在高版本的应用程序可以不经修改就能顺利运行。

## 编译环境

编译libcoolbpf需要安装如下依赖库/工具：

* elfutils-devel
* gcc

编译eBPF工具需要额外安装如下依赖库/工具：

* clang
* llvm

## 安装/卸载libcoolbpf

安装：在coolbpf根目录下运行`./install.sh`即可。
卸载：在coolbpf根目录下运行`./uninstall.sh`即可。

## 使用示例

在tools/examples/syscall目录，我们提供了使用libcoolbpf来开发eBPF程序示例。编译syscall eBPF工具流程如下：

* 安装libcoolbpf：在coolbpf根目录下运行`./install.sh`来安装libcoolbpf
* 编译syscall：在coolbpf根目录下运行`mkdir -p build && cd build && cmake -DBUILD_EXAMPLE=on .. && make`

最终生成的syscall可执行程序位置在：`build/tools/examples/syscall/syscall`。

## 使用 BPF kernel modules 

在 bpf_kernel_modules 目录，我们提供了额外的内核模块实现的library, 为特定类型的BPF程序提供额外的 [kernel functions](https://docs.kernel.org/bpf/kfuncs.html)。使用这些library, 首先编译内核模块然后加载内核模块，最后在eBPF程序中使用模块暴露的kernel function即可。以为XDP程序设计的eNetSTL

(eNetSTL 作者: 东南大学 沈典、杨彬、杨翰林、赵伦祺)

* 编译eNetSTL: 在 bpf_kernel_modules/eNetSTL目录下运行 `make` (如果使用clang编译的内核运行 `make LLVM=1`), 然后运行 `sudo insmod eNetSTL.ko` 
* 在eBPF程序中 `#include "coolbpf.h"`，按照需求使用API, eNetSTL的API使用方式见 src/coolbpf_bpf.h
* eNetSTL的使用例子参考 tools/examples/eNetSTL
