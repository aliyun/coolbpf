# coolbpf
    coolbpf's target is to build a platform for libbpf compile collection,
    which is for creating efficient kernel tracing and manipulation
    programs, is to wrapper main functions of libbpf for user development.

    coolbpf's main function are:
    1) Service for local compile, and some wraps for BPF function call.
    2) Service for remote compile, it receives xx.bpf.c, and return bpf.so
    to your local APP to loading. The user can focus on their main functions
    and don't
    care compile environment.
    3) High kernel version backport to low version with kernel module, such
    as 3.10 BPF support, and perf buffer replace with new feature of ring
    buffer.
    4) BTF auto generate.
    5）Variety kernel version testing for new BPF functions and tools.
    6）Support for many languags, python/go/c/rust.


## Compiler Environment

Compiling libcoolbpf requires installing the following dependent libraries/tools:

* elfutils-devel
* gcc

Compiling the eBPF tool requires additional installation of the following dependent libraries/tools:

* clang
* llvm

## Install/uninstall libcoolbpf

Installation: Run `./install.sh` in the coolbpf root directory.
Uninstall: Run `./uninstall.sh` in the coolbpf root directory.

## Usage example

In the tools/examples/syscall directory, we provide examples of using libcoolbpf to develop eBPF programs. The process of compiling the syscall eBPF tool is as follows:

* Install libcoolbpf: Run `./install.sh` in the coolbpf root directory to install libcoolbpf
* Compile syscall: run `mkdir -p build && cd build && cmake -DBUILD_EXAMPLE=on .. && make` in the coolbpf root directory

The location of the final generated syscall executable program is: `build/tools/examples/syscall/syscall`.