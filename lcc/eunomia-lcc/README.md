# eunomia-lcc

use eunomia-bpf as a frontend for Coolbpf libbpf and kernel bpf supported.

使用开源社区的 [eunomia-bpf](https://gitee.com/anolis/eunomia) 框架作为 Coolbpf 的用户态开发库，让 Coolbpf 也能：

- 在编写 eBPF 程序或工具时只编写 libbpf 内核态代码，自动获取内核态导出信息，自动生成命令行参数、直方图输出等；
- 使用 WASM 进行用户态交互程序的开发，在 WASM 虚拟机内部控制整个 eBPF 程序的加载和执行，以及处理相关数据；
- 可以将预编译的 eBPF 程序打包为通用的 JSON 或 WASM 模块，跨架构和内核版本进行分发，无需重新编译即可动态加载运行。

同时保留 Coolbpf 的低版本兼容、BTF 自动获取、远程编译等特性，让 eBPF 程序的开发更加简便易行。

## example

### 编译运行(以编译 signsoop 为例)

以编译 example/signsoop 为例，首先确保 eunomia-bpf 已经作为一个 submodule 加入到项目中：

```bash
git submodule update --init --recursive
```

然后在项目根目录下执行，编译 eunomia-bpf 的编译工具链和运行时，在编译时需要安装 `libclang`, `libelf` and `zlib` 库：

```bash
cd lcc/eunomia-lcc
make
```

编译完成后可以看到编译工具 `ecc` 和运行工具 `ecli`, 可以使用 `ecc` 编译 example 中的 eBPF 程序：

```console
$ ./ecc sigsnoop.bpf.c sigsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

或者在 x86 上也可以用 docker 编译，在 sigsnoop 目录下：

```bash
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

可以使用 `ecli` 运行编译后的程序，可以通过内核态代码中的全局变量指定命令行参数，生成帮助信息等：

```console
$ sudo ./ecli package.json
TIME     PID     TPID    SIG     RET     COMM    
20:43:44  21276  3054    0       0       cpptools-srv
20:43:44  22407  3054    0       0       cpptools-srv
20:43:44  20222  3054    0       0       cpptools-srv
20:43:44  8933   3054    0       0       cpptools-srv
20:43:44  2915   2803    0       0       node
20:43:44  2943   2803    0       0       node
20:43:44  31453  3054    0       0       cpptools-srv

$ sudo ./ecli package.json  -h
Usage: sigsnoop_bpf [--help] [--version] [--verbose] [--filtered_pid VAR] [--target_signal VAR] [--failed_only]

Trace standard and real-time signals.

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filtered_pid        Process ID to trace. If set to 0, trace all processes. 
  --target_signal       Signal number to trace. If set to 0, trace all signals. 
  --failed_only         Trace only failed signals. If set to false, trace all signals. 

Built with eunomia-bpf framework.

$ sudo ./ecli package.json --filtered_pid 3024
TIME     PID     TPID    SIG     RET     COMM    
16:38:33  3024   2920    0       0       node
16:38:34  3024   2920    0       0       node
16:38:34  3024   2920    0       0       node
16:38:35  3024   2920    0       0       node
16:38:35  3024   2920    0       0       node
16:38:36  3024   2920    0       0       node
```

### minimal

`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. 

```console
$ ./ecc minimal.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli package.json
Runing eBPF program...
```

To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

### runqlat

This program summarizes scheduler run queue latency as a histogram, showing
how long tasks spent waiting their turn to run on-CPU.

```console
$ ./ecc runqlat.bpf.c runqlat.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
$ sudo ./ecli package.json
     (unit)              : count    distribution
         0 -> 1          : 69       |**********************************      |
         2 -> 3          : 58       |*****************************           |
         4 -> 7          : 42       |*********************                   |
         8 -> 15         : 69       |**********************************      |
        16 -> 31         : 80       |****************************************|
        32 -> 63         : 28       |**************                          |
        64 -> 127        : 10       |*****                                   |
       128 -> 255        : 6        |***                                     |
       256 -> 511        : 1        |                                        |
       512 -> 1023       : 1        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 1        |                                        |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 1        |                                        |

$ sudo ./ecli package.json -h
Usage: runqlat_bpf [--help] [--version] [--verbose] [--filter_cg] [--targ_per_process] [--targ_per_thread] [--targ_per_pidns] [--targ_ms] [--targ_tgid VAR]

Summarize run queue (scheduler) latency as a histogram

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filter_cg           set value of bool variable filter_cg 
  --targ_per_process    print a histogram per process ID 
  --targ_per_thread     print a histogram per thread ID 
  --targ_per_pidns      print a histogram per PID namespace 
  --targ_ms             millisecond histogram 
  --targ_tgid           trace this PID only 

Built with eunomia-bpf framework.
```

### opensnoop

Demonstrations of opensnoop, the Linux eBPF/bcc version.

opensnoop traces the open() syscall system-wide, and prints various details.
Example output:

```console
$ sudo ecli package.json -h
Usage: opensnoop_bpf [--help] [--version] [--verbose] [--pid_target VAR] [--tgid_target VAR] [--uid_target VAR] [--failed]

Trace open family syscalls.

Optional arguments:
  -h, --help    shows help message and exits 
  -v, --version prints version information and exits 
  --verbose     prints libbpf debug information 
  --pid_target  Process ID to trace 
  --tgid_target Thread ID to trace 
  --uid_target  User ID to trace 
  -f, --failed  trace only failed events 

Built with eunomia-bpf framework.

$ sudo ecli examples/bpftools/opensnoop/package.json
TIME     TS      PID     UID     RET     FLAGS   COMM    FNAME   
20:31:50  0      1       0       51      524288  systemd /proc/614/cgroup
20:31:50  0      33182   0       25      524288  ecli    /etc/localtime
20:31:53  0      754     0       6       0       irqbalance /proc/interrupts
20:31:53  0      754     0       6       0       irqbalance /proc/stat
20:32:03  0      754     0       6       0       irqbalance /proc/interrupts
20:32:03  0      754     0       6       0       irqbalance /proc/stat
20:32:03  0      632     0       7       524288  vmtoolsd /etc/mtab
20:32:03  0      632     0       9       0       vmtoolsd /proc/devices

$ sudo ecli examples/bpftools/opensnoop/package.json --pid_target 754
TIME     TS      PID     UID     RET     FLAGS   COMM    FNAME   
20:34:13  0      754     0       6       0       irqbalance /proc/interrupts
20:34:13  0      754     0       6       0       irqbalance /proc/stat
20:34:23  0      754     0       6       0       irqbalance /proc/interrupts
20:34:23  0      754     0       6       0       irqbalance /proc/stat
```

## 更多信息

请参考：<https://gitee.com/anolis/eunomia>
