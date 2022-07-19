
### 编译 coolbpf go 语言 rexample 流程

## 环境准备
1.本地安装go
2.go版本借助libbpfgo，编译包自动从github引入libbpfgo
## 编译流程
rexample 目录下有相关example，直接执行通过`make`编译生成 go的二进制程序
```bash
# cd lcc/golcc/rexample/hello
# make clean;make
rm -f hello hello.bpf.o
cp /mnt/source/gitee/coolbpf_gitee/lcc/golcc/rexample/hello/bpf/hello.bpf.c /mnt/source/gitee/coolbpf_gitee/lcc/golcc/rexample/hello
coolbpf -f hello.bpf.c -o
remote server compile success.
rm -f /mnt/source/gitee/coolbpf_gitee/lcc/golcc/rexample/hello/hello.bpf.c
CGO_CFLAGS="-I /mnt/source/gitee/coolbpf_gitee/lcc/golcc/rexample/hello/../../include" CGO_LDFLAGS="/mnt/source/gitee/coolbpf_gitee/lcc/golcc/rexample/hello/../../lib/libbpf.a" go build -o hello
```

## 执行结果
```bash
#./hello 
BPF_PROG_TYPE_KPROBE
^C
#cat /sys/kernel/debug/tracing/trace
# tracer: nop
#
# entries-in-buffer/entries-written: 225/225   #P:8
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            java-7155  [000] .... 1221499.060321: 0: hello golcc, parent:85115e00
           <...>-40539 [004] .... 1221499.061255: 0: hello golcc, parent:fb95de00
           <...>-40539 [004] .... 1221499.061366: 0: hello golcc, parent:fb958000
           <...>-40539 [004] .... 1221499.061450: 0: hello golcc, parent:fb95c680
            java-7176  [004] .... 1221499.068765: 0: hello golcc, parent:fb95af00
      staragentd-3603  [007] .... 1221499.142273: 0: hello golcc, parent:b94f4680
         systemd-1     [003] .... 1221499.145939: 0: hello golcc, parent:8bcb5e00
```
## libbpf 版本更新
从github仓库下载最新版本，更新.h头文件和libbpf.a库
https://github.com/libbpf/libbpf.git
```bash
$ cd libbpf/src
$ make install
$ cp /usr/include/bpf/* golcc/include/bpf/
$ cp /usr/lib64/libbpf.a golcc/lib/
```
## libbpfgo 版本更新
编辑 golcc/rexample/hello/go.mod 替换 libbpfgo 版本号
```bash
$cat lcc/golcc/rexample/hello/go.mod
module hello

go 1.17

require github.com/aquasecurity/libbpfgo v0.3.0-libbpf-0.8.0

require golang.org/x/sys v0.0.0-20210514084401-e8d321eab015 // indirect
```
版本号说明：v0.3.0 是libbpfgo的版本号，0.8.0 是对应libbpf的版本号，两个需要配套，否则可能会出现兼容性问题