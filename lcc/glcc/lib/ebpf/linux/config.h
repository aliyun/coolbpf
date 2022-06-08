#ifndef __EBPF_LINUX_CONFIG_H
#define __EBPF_LINUX_CONFIG_H


static int bpf_jit_enable = 1;

#define CONFIG_BPF_JIT_ALWAYS_ON
#define CONFIG_HAVE_EBPF_JIT

// /work/lcc/lib/ebpf/linux/config.h:5:0: warning: "CONFIG_BPF_JIT" redefined [enabled by default]
//  #define CONFIG_BPF_JIT
//  ^
// In file included from /usr/src/kernels/3.10.0-327.ali2017.alios7.x86_64/include/linux/kconfig.h:4:0,
//                  from <command-line>:0:
// include/generated/autoconf.h:2461:0: note: this is the location of the previous definition
//  #define CONFIG_BPF_JIT 1
// #define CONFIG_BPF_JIT

#define DEBUG_LINE printk("%s:%d:1 fun:%s\n", __FILE__ ,__LINE__, __FUNCTION__)

#endif
