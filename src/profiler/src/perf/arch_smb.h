#ifndef __ARCH_SMB_H_
#define __ARCH_SMB_H_

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long s64;
typedef int s32;
typedef short s16;
typedef char s8;

#if defined(__i386__)
typedef u32 regs_t;
#include "perf_x86_regs.h"
#define PERF_REG_IP PERF_REG_X86_IP
#define PERF_REG_SP PERF_REG_X86_SP
#define PERF_REG_IP_INDEX (1)
#define PERF_REG_SP_INDEX (0)
#define mb() asm volatile("lock; addl $0,0(%%esp)" :: : "memory")
#define wmb() asm volatile("lock; addl $0,0(%%esp)" :: : "memory")
#define rmb() asm volatile("lock; addl $0,0(%%esp)" :: : "memory")
#define cpu_relax() asm volatile("rep; nop" :: : "memory");
#define CPUINFO_PROC "model name"
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 336
#endif
#endif

#if defined(__x86_64__)
typedef u64 regs_t;
#include "perf_x86_regs.h"
#define PERF_REG_IP PERF_REG_X86_IP
#define PERF_REG_SP PERF_REG_X86_SP
#define PERF_REG_FP PERF_REG_X86_BP
#define PERF_REG_IP_INDEX (2)
#define PERF_REG_SP_INDEX (1)
#define PERF_REG_FP_INDEX (0)
#define mb() asm volatile("mfence" :: : "memory")
#define wmb() asm volatile("sfence" :: : "memory")
#define rmb() asm volatile("lfence" :: : "memory")
#define cpu_relax() asm volatile("rep; nop" :: : "memory");
#define CPUINFO_PROC "model name"
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif
#define PERF_REG_MASK ((1ULL << PERF_REG_FP)|(1ULL << PERF_REG_IP) | (1ULL << PERF_REG_SP) | (1 << PERF_REG_X86_AX) | (1 << PERF_REG_X86_R9) | (1 << PERF_REG_X86_R11) | (1 << PERF_REG_X86_R13) | (1 << PERF_REG_X86_R15))
#define PERF_MAX_REGS   8
#endif

#ifdef __aarch64__
typedef u64 regs_t;
#include "perf_aarch64_regs.h"
#define PERF_REG_IP PERF_REG_ARM64_PC
#define PERF_REG_SP PERF_REG_ARM64_SP
#define PERF_REG_FP PERF_REG_ARM64_X29
#define PERF_REG_IP_INDEX (2)
#define PERF_REG_SP_INDEX (1)
#define PERF_REG_FP_INDEX (0)
#define mb() asm volatile("dmb ish" :: : "memory")
#define wmb() asm volatile("dmb ishst" :: : "memory")
#define rmb() asm volatile("dmb ishld" :: : "memory")
#define cpu_relax() asm volatile("yield" :: : "memory")
#define PERF_REG_MASK ((1ULL << PERF_REG_FP)|(1ULL << PERF_REG_IP) | (1ULL << PERF_REG_SP) | (1 << PERF_REG_ARM64_LR) | (1 << PERF_REG_ARM64_X22))
#define PERF_MAX_REGS   5
#endif


#define barrier() asm volatile("" :: : "memory")

#ifndef cpu_relax
#define cpu_relax() barrier()
#endif

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define PERF_UNWIND_REG_IP PERF_REG_IP
#define PERF_UNWIND_REG_SP PERF_REG_SP
#define PERF_UNWIND_REG_FP PERF_REG_FP

// #define PERF_REG_MASK ((1ULL << PERF_REG_FP)|(1ULL << PERF_REG_IP) | (1ULL << PERF_REG_SP))
// #define PERF_MAX_REGS   3

#endif
