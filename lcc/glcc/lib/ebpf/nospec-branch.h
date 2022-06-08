/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NOSPEC_BRANCH_H__
#define __NOSPEC_BRANCH_H__

#include <asm/alternative.h>
#include <asm/alternative-asm.h>
// #include <asm/cpufeatures.h>
#include <asm/bitsperlong.h>
#include <asm/percpu.h>
#include <asm/nops.h>
#include <asm/jump_label.h>

/*
 * Fill the CPU return stack buffer.
 *
 * Each entry in the RSB, if used for a speculative 'ret', contains an
 * infinite 'pause; lfence; jmp' loop to capture speculative execution.
 *
 * This is required in various cases for retpoline and IBRS-based
 * mitigations for the Spectre variant 2 vulnerability. Sometimes to
 * eliminate potentially bogus entries from the RSB, and sometimes
 * purely to ensure that it doesn't get empty, which on some CPUs would
 * allow predictions from other (unwanted!) sources to be used.
 *
 * We define a CPP macro such that it can be used from both .S files and
 * inline assembly. It's possible to do a .macro and then include that
 * from C via asm(".include <asm/nospec-branch.h>") but let's not go there.
 */

#define RSB_CLEAR_LOOPS		32	/* To forcibly overwrite all entries */
#define RSB_FILL_LOOPS		16	/* To avoid underflow */

/*
 * Google experimented with loop-unrolling and this turned out to be
 * the optimal version — two calls, each with their own speculation
 * trap should their return address end up getting used, in a loop.
 */
#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	call	772f;				\
773:	/* speculation trap */			\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	call	774f;				\
775:	/* speculation trap */			\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	dec	reg;				\
	jnz	771b;				\
	add	$(BITS_PER_LONG/8) * nr, sp;

#ifdef __ASSEMBLY__

 /*
  * A simpler FILL_RETURN_BUFFER macro. Don't make people use the CPP
  * monstrosity above, manually.
  */
.macro FILL_RETURN_BUFFER_CLOBBER reg=%rax
	661: __FILL_RETURN_BUFFER(\reg, RSB_CLEAR_LOOPS, %_ASM_SP); 662:
	.pushsection .altinstr_replacement, "ax"
	663: ASM_NOP8; ASM_NOP8; ASM_NOP8; ASM_NOP8; ASM_NOP8; ASM_NOP3; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, X86_FEATURE_SMEP, 662b-661b, 664b-663b
	.popsection
.endm

.macro FILL_RETURN_BUFFER
	push %rax
	FILL_RETURN_BUFFER_CLOBBER reg=%rax
	pop %rax
.endm

/*
 * These are the bare retpoline primitives for indirect jmp and call.
 * Do not use these directly; they only exist to make the ALTERNATIVE
 * invocation below less ugly.
 */
.macro RETPOLINE_JMP reg:req
	call	.Ldo_rop_\@
.Lspec_trap_\@:
	pause
	lfence
	jmp	.Lspec_trap_\@
.Ldo_rop_\@:
	mov	\reg, (%_ASM_SP)
	ret
.endm

/*
 * This is a wrapper around RETPOLINE_JMP so the called function in reg
 * returns to the instruction after the macro.
 */
.macro RETPOLINE_CALL reg:req
	jmp	.Ldo_call_\@
.Ldo_retpoline_jmp_\@:
	RETPOLINE_JMP \reg
.Ldo_call_\@:
	call	.Ldo_retpoline_jmp_\@
.endm

.macro __JMP_NOSPEC reg:req
	661: RETPOLINE_JMP \reg; 662:
	.pushsection .altinstr_replacement, "ax"
	663: lfence; jmp *\reg; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, X86_FEATURE_RETPOLINE_AMD, 662b-661b, 664b-663b
	.popsection
.endm

.macro __CALL_NOSPEC reg:req
	661: RETPOLINE_CALL \reg; 662:
	.pushsection .altinstr_replacement, "ax"
	663: lfence; call *\reg; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, X86_FEATURE_RETPOLINE_AMD, 662b-661b, 664b-663b
	.popsection
.endm

/*
 * JMP_NOSPEC and CALL_NOSPEC macros can be used instead of a simple
 * indirect jmp/call which may be susceptible to the Spectre variant 2
 * attack.
 */
.macro JMP_NOSPEC reg:req
	STATIC_JUMP .Lretp_\@, retp_enabled_key
	jmp *\reg

.Lretp_\@:
	__JMP_NOSPEC \reg
.endm

.macro CALL_NOSPEC reg:req
	STATIC_JUMP .Lretp_\@, retp_enabled_key
	call *\reg
	jmp	.Ldone_\@

.Lretp_\@:
	__CALL_NOSPEC \reg

.Ldone_\@:
.endm

/*
 * MDS_USER_CLEAR_CPU_BUFFERS macro is the assembly equivalent of
 * mds_user_clear_cpu_buffers(). Like the C version, the __KERNEL_DS
 * is used for verw.
 * Note: The ZF flag will be clobbered after calling this macro.
 */
.macro MDS_USER_CLEAR_CPU_BUFFERS
	STATIC_JUMP .Lverw_\@, mds_user_clear
	jmp	.Ldone_\@
	.balign 2
.Lds_\@:
	.word	__KERNEL_DS
.Lverw_\@:
	verw	.Lds_\@(%rip)
.Ldone_\@:
.endm

#else /* __ASSEMBLY__ */

#if defined(CONFIG_X86_64) && defined(RETPOLINE)
/*
 * Since the inline asm uses the %V modifier which is only in newer GCC,
 * the 64-bit one is dependent on RETPOLINE not CONFIG_RETPOLINE.
 */
#define CALL_NOSPEC						\
	"call __x86_indirect_thunk_%V[thunk_target]\n"
#define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#else /* No retpoline for C / inline asm */
# define CALL_NOSPEC "call *%[thunk_target]\n"
# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif

/* The Spectre V2 mitigation variants */
enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_RETPOLINE_MINIMAL,
	SPECTRE_V2_RETPOLINE_NO_IBPB,
	SPECTRE_V2_RETPOLINE_UNSAFE_MODULE,
	SPECTRE_V2_RETPOLINE,
	SPECTRE_V2_RETPOLINE_IBRS_USER,
	SPECTRE_V2_IBRS,
	SPECTRE_V2_IBRS_ALWAYS,
	SPECTRE_V2_IBP_DISABLED,
	SPECTRE_V2_IBRS_ENHANCED,
};

extern enum spectre_v2_mitigation spectre_v2_enabled;

void __spectre_v2_select_mitigation(void);
void spectre_v2_print_mitigation(void);

static inline bool retp_compiler(void)
{
#ifdef RETPOLINE
	return true;
#else
	return false;
#endif
}

/*
 * The Intel specification for the SPEC_CTRL MSR requires that we
 * preserve any already set reserved bits at boot time (e.g. for
 * future additions that this kernel is not currently aware of).
 * We then set any additional mitigation bits that we want
 * ourselves and always use this as the base for SPEC_CTRL.
 * We also use this when handling guest entry/exit as below.
 */
extern u64 x86_spec_ctrl_base;

/* The Speculative Store Bypass disable variants */
enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE,
	SPEC_STORE_BYPASS_DISABLE,
	SPEC_STORE_BYPASS_PRCTL,
	SPEC_STORE_BYPASS_SECCOMP,
};

/* AMD specific Speculative Store Bypass MSR data */
extern u64 x86_amd_ls_cfg_base;
extern u64 x86_amd_ls_cfg_ssbd_mask;

/*
 * On VMEXIT we must ensure that no RSB predictions learned in the guest
 * can be followed in the host, by overwriting the RSB completely. Both
 * retpoline and IBRS mitigations for Spectre v2 need this; only on future
 * CPUs with IBRS_ATT *might* it be avoided.
 */
static inline void fill_RSB(void)
{
	unsigned long loops;
	register unsigned long sp asm(_ASM_SP);

	asm volatile (__stringify(__FILL_RETURN_BUFFER(%0, RSB_CLEAR_LOOPS, %1))
		      : "=r" (loops), "+r" (sp)
		      : : "memory" );
}

extern struct static_key mds_user_clear;
extern struct static_key mds_idle_clear;

#include <asm/segment.h>

/**
 * mds_clear_cpu_buffers - Mitigation for MDS vulnerability
 *
 * This uses the otherwise unused and obsolete VERW instruction in
 * combination with microcode which triggers a CPU buffer flush when the
 * instruction is executed.
 */
static inline void mds_clear_cpu_buffers(void)
{
	static const u16 ds = __KERNEL_DS;

	/*
	 * Has to be the memory-operand variant because only that
	 * guarantees the CPU buffer flush functionality according to
	 * documentation. The register-operand variant does not.
	 * Works with any segment selector, but a valid writable
	 * data segment is the fastest variant.
	 *
	 * "cc" clobber is required because VERW modifies ZF.
	 */
	asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}

/**
 * mds_user_clear_cpu_buffers - Mitigation for MDS vulnerability
 *
 * Clear CPU buffers if the corresponding static key is enabled
 *
 * RHEL7: This inline function from upstream isn't being used. The
 * equivalent MDS_USER_CLEAR_CPU_BUFFERS assembly macro is used in
 * the entry code to achieve the same effect.
 */
static inline void mds_user_clear_cpu_buffers(void)
{
	if (static_key_false(&mds_user_clear))
		mds_clear_cpu_buffers();
}

/**
 * mds_idle_clear_cpu_buffers - Mitigation for MDS vulnerability
 *
 * Clear CPU buffers if the corresponding static key is enabled
 */
static inline void mds_idle_clear_cpu_buffers(void)
{
	if (static_key_false(&mds_idle_clear))
		mds_clear_cpu_buffers();
}

#endif /* __ASSEMBLY__ */

/*
 * Below is used in the eBPF JIT compiler and emits the byte sequence
 * for the following assembly:
 *
 * With retpolines configured:
 *
 *    callq do_rop
 *  spec_trap:
 *    pause
 *    lfence
 *    jmp spec_trap
 *  do_rop:
 *    mov %rax,(%rsp)
 *    retq
 *
 * Without retpolines configured:
 *
 *    jmp *%rax
 */
#ifdef CONFIG_RETPOLINE
# define RETPOLINE_RAX_BPF_JIT_SIZE	17
# define RETPOLINE_RAX_BPF_JIT()				\
	EMIT1_off32(0xE8, 7);	 /* callq do_rop */		\
	/* spec_trap: */					\
	EMIT2(0xF3, 0x90);       /* pause */			\
	EMIT3(0x0F, 0xAE, 0xE8); /* lfence */			\
	EMIT2(0xEB, 0xF9);       /* jmp spec_trap */		\
	/* do_rop: */						\
	EMIT4(0x48, 0x89, 0x04, 0x24); /* mov %rax,(%rsp) */	\
	EMIT1(0xC3);             /* retq */
#else
# define RETPOLINE_RAX_BPF_JIT_SIZE	2
# define RETPOLINE_RAX_BPF_JIT()				\
	EMIT2(0xFF, 0xE0);	 /* jmp *%rax */
#endif

#endif /* __NOSPEC_BRANCH_H__ */
