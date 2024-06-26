/* bpf_jit.S : BPF JIT helper functions
 *
 * Copyright (C) 2011 Eric Dumazet (eric.dumazet@gmail.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#include <linux/linkage.h>
#include "bpf_frame.h"

/*
 * Calling convention :
 * rbx : skb pointer (callee saved)
 * esi : offset of byte(s) to fetch in skb (can be scratched)
 * r10 : copy of skb->data
 * r9d : hlen = skb->len - skb->data_len
 */
#define SKBDATA	%r10
#define SKF_MAX_NEG_OFF    $(-0x200000) /* SKF_LL_OFF from filter.h */

#define FUNC(name) \
	.globl name; \
	.type name, @function; \
	name:

FUNC(trace_sk_load_word)
	test	%esi,%esi
	js	bpf_slow_path_word_neg

FUNC(trace_sk_load_word_positive_offset)
	mov	%r9d,%eax		# hlen
	sub	%esi,%eax		# hlen - offset
	cmp	$3,%eax
	jle	bpf_slow_path_word
	mov     (SKBDATA,%rsi),%eax
	bswap   %eax  			/* ntohl() */
	ret

FUNC(trace_sk_load_half)
	test	%esi,%esi
	js	bpf_slow_path_half_neg

FUNC(trace_sk_load_half_positive_offset)
	mov	%r9d,%eax
	sub	%esi,%eax		#	hlen - offset
	cmp	$1,%eax
	jle	bpf_slow_path_half
	movzwl	(SKBDATA,%rsi),%eax
	rol	$8,%ax			# ntohs()
	ret

FUNC(trace_sk_load_byte)
	test	%esi,%esi
	js	bpf_slow_path_byte_neg

FUNC(trace_sk_load_byte_positive_offset)
	cmp	%esi,%r9d   /* if (offset >= hlen) goto bpf_slow_path_byte */
	jle	bpf_slow_path_byte
	movzbl	(SKBDATA,%rsi),%eax
	ret

/* rsi contains offset and can be scratched */
#define bpf_slow_path_common(LEN)		\
	lea	32(%rbp), %rdx;\
	FRAME_BEGIN;				\
	mov	%rbx, %rdi; /* arg1 == skb */	\
	push	%r9;				\
	push	SKBDATA;			\
/* rsi already has offset */			\
	mov	$LEN,%ecx;	/* len */	\
	call	skb_copy_bits;			\
	test    %eax,%eax;			\
	pop	SKBDATA;			\
	pop	%r9;				\
	FRAME_END


bpf_slow_path_word:
	bpf_slow_path_common(4)
	js	bpf_error
	mov	32(%rbp),%eax
	bswap	%eax
	ret

bpf_slow_path_half:
	bpf_slow_path_common(2)
	js	bpf_error
	mov	32(%rbp),%ax
	rol	$8,%ax
	movzwl	%ax,%eax
	ret

bpf_slow_path_byte:
	bpf_slow_path_common(1)
	js	bpf_error
	movzbl	32(%rbp),%eax
	ret

#define sk_negative_common(SIZE)				\
	FRAME_BEGIN;						\
	mov	%rbx, %rdi; /* arg1 == skb */			\
	push	%r9;						\
	push	SKBDATA;					\
/* rsi already has offset */					\
	mov	$SIZE,%edx;	/* size */			\
	call	trace_bpf_internal_load_pointer_neg_helper;	\
	test	%rax,%rax;					\
	pop	SKBDATA;					\
	pop	%r9;						\
	FRAME_END;						\
	jz	bpf_error

bpf_slow_path_word_neg:
	cmp	SKF_MAX_NEG_OFF, %esi	/* test range */
	jl	bpf_error	/* offset lower -> error  */

FUNC(trace_sk_load_word_negative_offset)
	sk_negative_common(4)
	mov	(%rax), %eax
	bswap	%eax
	ret

bpf_slow_path_half_neg:
	cmp	SKF_MAX_NEG_OFF, %esi
	jl	bpf_error

FUNC(trace_sk_load_half_negative_offset)
	sk_negative_common(2)
	mov	(%rax),%ax
	rol	$8,%ax
	movzwl	%ax,%eax
	ret

bpf_slow_path_byte_neg:
	cmp	SKF_MAX_NEG_OFF, %esi
	jl	bpf_error

FUNC(trace_sk_load_byte_negative_offset)
	sk_negative_common(1)
	movzbl	(%rax), %eax
	ret

bpf_error:
# force a return 0 from jit handler
	xor	%eax,%eax
	mov	(%rbp),%rbx
	mov	8(%rbp),%r13
	mov	16(%rbp),%r14
	mov	24(%rbp),%r15
	add	$40, %rbp
	leaveq
	ret
