/**
 * @author Lunqi Zhao (lunqi.zhao@seu.edu.cn), Dian Shen (dshen@seu.edu.cn)
 * @date 2024-10-30
 * @copyright Southeast University Copyright (c) 2022
 */

#ifndef __SIMPLE_RINGBUF_H__
#define __SIMPLE_RINGBUF_H__

#include "enetstl_common.bpf.h"

#define DECLARE_SIMPLE_RINGBUF(_name, _value_type, _size_shift)               \
	struct simple_rbuf__##_name {                                         \
		_value_type data[SHIFT_TO_SIZE((_size_shift))];               \
		__u64 cons;                                                   \
		__u64 prod;                                                   \
	};                                                                    \
	static __always_inline bool _name##__simple_rbuf_full(                \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		return (rb)->prod - (rb)->cons == SHIFT_TO_SIZE(_size_shift); \
	}                                                                     \
	static __always_inline bool _name##__simple_rbuf_empty(               \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		return (rb)->prod == (rb)->cons;                              \
	}                                                                     \
	static __always_inline _value_type *_name##__simple_rbuf_cons(        \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		if (unlikely(_name##__simple_rbuf_empty((rb)))) {             \
			return NULL; /*ringbuf is empty*/                     \
		} else {                                                      \
			return &((rb)->data[BOUND_INDEX((rb)->cons,           \
							(_size_shift))]);     \
		}                                                             \
	}                                                                     \
	static __always_inline void _name##__simple_rbuf_release(             \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		++((rb)->cons);                                               \
	}                                                                     \
	static __always_inline _value_type *_name##__simple_rbuf_prod(        \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		if (unlikely(_name##__simple_rbuf_full((rb)))) {              \
			return NULL; /*ringbuf is full*/                      \
		} else {                                                      \
			return &((rb)->data[BOUND_INDEX((rb)->prod,           \
							(_size_shift))]);     \
		}                                                             \
	}                                                                     \
	static __always_inline void _name##__simple_rbuf_submit(              \
		struct simple_rbuf__##_name *rb)                              \
	{                                                                     \
		++((rb)->prod);                                               \
	}

#endif