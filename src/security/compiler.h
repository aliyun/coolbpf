//
// Created by qianlu on 2024/6/16.
//

#ifndef SYSAK_COMPILER_H
#define SYSAK_COMPILER_H

#ifdef __V61_BPF_PROG
#define FUNC_LOCAL  static __attribute__((noinline)) __attribute__((__unused__))
#define FUNC_INLINE static inline __attribute__((always_inline))
#else
/* Older kernels have all functions inlined.  */
#define FUNC_LOCAL  static inline __attribute__((always_inline))
#define FUNC_INLINE static inline __attribute__((always_inline))
#endif

#endif //SYSAK_COMPILER_H
