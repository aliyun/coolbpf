/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef COOLBPF_KALLSYMS_H
#define COOLBPF_KALLSYMS_H

#include <stdbool.h>
#include "coolbpf_common.h"

/**
 * @brief kernel symbol
 *
 */
struct ksym
{
    const char *name;   /**< the name of kernel symbol */
    unsigned long addr; /**< the memory address of kernel symbol */
};

struct ksyms;

/**
 * @brief load kernel symbols from /proc/kallsyms
 *
 * @return struct ksyms*
 */
COOLBPF_API struct ksyms *ksyms__load(void);

/**
 * @brief release ksyms memory
 *
 * @param ksyms ksyms object
 */
COOLBPF_API void ksyms__free(struct ksyms *ksyms);

/**
 * @brief find kernel symbol by memory address
 *
 * @param ksyms ksyms object
 * @param addr memory address
 * @return const struct ksym*
 */
COOLBPF_API const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
                                   unsigned long addr);

/**
 * @brief find kernel symbol by symbol name
 *
 * @param ksyms
 * @param name
 * @return const struct ksym*
 */
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
                                     const char *name);
#endif /* __TRACE_HELPERS_H */
