/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   declarations for bpf backend -- private header
 */
#ifndef FIRM_BE_BPF_BPF_BEARCH_T_H
#define FIRM_BE_BPF_BPF_BEARCH_T_H

#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>

#include "beirg.h"
#include "firm_types.h"
#include "pmap.h"


typedef struct bpf_irg_data_t bpf_irg_data_t;

struct bpf_irg_data_t {
    struct bpf_insn insns[4096];
    int pos;
    unsigned short *ret_jmp;
};

void bpf_finish_graph(ir_graph *irg);

#endif
