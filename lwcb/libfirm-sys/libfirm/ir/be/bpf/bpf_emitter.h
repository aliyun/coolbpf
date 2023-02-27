/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief    declarations for emit functions
 */
#ifndef FIRM_BE_BPF_BPF_EMITTER_H
#define FIRM_BE_BPF_BPF_EMITTER_H

#include "firm_types.h"
#include <linux/bpf.h>

void bpf_emit_function(ir_graph *irg);


void *bpf_get_bytecode(ir_graph *irg);
int bpf_bytecode_size(ir_graph *irg);


struct bpf_emitter {
    int pos;
    struct bpf_insn insns[4096];

	unsigned short *ret_jmp;
};

#endif
