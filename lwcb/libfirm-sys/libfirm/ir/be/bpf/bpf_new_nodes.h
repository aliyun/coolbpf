/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   Function prototypes for the assembler ir node constructors.
 */
#ifndef FIRM_BE_BPF_BPF_NEW_NODES_H
#define FIRM_BE_BPF_BPF_NEW_NODES_H

#include "bpf_nodes_attr.h"

/**
 * Returns the attributes of an bpf node.
 */
bpf_attr_t *get_bpf_attr(ir_node *node);

const bpf_attr_t *get_bpf_attr_const(const ir_node *node);


const bpf_bswap_attr_t *get_bpf_bswap_attr_const(const ir_node *node);
const bpf_condjmp_attr_t *get_bpf_condjmp_attr_const(const ir_node *node);
const bpf_cmp_attr_t *get_bpf_cmp_attr_const(const ir_node *node);
bpf_load_attr_t *get_bpf_load_attr(const ir_node *node);
const bpf_const_attr_t *get_bpf_const_attr_const(const ir_node *node);
const bpf_call_attr_t *get_bpf_call_attr_const(const ir_node *node);
const bpf_store_attr_t *get_bpf_store_attr_const(const ir_node *node);
const bpf_store_attr_t *get_bpf_load_attr_const(const ir_node *node);
const bpf_member_attr_t *get_bpf_member_attr_const(const ir_node *node);

/* Include the generated headers */
#include "gen_bpf_new_nodes.h"

#endif
