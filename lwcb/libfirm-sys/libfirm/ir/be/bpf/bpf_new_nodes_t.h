/*
 * This file is part of libFirm.
 * Copyright (C) 2016 Matthias Braun
 */

/**
 * @file
 * @brief   Internal declarations used by gen_new_nodes.c
 */
#ifndef FIRM_BE_BPF_BPF_NEW_NODES_T_H
#define FIRM_BE_BPF_BPF_NEW_NODES_T_H

#include "bpf_new_nodes.h"

void bpf_dump_node(FILE *F, const ir_node *n, dump_reason_t reason);

void set_bpf_value(ir_node *const node, ir_entity *const entity,
                        ir_tarval *const value);

int bpf_attrs_equal(const ir_node *a, const ir_node *b);


void bpf_set_imm_attr(ir_node *res, int32_t imm);
void init_bpf_load_store_attributes(ir_node *res, uint16_t offset, int32_t imm, bool is_imm);

void init_bpf_bswap_attr(ir_node *res, uint8_t type, uint8_t size);
void init_bpf_condjmp_attr(ir_node *res, ir_relation relation);
void init_bpf_cmp_attr(ir_node *res, int32_t imm32, bool is_imm);
void init_bpf_const_attr(ir_node *res, int64_t value, ir_mode *mode, int is_mapfd);
void init_bpf_call_attr(ir_node *res, ir_entity *entity, int32_t func_id);
void init_bpf_mapfd_attr(ir_node *res, int32_t offset);
void init_bpf_member_attr(ir_node *res, ir_entity *entity, int32_t offset);
void init_bpf_load_attr(ir_node *res, ir_entity *entity, ir_mode *mode, int16_t offset, bool is_frame_entity);
void init_bpf_store_attr(ir_node *res, ir_entity *entity, ir_mode *mode, int16_t offset, bool is_frame_entity);

int bpf_bswap_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_condjmp_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_cmp_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_const_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_call_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_mapfd_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_member_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_load_attrs_equal(const ir_node *a, const ir_node *b);
int bpf_store_attrs_equal(const ir_node *a, const ir_node *b);

bpf_load_store_attr_t *get_bpf_load_store_attr(ir_node *res);

#endif
