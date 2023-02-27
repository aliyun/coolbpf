/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   This file implements the creation of the achitecture specific firm
 *          opcodes and the coresponding node constructors for the bpf
 *          assembler irg.
 */
#include "bpf_new_nodes_t.h"

#include "bpf_nodes_attr.h"
#include "bedump.h"
#include "gen_bpf_regalloc_if.h"
#include "ircons_t.h"
#include "irgraph_t.h"
#include "irmode_t.h"
#include "irnode_t.h"
#include "irop_t.h"
#include "iropt_t.h"
#include "irprintf.h"
#include "irprog_t.h"
#include "xmalloc.h"
#include <stdlib.h>

bool bpf_has_load_store_attr(const ir_node *node)
{
	return is_bpf_Load(node) || is_bpf_Store(node);
}

void bpf_dump_node(FILE *F, const ir_node *n, dump_reason_t reason)
{
	switch (reason) {
	case dump_node_opcode_txt:
		fprintf(F, "%s", get_irn_opname(n));
		break;

	case dump_node_mode_txt:
		break;

	case dump_node_nodeattr_txt:

		/* TODO: dump some attributes which should show up */
		/* in node name in dump (e.g. consts or the like)  */

		break;

	case dump_node_info_txt:
		break;
	}
}

void bpf_set_imm_attr(ir_node *res, int32_t imm)
{
	bpf_imm_attr_t *attr = (bpf_imm_attr_t *)get_irn_generic_attr(res);
	attr->imm32 = imm;
	arch_add_irn_flags(res, (arch_irn_flags_t)bpf_arch_irn_flag_immediate_form);
}

void init_bpf_bswap_attr(ir_node *res, uint8_t type, uint8_t size)
{
	bpf_bswap_attr_t *attr = (bpf_bswap_attr_t *)get_irn_generic_attr(res);
	attr->type = type;
	attr->size = size;
}

void init_bpf_condjmp_attr(ir_node *res, ir_relation relation)
{
	bpf_condjmp_attr_t *attr = (bpf_condjmp_attr_t *)get_irn_generic_attr(res);
	attr->relation = relation;
}

void init_bpf_cmp_attr(ir_node *res, int32_t imm32, bool is_imm)
{
	bpf_cmp_attr_t *attr = (bpf_const_attr_t *)get_irn_generic_attr(res);
	attr->imm32 = imm32;
	attr->is_imm = is_imm;
}

void init_bpf_const_attr(ir_node *res, int64_t value, ir_mode *mode, int is_mapfd)
{
	bpf_const_attr_t *attr = (bpf_const_attr_t *)get_irn_generic_attr(res);
	attr->value = value;
	attr->mode = mode;
	attr->is_mapfd = is_mapfd;
}

void init_bpf_call_attr(ir_node *res, ir_entity *entity, int32_t func_id)
{
	bpf_call_attr_t *attr = (bpf_call_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->func_id = func_id;
}

void init_bpf_mapfd_attr(ir_node *res, int32_t fd)
{
	bpf_mapfd_attr_t *attr = (bpf_mapfd_attr_t *)get_irn_generic_attr(res);
	attr->fd = fd;
}

void init_bpf_member_attr(ir_node *res, ir_entity *entity, int32_t offset)
{
	bpf_member_attr_t *attr = (bpf_member_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->offset = offset;
}

void init_bpf_load_attr(ir_node *res, ir_entity *entity, ir_mode *mode, int16_t offset, bool is_frame_entity)
{
	bpf_load_attr_t *attr = (bpf_load_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->mode = mode;
	attr->offset = offset;
	attr->is_frame_entity = is_frame_entity;
}

void init_bpf_store_attr(ir_node *res, ir_entity *entity, ir_mode *mode, int16_t offset, bool is_frame_entity)
{
	bpf_store_attr_t *attr = (bpf_store_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->offset = offset;
	attr->mode = mode;
	attr->is_frame_entity = is_frame_entity;
}

bpf_load_store_attr_t *get_bpf_load_store_attr(ir_node *node)
{
	assert(bpf_has_load_store_attr(node));
	return (bpf_load_store_attr_t*) get_irn_generic_attr_const(node);
}

void init_bpf_load_store_attributes(ir_node *res, uint16_t offset, int32_t imm, bool is_imm)
{
	bpf_load_store_attr_t *attr     = get_bpf_load_store_attr(res);
	attr->imm = imm;
	attr->is_imm = is_imm;
	attr->offset = offset;
}

const bpf_attr_t *get_bpf_attr_const(const ir_node *node)
{
	assert(is_bpf_irn(node) && "need bpf node to get attributes");
	return (const bpf_attr_t *)get_irn_generic_attr_const(node);
}

bpf_attr_t *get_bpf_attr(ir_node *node)
{
	assert(is_bpf_irn(node) && "need bpf node to get attributes");
	return (bpf_attr_t *)get_irn_generic_attr(node);
}

void set_bpf_value(ir_node *const node, ir_entity *const entity,
                        ir_tarval *const value)
{
	(void)node;
	(void)value;
	(void)entity;
	
	// bpf_attr_t *attr = get_bpf_attr(node);
	// attr->entity = entity;
	// attr->value  = value;
}

int bpf_attrs_equal(const ir_node *a, const ir_node *b)
{
	(void)a;
	(void)b;
	// const bpf_attr_t *attr_a = get_bpf_attr_const(a);
	// const bpf_attr_t *attr_b = get_bpf_attr_const(b);
	// return attr_a->value == attr_b->value
	//     && attr_a->entity == attr_b->entity;
	return 0;
}


int bpf_bswap_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_bswap_attr_t *attr_a = (bpf_bswap_attr_t *)get_irn_generic_attr(a);
	const bpf_bswap_attr_t *attr_b = (bpf_bswap_attr_t *)get_irn_generic_attr(b);
	return attr_a->type == attr_b->type && attr_a->size == attr_b->size;
}

int bpf_condjmp_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_condjmp_attr_t *attr_a = (bpf_condjmp_attr_t *)get_irn_generic_attr(a);
	const bpf_condjmp_attr_t *attr_b = (bpf_condjmp_attr_t *)get_irn_generic_attr(b);
	return attr_a->relation == attr_b->relation;
}

int bpf_cmp_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_cmp_attr_t *attr_a = (bpf_cmp_attr_t *)get_irn_generic_attr(a);
	const bpf_cmp_attr_t *attr_b = (bpf_cmp_attr_t *)get_irn_generic_attr(b);

	return attr_a->imm32 == attr_b->imm32 && attr_a->is_imm == attr_b->is_imm;
}

int bpf_const_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_const_attr_t *attr_a = (bpf_const_attr_t *)get_irn_generic_attr(a);
	const bpf_const_attr_t *attr_b = (bpf_const_attr_t *)get_irn_generic_attr(b);

	return attr_a->value == attr_b->value && attr_a->mode == attr_b->mode;
}

int bpf_call_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_call_attr_t *attr_a = (bpf_call_attr_t *)get_irn_generic_attr(a);
	const bpf_call_attr_t *attr_b = (bpf_call_attr_t *)get_irn_generic_attr(b);
	return attr_a->func_id == attr_b->func_id && attr_a->entity == attr_b->entity;
}

int bpf_mapfd_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_mapfd_attr_t *attr_a = (bpf_mapfd_attr_t *)get_irn_generic_attr(a);
	const bpf_mapfd_attr_t *attr_b = (bpf_mapfd_attr_t *)get_irn_generic_attr(b);
	return attr_a->fd == attr_b->fd;
}

int bpf_member_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_load_attr_t *attr_a = (bpf_load_attr_t *)get_irn_generic_attr(a);
	const bpf_load_attr_t *attr_b = (bpf_load_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset;
}

int bpf_load_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_load_attr_t *attr_a = (bpf_load_attr_t *)get_irn_generic_attr(a);
	const bpf_load_attr_t *attr_b = (bpf_load_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset && attr_a->mode == attr_b->mode;
}

const bpf_bswap_attr_t *get_bpf_bswap_attr_const(const ir_node *node)
{
	return (const bpf_bswap_attr_t *)get_irn_generic_attr_const(node);
}

const bpf_condjmp_attr_t *get_bpf_condjmp_attr_const(const ir_node *node)
{
	return (const bpf_condjmp_attr_t*) get_irn_generic_attr_const(node);
}

const bpf_cmp_attr_t *get_bpf_cmp_attr_const(const ir_node *node)
{
	return (const bpf_cmp_attr_t*) get_irn_generic_attr_const(node);
}

int bpf_store_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_store_attr_t *attr_a = (bpf_store_attr_t *)get_irn_generic_attr(a);
	const bpf_store_attr_t *attr_b = (bpf_store_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset && attr_a->mode == attr_b->mode;
}

const bpf_const_attr_t *get_bpf_const_attr_const(const ir_node *node)
{
	return (const bpf_const_attr_t*) get_irn_generic_attr_const(node);
}

const bpf_call_attr_t *get_bpf_call_attr_const(const ir_node *node)
{
	return (const bpf_call_attr_t*) get_irn_generic_attr_const(node);
}

const bpf_store_attr_t *get_bpf_store_attr_const(const ir_node *node)
{
	return (const bpf_store_attr_t*) get_irn_generic_attr_const(node);
}

bpf_load_attr_t *get_bpf_load_attr(const ir_node *node)
{
	return (bpf_load_attr_t*) get_irn_generic_attr(node);
}

const bpf_store_attr_t *get_bpf_load_attr_const(const ir_node *node)
{
	return (const bpf_load_attr_t*) get_irn_generic_attr_const(node);
}

const bpf_member_attr_t *get_bpf_member_attr_const(const ir_node *node)
{
	return (const bpf_member_attr_t*) get_irn_generic_attr_const(node);
}