/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief    Peephole optimization and legalization of a SPARC function
 * @author   Matthias Braun
 *
 * A note on SPARC stack pointer (sp) behavior:
 * The ABI expects SPARC_MIN_STACKSIZE bytes to be available at the
 * stack pointer. This space will be used to spill register windows,
 * and for spilling va_arg arguments (maybe we can optimize this away for
 * statically known not-va-arg-functions...)
 * This in effect means that we allocate that extra space at the function begin
 * which is easy. But this space isn't really fixed at the beginning of the
 * stack frame. Instead you should rather imagine the space as always being the
 * last-thing on the stack.
 * So when addressing anything stack-specific we have to account for this
 * area, while our compiler thinks the space is occupied at the beginning
 * of the stack frame. The code here among other things adjusts these offsets
 * accordingly.
 */
#include "be2addr.h"
#include "beirg.h"
#include "benode.h"
#include "bepeephole.h"
#include "besched.h"
#include "bespillslots.h"
#include "bestack.h"
#include "beutil.h"
#include "gen_bpf_regalloc_if.h"
#include "heights.h"
#include "ircons.h"
#include "iredges_t.h"
#include "irgmod.h"
#include "irgwalk.h"
#include "irprog.h"
#include "panic.h"
#include "bpf_bearch_t.h"
#include "bpf_new_nodes.h"
#include "bpf_transform.h"
#include "util.h"

static ir_heights_t *heights;


static bool is_frame_load(const ir_node *node)
{
	return is_bpf_Load(node);
}

static void bpf_collect_frame_entity_nodes(ir_node *node, void *data)
{
	be_fec_env_t *env = (be_fec_env_t*)data;

	if (!is_frame_load(node))
		return;

	const bpf_load_attr_t *attr = get_bpf_load_attr_const(node);
	ir_entity *entity = attr->entity;
	if (entity != NULL)
		return;
	if (!attr->is_frame_entity)
		return;
	// unsigned size     = get_mode_size_bytes(mode);
	// unsigned po2align = log2_floor(size);
	// if (arch_get_irn_flags(node) & bpf_arch_irn_flag_needs_64bit_spillslot) {
	// 	size     = 8;
	// 	po2align = 3;
	// }
	be_load_needs_frame_entity(env, node, 8, 3);
}

static void bpf_set_frame_entity(ir_node *node, ir_entity *entity,
                                   unsigned size, unsigned po2align)
{
	(void)size;
	(void)po2align;
	/* we only say be_node_needs_frame_entity on nodes with load_store
	 * attributes, so this should be fine */
	bpf_load_attr_t *attr = get_bpf_load_attr(node);
	attr->entity = entity;
}

static void bpf_determine_frameoffset(ir_node *node, int sp_offset)
{
	if (!is_bpf_irn(node))
		return;
	if (is_bpf_FrameAddr(node)) {
		bpf_member_attr_t *const attr   = get_bpf_member_attr_const(node);
		ir_entity const    *const entity = attr->entity;
		if (entity != NULL)
			attr->offset += get_entity_offset(entity);
		attr->offset += sp_offset;
	} else if (is_bpf_Load(node)) {
        bpf_load_attr_t *const attr = get_bpf_load_attr_const(node);
        ir_entity const    *const entity = attr->entity;
		if (entity != NULL)
			attr->offset += get_entity_offset(entity);
		attr->offset += sp_offset;
    } else if (is_bpf_Store(node)) {
        bpf_store_attr_t *const attr = get_bpf_store_attr_const(node);
        ir_entity const    *const entity = attr->entity;
		if (entity != NULL)
			attr->offset += get_entity_offset(entity);
		attr->offset += sp_offset;
    }
}

static void bpf_sp_sim(ir_node *const node, stack_pointer_state_t *state)
{
	bpf_determine_frameoffset(node, state->offset);
}


void bpf_finish_graph(ir_graph *irg)
{
	be_fec_env_t *fec_env = be_new_frame_entity_coalescer(irg);
	irg_walk_graph(irg, NULL, bpf_collect_frame_entity_nodes, fec_env);
	be_assign_entities(fec_env, bpf_set_frame_entity, false);
	be_free_frame_entity_coalescer(fec_env);

	ir_type *const frame = get_irg_frame_type(irg);
	be_sort_frame_entities(frame, false);
	unsigned const misalign = 0;
	be_layout_frame_type(frame, 0, misalign);

	// bpf_introduce_prolog_epilog(irg, false);

	/* fix stack entity offsets */
	be_fix_stack_nodes(irg, &bpf_registers[REG_R10]);
	be_birg_from_irg(irg)->non_ssa_regs = NULL;
	be_sim_stack_pointer(irg, misalign, 3, bpf_sp_sim);

	// heights = heights_new(irg);

	// /* perform peephole optimizations */
	// ir_clear_opcodes_generic_func();
	// register_peephole_optimization(op_be_IncSP,        peephole_be_IncSP);
	// register_peephole_optimization(op_sparc_FrameAddr, peephole_sparc_FrameAddr);
	// register_peephole_optimization(op_sparc_RestoreZero,
	//                                peephole_sparc_RestoreZero);
	// register_peephole_optimization(op_sparc_Ldf, split_sparc_ldf);
	// register_peephole_optimization(op_sparc_AddCC, peephole_sparc_AddCC);
	// register_peephole_optimization(op_sparc_SubCC, peephole_sparc_SubCC);
	// be_peephole_opt(irg);

	// /* perform legalizations (mostly fix nodes with too big immediates) */
	// ir_clear_opcodes_generic_func();
	// register_peephole_optimization(op_be_IncSP,        finish_be_IncSP);
	// register_peephole_optimization(op_sparc_FrameAddr, finish_sparc_FrameAddr);
	// register_peephole_optimization(op_sparc_Ld,        finish_sparc_Ld);
	// register_peephole_optimization(op_sparc_Ldf,       finish_sparc_Ldf);
	// register_peephole_optimization(op_sparc_Save,      finish_sparc_Save);
	// register_peephole_optimization(op_sparc_St,        finish_sparc_St);
	// register_peephole_optimization(op_sparc_Stf,       finish_sparc_Stf);
	// be_peephole_opt(irg);

	// heights_free(heights);

	be_handle_2addr(irg, NULL);

	// be_remove_dead_nodes_from_schedule(irg);
}
