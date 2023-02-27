/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief    The main bpf backend driver file.
 */

#include "bpf_bearch_t.h"

#include "bpf_emitter.h"
#include "bpf_new_nodes.h"
#include "bpf_transform.h"
#include "be_t.h"
#include "beirg.h"
#include "bemodule.h"
#include "benode.h"
#include "bera.h"
#include "besched.h"
#include "bestack.h"
#include "debug.h"
#include "gen_bpf_regalloc_if.h"
#include "iredges_t.h"
#include "irprog_t.h"
#include "isas.h"
#include "lower_builtins.h"
#include "lower_calls.h"
#include "panic.h"
#include "target_t.h"

/**
 * Transforms the standard firm graph into a bpf firm graph
 */
static void bpf_select_instructions(ir_graph *irg)
{
	/* transform nodes into assembler instructions */
	be_timer_push(T_CODEGEN);
	bpf_transform_graph(irg);
	be_timer_pop(T_CODEGEN);
	be_dump(DUMP_BE, irg, "code-selection");

	/* do local optimizations (mainly CSE) */
	local_optimize_graph(irg);

	/* do code placement, to optimize the position of constants */
	place_code(irg);
}

static ir_node *bpf_new_spill(ir_node *value, ir_node *after)
{
	ir_node  *block  = get_block(after);
	ir_graph *irg    = get_irn_irg(after);
	ir_node  *frame  = get_irg_frame(irg);
	ir_node  *mem    = get_irg_no_mem(irg);
	ir_mode  *mode   = get_irn_mode(value);
	ir_node *store = new_bd_bpf_Store_reg(NULL, block, mem, value, frame,   NULL, mode, 0, true);
	arch_add_irn_flags(store, arch_irn_flag_spill);
	sched_add_after(after, store);
	return store;
}

static ir_node *bpf_new_reload(ir_node *value, ir_node *spill,
                                    ir_node *before)
{
	ir_node  *block  = get_block(before);
	ir_graph *irg    = get_irn_irg(before);
	ir_node  *frame  = get_irg_frame(irg);
	ir_mode  *mode   = get_irn_mode(value);
	ir_node  *load   = new_bd_bpf_Load_reg(NULL, block, spill, frame,  NULL, mode, 0, true);
	ir_node  *proj   = be_new_Proj(load, pn_bpf_Load_res);
	arch_add_irn_flags(load, arch_irn_flag_reload);
	sched_add_before(before, load);
	return proj;
}

static const regalloc_if_t bpf_regalloc_if = {
	.spill_cost  = 7,
	.reload_cost = 5,
	.new_spill   = bpf_new_spill,
	.new_reload  = bpf_new_reload,
};

// static void introduce_prologue(ir_graph *const irg)
// {
// 	ir_node  *const start      = get_irg_start(irg);
// 	ir_node  *const block      = get_nodes_block(start);
// 	ir_node  *const initial_sp = be_get_Start_proj(irg, &bpf_registers[REG_SP]);
// 	ir_type  *const frame_type = get_irg_frame_type(irg);
// 	unsigned  const frame_size = get_type_size(frame_type);
// 	ir_node  *const incsp      = be_new_IncSP(block, initial_sp, frame_size, false);
// 	edges_reroute_except(initial_sp, incsp, incsp);
// 	sched_add_after(start, incsp);
// }

static void bpf_generate_code(FILE *output, const char *cup_name)
{
	be_begin(output, cup_name);
	unsigned *const sp_is_non_ssa = rbitset_alloca(N_BPF_REGISTERS);
	rbitset_set(sp_is_non_ssa, REG_R10);

	foreach_irp_irg(i, irg) {
		if (!be_step_first(irg))
			continue;

		struct obstack *obst = be_get_be_obst(irg);
		be_birg_from_irg(irg)->isa_link = OALLOCZ(obst, bpf_irg_data_t);
		be_birg_from_irg(irg)->non_ssa_regs = sp_is_non_ssa;
		bpf_select_instructions(irg);

		be_step_schedule(irg);

		be_sched_fix_flags(irg, &bpf_reg_classes[CLASS_bpf_flags], NULL, NULL, NULL);

		be_step_regalloc(irg, &bpf_regalloc_if);

		// introduce_prologue(irg);

		be_fix_stack_nodes(irg, &bpf_registers[REG_R10]);
		be_birg_from_irg(irg)->non_ssa_regs = NULL;

		bpf_finish_graph(irg);
		bpf_emit_function(irg);

		be_step_last(irg);
	}

	be_finish();
}

static void bpf_init(void)
{
	bpf_register_init();
	bpf_create_opcodes();

	ir_target.experimental
		= "The bpf backend is just a demo for writing backends";
	ir_target.float_int_overflow = ir_overflow_min_max;
}

static void bpf_finish(void)
{
	bpf_free_opcodes();
}

static void bpf_lower_for_target(void)
{
	ir_builtin_kind supported[8];
	size_t s = 0;
	supported[s++] = ir_bk_bswap;
	lower_builtins(s, supported, NULL);
	be_after_irp_transform("lower-builtins");

	/* lower compound param handling */
	lower_calls_with_compounds(LF_RETURN_HIDDEN,
				   lower_aggregates_as_pointers, NULL,
				   lower_aggregates_as_pointers, NULL,
				   reset_stateless_abi);
	be_after_irp_transform("lower-calls");


}

static unsigned bpf_get_op_estimated_cost(const ir_node *node)
{
	if (is_bpf_Load(node))
		return 5;
	if (is_bpf_Store(node))
		return 7;
	return 1;
}

arch_isa_if_t const bpf_isa_if = {
	.name                  = "bpf",
	.pointer_size          = 8,
	.modulo_shift          = 32,
	.big_endian            = false,
	.po2_biggest_alignment = 4,
	.pic_supported         = false,
	.n_registers           = N_BPF_REGISTERS,
	.registers             = bpf_registers,
	.n_register_classes    = N_BPF_CLASSES,
	.register_classes      = bpf_reg_classes,
	.init                  = bpf_init,
	.finish                = bpf_finish,
	.generate_code         = bpf_generate_code,
	.lower_for_target      = bpf_lower_for_target,
	.get_op_estimated_cost = bpf_get_op_estimated_cost,
	.get_bytecode = bpf_get_bytecode,
	.bytecode_size = bpf_bytecode_size,
};

BE_REGISTER_MODULE_CONSTRUCTOR(be_init_arch_bpf)
void be_init_arch_bpf(void)
{
	bpf_init_transform();
}
