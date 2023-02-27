/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   calling convention helpers
 * @author  Matthias Braun
 */
#include "bpf_cconv.h"

#include "bpf_bearch_t.h"
#include "becconv.h"
#include "beirg.h"
#include "irmode_t.h"
#include "panic.h"
#include "typerep.h"
#include "util.h"
#include "xmalloc.h"

static const unsigned ignore_regs[] = {
	REG_R10,
	// REG_R0,
};

static const arch_register_t* const param_regs[] = {
	&bpf_registers[REG_R1],
	&bpf_registers[REG_R2],
	&bpf_registers[REG_R3],
	&bpf_registers[REG_R4],
	&bpf_registers[REG_R5],
};

static const arch_register_t* const result_regs[] = {
	&bpf_registers[REG_R0],
};

calling_convention_t *bpf_decide_calling_convention(const ir_graph *irg,
                                                    ir_type *function_type)
{
	/* determine how parameters are passed */
	size_t const        n_param_regs = ARRAY_SIZE(param_regs);
	size_t const        n_params     = get_method_n_params(function_type);
	size_t              regnum       = 0;
	reg_or_stackslot_t *params       = XMALLOCNZ(reg_or_stackslot_t, n_params);

	for (size_t i = 0; i < n_params; ++i) {
		ir_type            *param_type = get_method_param_type(function_type,i);
		ir_mode            *mode       = get_type_mode(param_type);
		int                 bits       = get_mode_size_bits(mode);
		reg_or_stackslot_t *param      = &params[i];
		param->type = param_type;

		if (regnum < n_param_regs) {
			param->reg0 = param_regs[regnum++];
		} else {
			panic("Too many paramenters, eBPF only support up to 5 paramenters.");
		}
	}
	
    unsigned const n_param_regs_used = regnum;

	size_t const        n_result_regs= ARRAY_SIZE(result_regs);
	size_t              n_results    = get_method_n_ress(function_type);
	reg_or_stackslot_t *results      = XMALLOCNZ(reg_or_stackslot_t, n_results);
	regnum = 0;
	for (size_t i = 0; i < n_results; ++i) {
		ir_type            *result_type = get_method_res_type(function_type, i);
		ir_mode            *result_mode = get_type_mode(result_type);
		reg_or_stackslot_t *result      = &results[i];

        if (regnum >= n_result_regs) {
            panic("too many results");
        } else {
            const arch_register_t *reg = result_regs[regnum++];
            result->reg0 = reg;
        }
	}

	calling_convention_t *cconv = XMALLOCZ(calling_convention_t);
	cconv->parameters       = params;
	cconv->n_parameters     = n_params;
	cconv->n_param_regs     = n_param_regs_used;
	cconv->results          = results;

	/* setup allocatable registers */
	if (irg != NULL) {
		be_irg_t *birg = be_birg_from_irg(irg);

		assert(birg->allocatable_regs == NULL);
		birg->allocatable_regs = be_cconv_alloc_all_regs(&birg->obst, N_BPF_REGISTERS);
		be_cconv_rem_regs(birg->allocatable_regs, ignore_regs, ARRAY_SIZE(ignore_regs));
	}

	return cconv;
}

void bpf_free_calling_convention(calling_convention_t *cconv)
{
	free(cconv->parameters);
	free(cconv->results);
	free(cconv);
}
