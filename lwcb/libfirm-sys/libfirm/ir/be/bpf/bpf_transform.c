/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   code selection (transform FIRM into bpf FIRM)
 */
#include "bpf_transform.h"

#include "bpf_new_nodes.h"
#include "bpf_nodes_attr.h"
#include "beirg.h"
#include "benode.h"
#include "betranshlp.h"
#include "debug.h"
#include "gen_bpf_regalloc_if.h"
#include "ircons.h"
#include "iredges_t.h"
#include "irgmod.h"
#include "irgraph_t.h"
#include "irmode_t.h"
#include "irnode_t.h"
#include "iropt_t.h"
#include "panic.h"
#include "bpf_cconv.h"
#include "util.h"

static calling_convention_t *current_cconv = NULL;
static be_stack_env_t        stack_env;

DEBUG_ONLY(static firm_dbg_module_t *dbg = NULL;)

typedef ir_node *(*new_binop_func)(dbg_info *dbgi, ir_node *block,
								   ir_node *left, ir_node *right);

typedef ir_node *(*new_binop_reg_func)(dbg_info *dbgi, ir_node *block, ir_node *op1, ir_node *op2);
typedef ir_node *(*new_binop_imm_func)(dbg_info *dbgi, ir_node *block, ir_node *op1, ir_entity *entity, int32_t immediate);

static ir_node *transform_binop(ir_node *node, new_binop_func new_func)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *left = get_binop_left(node);
	ir_node *new_left = be_transform_node(left);
	ir_node *right = get_binop_right(node);
	ir_node *new_right = be_transform_node(right);

	return new_func(dbgi, new_block, new_left, new_right);
}

static ir_node *gen_helper_binop_args(ir_node *node,
									  ir_node *op1,
									  ir_node *op2,
									  new_binop_reg_func new_reg,
									  new_binop_imm_func new_imm)
{

	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *block = be_transform_nodes_block(node);

	ir_node *new_op1 = be_transform_node(op1);

	if (is_Const(op2))
	{
		int32_t const imm = get_Const_long(op2);
		return new_imm(dbgi, block, new_op1, NULL, imm);
	}

	ir_node *new_op2 = be_transform_node(op2);
	return new_reg(dbgi, block, new_op1, new_op2);
}

static ir_node *gen_And(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_And_reg);
}

static ir_node *gen_Or(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Or_reg);
}

static ir_node *gen_Eor(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Xor_reg);
}

static ir_node *gen_Div(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Div_reg);
}

static ir_node *gen_Shl(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Shl_reg);
}

static ir_node *gen_Shr(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Add_reg);
}

static ir_node *gen_Add(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Add_reg);
}

static ir_node *gen_Sub(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Sub_reg);
}

static ir_node *gen_Mul(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Mul_reg);
}

typedef ir_node *(*new_unop_func)(dbg_info *dbgi, ir_node *block, ir_node *op);

static ir_node *transform_unop(ir_node *node, int op_index, new_unop_func new_func)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *op = get_irn_n(node, op_index);
	ir_node *new_op = be_transform_node(op);

	return new_func(dbgi, new_block, new_op);
}

static ir_node *gen_Minus(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	panic("eBPF doesn't support minus");
	// return transform_binop(node, new_bd_bpf_Minus_reg);
	return NULL;
}

static ir_node *gen_Not(ir_node *node)
{
	panic("eBPF doesn't support Not operator, we should use if statement to construct Not operator.");
}

static ir_node *gen_Const(ir_node *node)
{
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *block = be_transform_nodes_block(node);
	ir_mode *mode = get_irn_mode(node);
	ir_tarval *tv = get_Const_tarval(node);

	return new_bd_bpf_Const(dbgi, block, get_tarval_long(tv), mode, get_Const_is_mapfd(node));
}

// static ir_node *gen_Address(ir_node *node)
// {
// 	ir_entity *entity    = get_Address_entity(node);
// 	dbg_info  *dbgi      = get_irn_dbg_info(node);
// 	ir_node   *new_block = be_transform_nodes_block(node);
// 	return make_address(dbgi, new_block, entity, 0);
// }

static ir_node *gen_Conv(ir_node *node)
{
	ir_node *op = get_Conv_op(node);
	ir_mode *src_mode = get_irn_mode(op);
	ir_mode *dst_mode = get_irn_mode(node);

	if (src_mode == dst_mode)
		return be_transform_node(op);

	ir_node *block = be_transform_nodes_block(node);
	int src_bits = get_mode_size_bits(src_mode);
	int dst_bits = get_mode_size_bits(dst_mode);
	dbg_info *dbgi = get_irn_dbg_info(node);

	if (src_bits >= dst_bits)
	{
		/* kill unnecessary conv */
		return be_transform_node(op);
	}

	if (be_upper_bits_clean(op, src_mode))
	{
		return be_transform_node(op);
	}
	ir_node *new_op = be_transform_node(op);

	// if (mode_is_signed(src_mode)) {
	// 	return gen_sign_extension(dbgi, block, new_op, src_bits);
	// } else {
	// 	return gen_zero_extension(dbgi, block, new_op, src_bits);
	// }
	return new_op;
}

static const arch_register_t *const caller_saves[] = {
	&bpf_registers[REG_R0],
	&bpf_registers[REG_R1],
	&bpf_registers[REG_R2],
	&bpf_registers[REG_R3],
	&bpf_registers[REG_R4],
	&bpf_registers[REG_R5],
};

static ir_node *gen_Call(ir_node *node)
{
	ir_graph *irg = get_irn_irg(node);
	ir_node *callee = get_Call_ptr(node);
	ir_node *new_block = be_transform_nodes_block(node);
	ir_node *mem = get_Call_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_type *type = get_Call_type(node);
	size_t n_params = get_Call_n_params(node);
	size_t n_ress = get_method_n_ress(type);
	int in_arity = 0;

	calling_convention_t *cconv = bpf_decide_calling_convention(NULL, type);
	size_t n_param_regs = cconv->n_param_regs;

	ir_node **in = ALLOCAN(ir_node *, 5);
	arch_register_req_t const **const in_req = be_allocate_in_reqs(irg, 5);

	/* memory input */
	in_req[in_arity] = arch_memory_req;
	in[in_arity] = new_mem;
	++in_arity;

	for (size_t p = 0; p < n_params; ++p)
	{
		ir_node *value = get_Call_param(node, p);
		ir_node *new_value = be_transform_node(value);
		const reg_or_stackslot_t *param = &cconv->parameters[p];

		in[in_arity] = new_value;
		in_req[in_arity] = param->reg0->single_req;
		++in_arity;
	}

	// 1 is R0
	// 5 is R1 - R5
	unsigned out_arity = pn_bpf_Call_first_result + ARRAY_SIZE(caller_saves);
	// create call node;
	ir_node *res;
	ir_entity *entity = NULL;
	int32_t func_id = 0;
	int32_t i = 0;
	if (is_Address(callee))
	{
		entity = get_Address_entity(callee);

		ident *id = get_entity_ident(entity);
		for (i = 0;; i++)
		{
			if (id[i] == ':')
				break;
		}

		i++;

		func_id = atoi(&id[i]);
	}

	res = new_bd_bpf_Call_helper(dbgi, new_block, in_arity, in, in_req, out_arity, entity, func_id);
	arch_set_irn_register_req_out(res, pn_bpf_Call_M, arch_memory_req);

	for (size_t o = 0; o < ARRAY_SIZE(caller_saves); ++o)
	{
		const arch_register_t *reg = caller_saves[o];
		arch_set_irn_register_req_out(res, pn_bpf_Call_first_result + o, reg->single_req);
	}
	// set_irn_pinned(res, get_irn_pinned(node));

	bpf_free_calling_convention(cconv);
	return res;
}

typedef struct address_t
{
	ir_node *base;
	ir_entity *entity;
	uint16_t offset;
	bool is_frame_entity;
} address_t;

static void match_address(ir_node *addr, address_t *address)
{
	uint16_t offset = 0;

	if (is_Add(addr))
	{
		ir_node *right = get_Add_right(addr);
		if (is_Const(right))
		{
			addr = get_Add_left(addr);
			offset = get_Const_long(right);
		}
	}
	// todo: handle Member node
	ir_entity *entity = NULL;
	if (is_Member(addr))
	{
		entity = get_Member_entity(addr);
		addr = get_Member_ptr(addr);
		/* Must be the frame pointer. All other sels must have been lowered
		 * already. */
		assert(is_Proj(addr) && is_Start(get_Proj_pred(addr)));
	}

	ir_node *const base = be_transform_node(addr);

	address->base = base;
	address->offset = offset;
	address->entity = entity;
	address->is_frame_entity = entity != NULL;
}

static ir_node *gen_Load(ir_node *node)
{
	address_t address;
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *ptr = get_Load_ptr(node);
	// ir_node *new_ptr = be_transform_node(ptr);
	match_address(ptr, &address);
	ir_node *mem = get_Load_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	ir_mode *mode = get_Load_mode(node);

	return new_bd_bpf_Load_reg(dbgi, new_block, new_mem, address.base, address.entity, mode, address.offset, address.is_frame_entity);
}

static ir_node *gen_Member(ir_node *node)
{
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *new_block = be_transform_nodes_block(node);
	ir_node *ptr = get_Member_ptr(node);
	ir_node *new_ptr = be_transform_node(ptr);
	ir_entity *entity = get_Member_entity(node);

	/* must be the frame pointer all other sels must have been lowered
	 * already */
	assert(is_Proj(ptr) && is_Start(get_Proj_pred(ptr)));

	return new_bd_bpf_FrameAddr(dbgi, new_block, new_ptr, entity, 0);
}

static ir_node *gen_Store(ir_node *node)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *ptr = get_Store_ptr(node);
	ir_node *val = get_Store_value(node);
	ir_node *mem = get_Store_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	ir_mode *mode = get_irn_mode(val);
	address_t address;
	match_address(ptr, &address);

	val = be_skip_downconv(val, false);
	val = be_transform_node(val);
	return new_bd_bpf_Store_reg(dbgi, new_block, new_mem, val, address.base, address.entity, mode, address.offset, address.is_frame_entity);
}

static ir_node *gen_Jmp(ir_node *node)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	return new_bd_bpf_Jmp(dbgi, new_block);
}

// set Start node outs
static ir_node *gen_Start(ir_node *node)
{
	be_start_out outs[N_BPF_REGISTERS] = {
		[REG_R0] = BE_START_IGNORE,
		[REG_R6] = BE_START_IGNORE,
		[REG_R7] = BE_START_IGNORE,
		[REG_R8] = BE_START_IGNORE,
		[REG_R9] = BE_START_IGNORE,
		[REG_R10] = BE_START_IGNORE,
	};

	outs[REG_R1] = BE_START_REG;

	ir_graph *const irg = get_irn_irg(node);
	return be_new_Start(irg, outs);
}

static ir_node *gen_Return(ir_node *node)
{
	int p = n_bpf_Return_first_result;
	unsigned const n_res = get_Return_n_ress(node);
	unsigned const n_ins = p + n_res;
	ir_node **const in = ALLOCAN(ir_node *, n_ins);
	ir_graph *const irg = get_irn_irg(node);
	arch_register_req_t const **const reqs = be_allocate_in_reqs(irg, n_ins);

	in[n_bpf_Return_mem] = be_transform_node(get_Return_mem(node));
	reqs[n_bpf_Return_mem] = arch_memory_req;

	// in[n_bpf_Return_stack]   = get_irg_frame(irg);
	// reqs[n_bpf_Return_stack] = &bpf_registers[REG_R10];

	for (unsigned i = 0; i != n_res; ++p, ++i)
	{
		ir_node *const res = get_Return_res(node, i);
		in[p] = be_transform_node(res);
		reqs[p] = arch_get_irn_register_req(in[p])->cls->class_req;
	}

	dbg_info *const dbgi = get_irn_dbg_info(node);
	ir_node *const block = be_transform_nodes_block(node);
	ir_node *const ret = new_bd_bpf_Return(dbgi, block, n_ins, in, reqs);
	return ret;
}

static ir_node *gen_Phi(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);
	const arch_register_req_t *req;
	if (be_mode_needs_gp_reg(mode))
	{
		req = &bpf_class_reg_req_gp;
	}
	else
	{
		req = arch_memory_req;
	}

	return be_transform_phi(node, req);
}

static ir_node *gen_Proj_Proj(ir_node *node)
{
	ir_node *pred = get_Proj_pred(node);
	ir_node *pred_pred = get_Proj_pred(pred);
	if (is_Start(pred_pred))
	{
		if (get_Proj_num(pred) == pn_Start_T_args)
		{
			// assume everything is passed in gp registers
			unsigned arg_num = get_Proj_num(node);
			if (arg_num >= 1)
				panic("more than 1 arguments not supported");
			ir_graph *const irg = get_irn_irg(node);
			return be_get_Start_proj(irg, &bpf_registers[REG_R1]);
		}
	} else if(is_Call(pred_pred)) {
		ir_node *const call     = get_Proj_pred(get_Proj_pred(node));
		ir_node *const new_call = be_transform_node(call);
		unsigned const pn       = get_Proj_num(node);
		unsigned const new_pn   = pn_bpf_Call_first_result + pn;
		return be_new_Proj(new_call, new_pn);
	}
	panic("No transformer for %+F -> %+F -> %+F", node, pred, pred_pred);
}

static ir_node *gen_Proj_Load(ir_node *node)
{
	ir_node *load = get_Proj_pred(node);
	ir_node *new_load = be_transform_node(load);
	switch ((pn_Load)get_Proj_num(node))
	{
	case pn_Load_M:
		return be_new_Proj(new_load, pn_bpf_Load_M);
	case pn_Load_res:
		return be_new_Proj(new_load, pn_bpf_Load_res);
	case pn_Load_X_regular:
	case pn_Load_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, load);
}

static ir_node *gen_Proj_Store(ir_node *node)
{
	ir_node *store = get_Proj_pred(node);
	ir_node *new_store = be_transform_node(store);
	switch ((pn_Store)get_Proj_num(node))
	{
	case pn_Store_M:
		return new_store;
	case pn_Store_X_regular:
	case pn_Store_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, store);
}

static ir_node *gen_Proj_Start(ir_node *node)
{
	ir_graph *const irg = get_irn_irg(node);
	unsigned const pn = get_Proj_num(node);
	switch ((pn_Start)pn)
	{
	case pn_Start_M:
		return be_get_Start_mem(irg);
	case pn_Start_T_args:
		return new_r_Bad(irg, mode_T);
	case pn_Start_P_frame_base:
		return be_get_Start_proj(irg, &bpf_registers[REG_R10]);
	}
}

static ir_node *gen_Proj_Call(ir_node *node)
{
	unsigned pn = get_Proj_num(node);
	ir_node *call = get_Proj_pred(node);
	ir_node *new_call = be_transform_node(call);
	switch ((pn_Call)pn)
	{
	case pn_Call_M:
		return be_new_Proj(new_call, pn_bpf_Call_M);
	case pn_Call_X_regular:
	case pn_Call_X_except:
	case pn_Call_T_result:
		break;
	}
	panic("unexpected Call proj %u", pn);
}

/**
 * Transform Proj(Builtin) node.
 */
static ir_node *gen_Proj_Builtin(ir_node *proj)
{
	ir_node         *pred     = get_Proj_pred(proj);
	ir_node         *new_pred = be_transform_node(pred);
	ir_builtin_kind  kind     = get_Builtin_kind(pred);
	unsigned         pn       = get_Proj_num(proj);
	switch (kind) {
	case ir_bk_bswap:
		assert(pn == pn_Builtin_max+1);
		return new_pred;
	}
	panic("Builtin %s not implemented", get_builtin_kind_name(kind));
}

static ir_node *gen_Cond(ir_node *node)
{
	ir_node    *selector  = get_Cond_selector(node);
	ir_node    *block     = be_transform_nodes_block(node);
	dbg_info   *dbgi      = get_irn_dbg_info(node);
	ir_node    *flag_node = be_transform_node(selector);
	ir_relation relation  = get_Cmp_relation(selector);

	return new_bd_bpf_CondJmp(dbgi, block, flag_node, relation);
}

static ir_node *gen_Cmp(ir_node *node)
{
	ir_node  *block    = be_transform_nodes_block(node);
	ir_node  *op1      = get_Cmp_left(node);
	ir_node  *op2      = get_Cmp_right(node);
	ir_mode  *cmp_mode = get_irn_mode(op1);
	dbg_info *dbgi     = get_irn_dbg_info(node);
	
	assert(get_irn_mode(op2) == cmp_mode);
	bool is_unsigned = !mode_is_signed(cmp_mode);

	/* integer compare, TODO: use shifter_op in all its combinations */
	ir_node *new_op1 = be_transform_node(op1);

	if (is_Const(op2)) {
		// todo: handle signed and unsigned
		return new_bd_bpf_Cmp_imm(dbgi, block, new_op1, get_Const_long(op2), true);
	}

	ir_node *new_op2 = be_transform_node(op2);
	return new_bd_bpf_Cmp_reg(dbgi, block, new_op1, new_op2, 0, false);
}

static ir_node *gen_bswap(ir_node *node)
{
	ir_node  *param     = get_Builtin_param(node, 0);
	ir_node  *new_param = be_transform_node(param);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *new_block = be_transform_nodes_block(node);
	ir_mode  *mode      = get_irn_mode(param);
	unsigned  size      = get_mode_size_bits(mode);

#define BPF_TO_BE	0x08	/* convert to big-endian */
	if (size == 16 || size == 32 || size == 64)
		return new_bd_bpf_BSwap(dbgi, new_block, new_param, BPF_TO_BE, size);

	panic("unsupport size: %d", size);
}

/**
 * Transform Builtin node.
 */
static ir_node *gen_Builtin(ir_node *node)
{
	ir_builtin_kind kind = get_Builtin_kind(node);

	switch (kind) {
		case ir_bk_bswap:
		return gen_bswap(node);
	}

	panic("Builtin %s not implemented", get_builtin_kind_name(kind));
}


static void bpf_register_transformers(void)
{
	be_start_transform_setup();

	be_set_transform_function(op_Add, gen_Add);
	be_set_transform_function(op_And, gen_And);
	// be_set_transform_function(op_Address, gen_Address);
	be_set_transform_function(op_Const, gen_Const);
	be_set_transform_function(op_Conv, gen_Conv);
	be_set_transform_function(op_Call, gen_Call);
	be_set_transform_function(op_Div, gen_Div);
	be_set_transform_function(op_Eor, gen_Eor); // XoR
	be_set_transform_function(op_Jmp, gen_Jmp);
	be_set_transform_function(op_Load, gen_Load);
	be_set_transform_function(op_Member, gen_Member);
	be_set_transform_function(op_Minus, gen_Minus);
	be_set_transform_function(op_Mul, gen_Mul);
	be_set_transform_function(op_Not, gen_Not);
	be_set_transform_function(op_Or, gen_Or);
	be_set_transform_function(op_Phi, gen_Phi);
	be_set_transform_function(op_Return, gen_Return);
	be_set_transform_function(op_Shl, gen_Shl);
	be_set_transform_function(op_Shr, gen_Shr);
	be_set_transform_function(op_Start, gen_Start);
	be_set_transform_function(op_Store, gen_Store);
	be_set_transform_function(op_Sub, gen_Sub);
	be_set_transform_function(op_Cond, gen_Cond);
	be_set_transform_function(op_Cmp, gen_Cmp);
	be_set_transform_function(op_Builtin, gen_Builtin);

	be_set_transform_proj_function(op_Load, gen_Proj_Load);
	be_set_transform_proj_function(op_Proj, gen_Proj_Proj);
	be_set_transform_proj_function(op_Start, gen_Proj_Start);
	be_set_transform_proj_function(op_Store, gen_Proj_Store);
	be_set_transform_proj_function(op_Call, gen_Proj_Call);
	be_set_transform_proj_function(op_Builtin, gen_Proj_Builtin);
}

static const unsigned ignore_regs[] = {
	REG_R10, // fp
	// REG_R0,	 // return register
};

static void setup_calling_convention(ir_graph *irg)
{
	be_irg_t *birg = be_birg_from_irg(irg);
	struct obstack *obst = &birg->obst;

	unsigned *allocatable_regs = rbitset_obstack_alloc(obst, N_BPF_REGISTERS);
	rbitset_set_all(allocatable_regs, N_BPF_REGISTERS);
	for (size_t r = 0, n = ARRAY_SIZE(ignore_regs); r < n; ++r)
	{
		rbitset_clear(allocatable_regs, ignore_regs[r]);
	}
	birg->allocatable_regs = allocatable_regs;
}

/**
 * Transform generic IR-nodes into bpf machine instructions
 */
void bpf_transform_graph(ir_graph *irg)
{
	assure_irg_properties(irg, IR_GRAPH_PROPERTY_NO_TUPLES | IR_GRAPH_PROPERTY_NO_BADS);

	bpf_register_transformers();


	be_stack_init(&stack_env);
	ir_entity *entity = get_irg_entity(irg);
	current_cconv = bpf_decide_calling_convention(irg, get_entity_type(entity));

	be_transform_graph(irg, NULL);

	be_stack_finish(&stack_env);
	bpf_free_calling_convention(current_cconv);

	/* do code placement, to optimize the position of constants */
	place_code(irg);
	/* backend expects outedges to be always on */
	assure_edges(irg);
}

void bpf_init_transform(void)
{
	FIRM_DBG_REGISTER(dbg, "firm.be.bpf.transform");
}
