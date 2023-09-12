use crate::mir::FunctionData;
use crate::mir::Instruction;
use crate::mir::{self};
use crate::types::BinaryOp;
use crate::TypeKind;
use cranelift_codegen::ir::types;
use cranelift_codegen::ir::AbiParam;
use cranelift_codegen::ir::Block;
use cranelift_codegen::ir::Function;
use cranelift_codegen::ir::InstBuilder;
use cranelift_codegen::ir::Signature;
use cranelift_codegen::ir::UserFuncName;
use cranelift_codegen::ir::Value;
use cranelift_codegen::isa::CallConv;
use cranelift_frontend::FunctionBuilder;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_frontend::Variable;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Default)]
struct LowerContext {
    visited: HashSet<mir::Block>,
    symbols: HashMap<String, Variable>,
    variable_variable: HashMap<mir::Variable, Variable>,
    block_block: HashMap<mir::Block, Block>,

    variable_count: u32,
}

impl LowerContext {
    fn new_var(&mut self) -> Variable {
        self.variable_count += 1;
        Variable::from_u32(self.variable_count)
    }

    fn use_var(&self, builder: &mut FunctionBuilder, var: &mir::Variable) -> Value {
        builder.use_var(self.variable_variable[var])
    }

    fn def_var(
        &mut self,
        builder: &mut FunctionBuilder,
        var: &mir::Variable,
        ty: &crate::Type,
        val: Value,
    ) {
        if let Some(&v) = self.variable_variable.get(var) {
            builder.def_var(v, val);
        } else {
            let v = self.new_var();
            builder.declare_var(v, to_clif_type(ty));
            builder.def_var(v, val);
            self.variable_variable.insert(*var, v);
        }
    }
}

pub fn do_clif(fd: &FunctionData) -> Function {
    let mut ctx = LowerContext::default();
    do_clif_func(&mut ctx, fd)
}

fn do_clif_func(ctx: &mut LowerContext, fd: &FunctionData) -> Function {
    let mut sig = Signature::new(CallConv::SystemV);
    sig.returns.push(AbiParam::new(types::I64));
    sig.params.push(AbiParam::new(types::I64));

    let mut fn_builder_ctx = FunctionBuilderContext::new();
    let mut func = Function::with_name_signature(UserFuncName::user(0, 0), sig);
    let mut builder = FunctionBuilder::new(&mut func, &mut fn_builder_ctx);
    do_clif_func_entry(ctx, &mut builder, fd);

    builder.seal_all_blocks();
    builder.finalize();
    log::debug!("bpfir to clif:\n{}", func.display());
    func
}

fn do_clif_func_entry(ctx: &mut LowerContext, builder: &mut FunctionBuilder, fd: &FunctionData) {
    let blk = builder.create_block();

    for (idx, _) in fd.blocks.iter() {
        ctx.block_block
            .insert(mir::Block(idx), builder.create_block());
    }
    let var = ctx.new_var();
    builder.append_block_params_for_function_params(blk);
    builder.declare_var(var, to_clif_type(&fd.variable_data(fd.params[0]).ty));
    ctx.variable_variable.insert(fd.params[0], var);
    builder.switch_to_block(blk);
    builder.seal_block(blk);

    builder.ins().jump(ctx.block_block[&fd.entry], &[]);

    builder.def_var(var, builder.block_params(blk)[0]);

    do_clif_block(ctx, builder, fd, fd.entry);

    let ret = ctx.new_var();
    builder.declare_var(ret, types::I64);
    let ret_val = builder.ins().iconst(types::I64, 0);
    builder.def_var(ret, ret_val);
    builder.ins().return_(&[ret_val]);
}

fn do_clif_block(
    ctx: &mut LowerContext,
    builder: &mut FunctionBuilder,
    fd: &FunctionData,
    block: mir::Block,
) {
    if ctx.visited.contains(&block) {
        return;
    }

    ctx.visited.insert(block);

    let bd = fd.block_data(block);
    for pred in &bd.preds {
        do_clif_block(ctx, builder, fd, *pred);
    }
    let blk = ctx.block_block[&block];
    builder.switch_to_block(blk);
    builder.seal_block(blk);

    for inst in &bd.insts {
        do_clif_inst(ctx, builder, fd, inst);
    }
}

fn do_clif_inst(
    ctx: &mut LowerContext,
    builder: &mut FunctionBuilder,
    fd: &FunctionData,
    inst: &Instruction,
) {
    log::debug!("{}", inst);
    match inst {
        Instruction::Assign(l, r) => {
            let rval = builder.use_var(ctx.variable_variable[r]);
            ctx.def_var(builder, l, &fd.variable_data(*l).ty, rval)
        }
        Instruction::AssignImm(l, r) => {
            let lvd = fd.variable_data(*l);
            let val = builder.ins().iconst(to_clif_type(&lvd.ty), *r);
            ctx.def_var(builder, l, &fd.variable_data(*l).ty, val);
        }
        Instruction::Member(_, _, _) => panic!("lower member instruction first"),
        Instruction::BinaryImm(op, v1, v2, imm) => {
            let v2_ = ctx.use_var(builder, v2);

            let v1_ = match op {
                BinaryOp::Add => builder.ins().iadd_imm(v2_, *imm),
                _ => todo!(),
            };
            ctx.def_var(builder, v1, &fd.variable_data(*v1).ty, v1_);
        }
        _ => todo!("{}", inst),
    }
}

fn to_clif_type(ty: &crate::Type) -> types::Type {
    match ty.kind {
        TypeKind::I16 => types::I16,
        TypeKind::U16 => types::I16,
        TypeKind::I32 => types::I32,
        TypeKind::U32 => types::I32,
        TypeKind::I64 => types::I64,
        TypeKind::U64 => types::I64,
        TypeKind::Ptr(_) => types::I64,
        _ => todo!("{}", ty.to_string()),
    }
}
