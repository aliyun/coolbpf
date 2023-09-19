use crate::call::Call;
use crate::parser::Ast;
use crate::parser::Expr;
use crate::parser::ExprKind;
use crate::print::Print;
use crate::BLangBuilder;
use crate::__PERF_EVENT_MAP__;
use anyhow::bail;
use anyhow::Result;
use bpfir::module::Module;
use bpfir::types::BinaryOp;
use bpfir::types::UnaryOp;
use bpfir::TypeKind;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types;
use cranelift_codegen::ir::types::*;
use cranelift_codegen::ir::AbiParam;
use cranelift_codegen::ir::FuncRef;
use cranelift_codegen::ir::InstBuilder;
use cranelift_codegen::ir::MemFlags;
use cranelift_codegen::ir::StackSlotData;
use cranelift_codegen::ir::StackSlotKind;
use cranelift_codegen::ir::Value;
use cranelift_frontend::FunctionBuilder;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_frontend::Variable;
use std::collections::HashMap;

#[derive(Default)]
struct LocalContext {
    vars: HashMap<String, Variable>,
    vars_cnt: u32,
    module: Module,
    prints: Vec<Print>,
}

impl LocalContext {
    pub fn find_var(
        &mut self,
        fb: &mut FunctionBuilder,
        sym: &String,
        ty: &bpfir::Type,
    ) -> Variable {
        if let Some(var) = self.vars.get(sym) {
            *var
        } else {
            log::debug!("insert new symbol: {}, type: {:?}", sym, ty);
            let var = self.new_var();
            fb.declare_var(var, to_clif_type(ty));
            self.vars.insert(sym.clone(), var);
            var
        }
    }

    pub fn get_ctx(&self) -> Variable {
        *self.vars.get("ctx").unwrap()
    }

    fn new_var(&mut self) -> Variable {
        self.vars_cnt += 1;
        Variable::from_u32(self.vars_cnt)
    }

    fn find_helper_function(&mut self, id: u32, fb: &mut FunctionBuilder) -> FuncRef {
        let func_id = self.module.declare_helper_function(id);
        self.module
            .declare_helper_function_in_function(func_id, &mut fb.func)
    }

    fn find_map(&mut self, sym: &str, ty: bpfir::Type, fb: &mut FunctionBuilder) -> Value {
        let id = self.module.declare_map(sym, ty);
        let gval = self.module.declare_map_in_function(id, &mut fb.func);
        fb.ins().symbol_value(I64, gval)
    }
}

pub fn gen_bpfir(bb: &mut BLangBuilder, ast: &Ast) -> Result<Module> {
    let mut ctx = LocalContext::default();

    for expr in &ast.exprs {
        gen_func(&mut ctx, expr).unwrap();
    }

    bb.prints = ctx.prints;
    return Ok(ctx.module);
}

fn gen_func(ctx: &mut LocalContext, expr: &Expr) -> Result<()> {
    let mut builder_context = FunctionBuilderContext::new();
    let mut fctx = ctx.module.context();
    fctx.func.signature.params.push(AbiParam::new(I64));
    fctx.func.signature.returns.push(AbiParam::new(I64));
    let mut builder = FunctionBuilder::new(&mut fctx.func, &mut builder_context);
    if let Expr {
        kind: ExprKind::Trace(ty, body),
        ..
    } = expr
    {
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        let ctx_var = ctx.new_var();
        builder.declare_var(ctx_var, I64);
        ctx.vars.insert("ctx".to_owned(), ctx_var);
        builder.switch_to_block(entry);
        builder.seal_block(entry);

        builder.def_var(ctx_var, builder.block_params(entry)[0]);
        gen_stmt(ctx, &mut builder, body)?;
        let ret_val = builder.ins().iconst(types::I64, 0);
        builder.ins().return_(&[ret_val]);
        builder.seal_all_blocks();
        builder.finalize();

        ctx.module.define_probing_function(ty.ty.clone(), fctx);
        return Ok(());
    }

    bail!("parsing failed")
}

fn gen_stmt(ctx: &mut LocalContext, fb: &mut FunctionBuilder, expr: &Expr) -> Result<()> {
    match &expr.kind {
        ExprKind::ExprStmt(e) => {
            gen_expr(ctx, fb, e);
        }

        ExprKind::Return => {
            todo!()
        }

        ExprKind::Compound(es) => {
            for e in es {
                gen_stmt(ctx, fb, e)?;
            }
        }

        ExprKind::If(c, t, e) => gen_if_stmt(ctx, fb, c, t, e),

        _ => todo!(),
    }

    Ok(())
}

fn gen_if_stmt(
    ctx: &mut LocalContext,
    fb: &mut FunctionBuilder,
    c: &Expr,
    t: &Expr,
    e: &Option<Expr>,
) {
    let condition = gen_expr_cf(ctx, fb, c).unwrap();

    let then_block = fb.create_block();
    let else_block = fb.create_block();
    let merge_block = fb.create_block();

    fb.ins().brif(condition, then_block, &[], else_block, &[]);

    fb.switch_to_block(then_block);
    fb.seal_block(then_block);

    gen_stmt(ctx, fb, t).unwrap();

    fb.ins().jump(merge_block, &[]);

    fb.switch_to_block(else_block);
    fb.seal_block(else_block);
    if let Some(x) = e {
        gen_stmt(ctx, fb, x).unwrap();
    }

    fb.ins().jump(merge_block, &[]);

    fb.switch_to_block(merge_block);
    fb.seal_block(merge_block);
}

fn gen_expr_cf(ctx: &mut LocalContext, fb: &mut FunctionBuilder, c: &Expr) -> Result<Value> {
    match &c.kind {
        ExprKind::Binary(op, l, r) => {
            let lhs = gen_expr_val(ctx, fb, l)?;
            let rhs = gen_expr_val(ctx, fb, r)?;
            let rel = match op {
                BinaryOp::LT => IntCC::SignedLessThan,
                BinaryOp::LTE => IntCC::SignedLessThanOrEqual,
                BinaryOp::GT => IntCC::SignedGreaterThan,
                BinaryOp::GTE => IntCC::SignedGreaterThanOrEqual,
                BinaryOp::Equal => IntCC::Equal,
                BinaryOp::NonEqual => IntCC::NotEqual,
                _ => panic!("If condition only handle relation operation"),
            };
            Ok(fb.ins().icmp(rel, lhs, rhs))
        }

        _ => panic!("If condition only handle relation operation"),
    }
}

fn gen_expr(ctx: &mut LocalContext, fb: &mut FunctionBuilder, expr: &Expr) {
    gen_expr_val(ctx, fb, expr).expect("failed to generate ir for expression");
}

fn gen_expr_val(ctx: &mut LocalContext, fb: &mut FunctionBuilder, expr: &Expr) -> Result<Value> {
    match &expr.kind {
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                let addr = gen_expr_val(ctx, fb, e)?;
                if let TypeKind::Ptr(x) = &expr.ty.kind {
                    return Ok(fb
                        .ins()
                        .load(to_clif_type(&expr.ty), MemFlags::trusted(), addr, 0));
                }
                return Ok(addr);
            }
            UnaryOp::Neg => {
                let val = gen_expr_val(ctx, fb, e)?;
                return Ok(fb.ins().ineg(val));
            }
            _ => todo!(),
        },
        ExprKind::Ident(_) => {
            return gen_expr_addr(ctx, fb, expr);
        }
        ExprKind::Constant(c) => {
            return Ok(fb.ins().iconst(to_clif_type(&expr.ty), *c));
        }
        ExprKind::Binary(op, l, r) => {
            match op {
                BinaryOp::Assign => {
                    let rval = gen_expr_val(ctx, fb, r)?;

                    match &l.kind {
                        ExprKind::Ident(i) => {
                            let var = ctx.find_var(fb, i, &l.ty);
                            fb.def_var(var, rval);
                            // should never use this value
                            return Ok(rval);
                        }

                        ExprKind::Binary(op, l2, r2) => {
                            if let BinaryOp::Index = op {
                                if let ExprKind::Ident(sym) = &l2.kind {
                                    let map = ctx.find_map(sym, l2.ty.clone(), fb);

                                    let keyval = gen_expr_val(ctx, fb, r2)?;
                                    let keyaddr = value_to_stack(fb, keyval, &r2.ty);

                                    let valaddr = value_to_stack(fb, rval, &r.ty);

                                    let flags = fb.ins().iconst(I64, libbpf_sys::BPF_ANY as i64);
                                    let fr = ctx.find_helper_function(
                                        libbpf_sys::BPF_FUNC_map_update_elem,
                                        fb,
                                    );
                                    let inst =
                                        fb.ins().call(fr, &vec![map, keyaddr, valaddr, flags]);
                                    return Ok(fb.inst_results(inst)[0]);
                                }
                            }
                            todo!()
                        }

                        _ => {
                            panic!("Currently lvalue only supports variables and index expressions")
                        }
                    }
                }
                BinaryOp::Index => {
                    // When we get here it should be an rvalue, we need to load this value
                    let addr = gen_expr_addr(ctx, fb, expr)?;
                    todo!()
                }
                BinaryOp::Add
                | BinaryOp::Sub
                | BinaryOp::Mult
                | BinaryOp::Div
                | BinaryOp::Mod
                | BinaryOp::BitOr
                | BinaryOp::BitAnd
                | BinaryOp::BitXor => {
                    let lval = gen_expr_val(ctx, fb, l)?;
                    let rval = gen_expr_val(ctx, fb, r)?;
                    return Ok(to_clif_binary(fb, op, lval, rval));
                }
                BinaryOp::LT
                | BinaryOp::LTE
                | BinaryOp::GT
                | BinaryOp::GTE
                | BinaryOp::NonEqual
                | BinaryOp::Equal => {
                    return gen_expr_cf(ctx, fb, expr);
                }
                _ => todo!(),
            }
        }
        ExprKind::Cast(from, to) => gen_expr_val(ctx, fb, from),
        ExprKind::Call(c, args) => match c {
            Call::Print => gen_call_print(ctx, fb, args),
            _ => todo!(),
        },
        ExprKind::Member(p, s, _) => {
            let addr = gen_expr_addr(ctx, fb, expr)?;
            let val = fb
                .ins()
                .load(to_clif_type(&expr.ty), MemFlags::trusted(), addr, 0);
            return Ok(val);
        }
        _ => todo!("{:?}", expr.kind),
    }
}

fn gen_expr_addr(ctx: &mut LocalContext, fb: &mut FunctionBuilder, expr: &Expr) -> Result<Value> {
    match &expr.kind {
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                return gen_expr_val(ctx, fb, e);
            }
            _ => todo!(),
        },
        ExprKind::Member(p, s, ma) => {
            let addr = gen_expr_addr(ctx, fb, p)?;
            if let Expr {
                kind: ExprKind::Ident(i),
                ..
            } = s.as_ref()
            {
                // todo: get real member offset
                return Ok(fb.ins().iadd_imm(addr, ma.as_ref().unwrap().offset as i64));
            }
            bail!("cant not parse")
        }
        ExprKind::Ident(i) => {
            if let Some(var) = ctx.vars.get(i) {
                return Ok(fb.use_var(*var));
            }
            unreachable!("ident {i}");
        }
        _ => todo!(),
    }
    todo!()
}

fn gen_load(ctx: &mut LocalContext, fb: &mut FunctionBuilder, addr: Value, ty: &bpfir::Type) {}

fn gen_call_print(
    ctx: &mut LocalContext,
    fb: &mut FunctionBuilder,
    args: &Vec<Expr>,
) -> Result<Value> {
    let mut values = vec![];
    let mut offsets = vec![];

    let mut print = Print::new();

    // print id
    values.push(fb.ins().iconst(I64, ctx.prints.len() as i64));
    offsets.push(print.add_type(&bpfir::Type::i64()));

    for arg in args {
        values.push(gen_expr_val(ctx, fb, arg)?);
        offsets.push(print.add_type(&arg.ty));
    }

    let addr = values_to_stack(fb, &values, &offsets, print.sz as i32);
    let fr = ctx.find_helper_function(libbpf_sys::BPF_FUNC_perf_event_output, fb);

    let ctx_val = fb.use_var(ctx.get_ctx());
    let map = ctx.find_map(__PERF_EVENT_MAP__, bpfir::Type::i64(), fb);
    let sz = fb.ins().iconst(I64, print.sz as i64);
    let flag = fb.ins().iconst(types::I64, 0xffffffff);
    let inst = fb.ins().call(fr, &vec![ctx_val, map, flag, addr, sz]);

    ctx.prints.push(print);
    Ok(fb.inst_results(inst)[0])
}

// Store the value on the stack and return the stack address
fn value_to_stack(fb: &mut FunctionBuilder, val: Value, ty: &bpfir::Type) -> Value {
    let ss = fb.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        type_size(ty),
    ));
    let addr = fb.ins().stack_addr(I64, ss, 0);
    let _ = fb.ins().stack_store(val, ss, 0);
    addr
}

fn values_to_stack(
    fb: &mut FunctionBuilder,
    values: &Vec<Value>,
    off: &Vec<i32>,
    sz: i32,
) -> Value {
    let ss = fb.create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, sz as u32));
    let addr = fb.ins().stack_addr(I64, ss, 0);

    for (&value, &off) in values.iter().zip(off) {
        let _ = fb.ins().stack_store(value, ss, off);
    }
    addr
}

fn type_size(ty: &bpfir::Type) -> u32 {
    match ty.kind {
        TypeKind::I8 => 1,
        TypeKind::U8 => 1,
        TypeKind::I16 => 2,
        TypeKind::U16 => 2,
        TypeKind::I32 => 4,
        TypeKind::U32 => 4,
        TypeKind::I64 => 8,
        TypeKind::U64 => 8,
        TypeKind::Ptr(_) => 8,
        TypeKind::Map(_, _, _, _) => 8,
        _ => todo!("{}", ty.to_string()),
    }
}

fn to_clif_type(ty: &bpfir::Type) -> types::Type {
    match ty.kind {
        TypeKind::Bool => types::I8,
        TypeKind::I8 => types::I8,
        TypeKind::U8 => types::I8,
        TypeKind::I16 => types::I16,
        TypeKind::U16 => types::I16,
        TypeKind::I32 => types::I32,
        TypeKind::U32 => types::I32,
        TypeKind::I64 => types::I64,
        TypeKind::U64 => types::I64,
        TypeKind::Ptr(_) => types::I64,
        TypeKind::Map(_, _, _, _) => types::I64,
        _ => todo!("{}", ty.to_string()),
    }
}

fn to_clif_binary(fb: &mut FunctionBuilder, op: &BinaryOp, x: Value, y: Value) -> Value {
    match op {
        BinaryOp::Add => fb.ins().iadd(x, y),
        BinaryOp::Sub => fb.ins().isub(x, y),
        BinaryOp::Mult => fb.ins().imul(x, y),
        BinaryOp::Div => fb.ins().sdiv(x, y),
        // BinaryOp::Mod  => fb.ins().smo
        // | BinaryOp::BitOr => fb.ins().bitor
        // | BinaryOp::BitAnd
        // | BinaryOp::BitXor
        _ => todo!(),
    }
}
