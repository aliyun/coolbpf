use crate::constant::Constant;
use crate::parser::Ast;
use crate::parser::Expr;
use crate::parser::ExprKind;

use anyhow::bail;
use anyhow::Result;
use bpfir::types::BinaryOp;
use bpfir::types::UnaryOp;
use generational_arena::Arena;
use std::collections::HashMap;
use std::collections::HashSet;
use std::default;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bpfir::mir::*;
use bpfir::tmp_unique_name;
use bpfir::unique_name;
use bpfir::Type;
use bpfir::TypeKind;

pub fn gen_bpfir(ast: &Ast) -> Result<Module> {
    let mut module = Module::new();
    for expr in &ast.exprs {
        if let Expr {
            kind: ExprKind::Trace(names, body),
            ..
        } = expr
        {
            log::debug!("generate bpfir for program: {:?}", names);
            let mut fd = FunctionData::new(names.ty.clone());

            let vd = VariableData::new(
                Type::ptr(Type::struct_("pt_regs".to_owned())),
                Some("ctx".to_owned()),
            );
            let var = fd.new_variable(vd);
            fd.add_param(var);
            let func = module.new_function(fd);
            gen_stmt(module.mut_function_data(func), body)?;
            return Ok(module);
        }
    }
    todo!()
}

fn gen_stmt(fd: &mut FunctionData, e: &Expr) -> Result<()> {
    match &e.kind {
        ExprKind::ExprStmt(expr) => {
            gen_expr(fd, expr);
        }

        ExprKind::Return => {
            todo!()
        }

        ExprKind::Compound(exprs) => {
            for expr in exprs {
                gen_stmt(fd, expr)?;
            }
        }

        ExprKind::If(_, _, _) => todo!(),

        _ => todo!(),
    }

    Ok(())
}

fn gen_if_stmt(fd: &mut FunctionData, c: &Expr, t: &Expr, e: &Option<Expr>) {
    todo!();

    // let then_block = fd.cfg.new_bblock(unique_name("IF_THEN").as_str());

    // fd.set_curr_block(then_block);

    // gen_stmt(fd, t);

    // let then_exit = fd.curr_block;

    if let Some(x) = e {}
}

fn gen_expr_cf(fd: &mut FunctionData, c: &Expr) {}

fn gen_expr(fd: &mut FunctionData, expr: &Expr) {
    gen_expr_val(fd, expr).expect("failed to generate ir for expression");
}

fn gen_expr_val(fd: &mut FunctionData, expr: &Expr) -> Result<Variable> {
    let current_block = fd.current_block();
    match &expr.kind {
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                let addr = gen_expr_val(fd, e)?;
                if let TypeKind::Ptr(x) = &expr.ty.kind {
                    let vd = VariableData::new(expr.ty.clone(), None);
                    let dst = fd.new_variable(vd);
                    fd.mut_block_data(current_block)
                        .add_instruction(Instruction::Load(dst, addr));
                    return Ok(dst);
                }
                return Ok(addr);
            }
            _ => todo!(),
        },
        ExprKind::Ident(i) => {
            return Ok(fd.read_variable(i));
        }
        ExprKind::Constant(c) => {
            let vd = VariableData::new(expr.ty.clone(), None);
            let var = fd.new_variable(vd);
            Instruction::AssignImm(var, *c);
            return Ok(var);
        }
        ExprKind::Binary(op, l, r) => match op {
            BinaryOp::Assign => {
                let rvar = gen_expr_val(fd, r)?;
                if let Expr {
                    kind: ExprKind::Ident(i),
                    ..
                } = l.as_ref()
                {
                    let vd = VariableData::new(l.ty.clone(), Some(i.clone()));
                    let lvar = fd.new_variable(vd);
                    Instruction::Assign(lvar, rvar);
                    return Ok(rvar);
                }
                todo!()
            }
            _ => todo!(),
        },
        ExprKind::Cast(from, to) => gen_expr_val(fd, from),
        ExprKind::Call(c, args) => {
            todo!()
        }
        ExprKind::Member(p, s) => {
            let mut addr = gen_expr_addr(fd, expr)?;
            if let TypeKind::Ptr(x) = &expr.ty.kind {
                let vd = VariableData::new(expr.ty.clone(), None);
                let dst = fd.new_variable(vd);
                fd.mut_block_data(current_block)
                    .add_instruction(Instruction::Load(dst, addr));
                return Ok(dst);
            }
            return Ok(addr);
        }
        _ => todo!(),
    }
}

fn gen_expr_addr(fd: &mut FunctionData, expr: &Expr) -> Result<Variable> {
    let current_block = fd.current_block();
    match &expr.kind {
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                return gen_expr_val(fd, e);
            }
            _ => todo!(),
        },
        ExprKind::Member(p, s) => {
            let addr = gen_expr_addr(fd, p)?;
            if let Expr {
                kind: ExprKind::Ident(i),
                ..
            } = s.as_ref()
            {
                let vd = VariableData::new(expr.ty.clone(), None);
                let var = fd.new_variable(vd);
                let inst = Instruction::Member(var, addr, i.clone());
                fd.mut_block_data(current_block).add_instruction(inst);
                return Ok(var);
            }
            bail!("cant not parse")
        }

        ExprKind::Ident(i) => {
            return Ok(fd.read_variable(i));
        }

        _ => todo!(),
    }
}
