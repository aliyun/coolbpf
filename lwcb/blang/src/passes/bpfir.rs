use crate::{
    constant::Constant,
    parser::{Ast, Expr, ExprKind},
};

use anyhow::{bail, Result};
use bpfir::types::BinaryOp;
use bpfir::types::UnaryOp;
use generational_arena::Arena;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::{HashMap, HashSet},
    default,
};

use bpfir::FuncData;
use bpfir::Module;
use bpfir::Value;
use bpfir::ValueData;
use bpfir::ValueKind;
use bpfir::{tmp_unique_name, unique_name};
use bpfir::{Type, TypeKind};

pub fn gen_bpfir(ast: &Ast) -> Result<Module> {
    let mut module = Module::new("blang");
    for expr in &ast.exprs {
        if let Expr {
            kind: ExprKind::Trace(names, body),
            ..
        } = expr
        {
            log::debug!("generate bpfir for program: {:?}", names);
            let func = match &names.ty().kind {
                TypeKind::Kprobe(x) | TypeKind::Kretprobe(x) => module.new_func(x),
                _ => panic!("{:#?}", 1),
            };
            gen_stmt(module.mut_func_data(func), body)?;
            // seal others block
            return Ok(module);
        }
    }
    todo!()
}

fn gen_stmt(fd: &mut FuncData, e: &Expr) -> Result<()> {
    let curr_block = fd.curr_block;
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

fn gen_if_stmt(fd: &mut FuncData, c: &Expr, t: &Expr, e: &Option<Expr>) {
    todo!();

    let then_block = fd.cfg.new_bblock(unique_name("IF_THEN").as_str());

    fd.set_curr_block(then_block);

    gen_stmt(fd, t);

    let then_exit = fd.curr_block;

    if let Some(x) = e {}
}

fn gen_expr_cf(fd: &mut FuncData, c: &Expr) {}

fn gen_expr(fd: &mut FuncData, expr: &Expr) {
    gen_expr_val(fd, expr).expect("failed to generate ir for expression");
}

fn gen_expr_val(fd: &mut FuncData, expr: &Expr) -> Result<Value> {
    let curr_block = fd.curr_block;
    match &expr.kind {
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                let addr = gen_expr_val(fd, e)?;
                if let TypeKind::Ptr(x) = &expr.ty.kind {
                    let vd = ValueData::new(
                        tmp_unique_name().as_str(),
                        ValueKind::Load(addr),
                        expr.ty.clone(),
                        curr_block,
                    );
                    return Ok(fd.cfg.new_value(curr_block, vd));
                }
                return Ok(addr);
            }
            _ => todo!(),
        },
        ExprKind::Ident(i) => {
            return Ok(fd.cfg.read_variable(curr_block, i));
        }
        ExprKind::Constant(c) => {
            let vd = ValueData::new(
                tmp_unique_name().as_str(),
                ValueKind::Constant(c.clone()),
                expr.ty.clone(),
                curr_block,
            );
            return Ok(fd.cfg.new_value(curr_block, vd));
        }
        ExprKind::Binary(op, l, r) => match op {
            BinaryOp::Assign => {
                let val = gen_expr_val(fd, r)?;
                if let Expr {
                    kind: ExprKind::Ident(i),
                    ..
                } = l.as_ref()
                {
                    let vd = ValueData::new(i, ValueKind::Assign(val), l.ty.clone(), curr_block);
                    let res = fd.cfg.new_value(curr_block, vd);
                    fd.cfg.write_variable(curr_block, i, res);
                    return Ok(res);
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
            let vd = ValueData::new(
                tmp_unique_name().as_str(),
                ValueKind::Load(addr),
                expr.ty.clone(),
                curr_block,
            );
            return Ok(fd.cfg.new_value(curr_block, vd));
        }
        _ => todo!(),
    }
}

fn gen_expr_addr(fd: &mut FuncData, expr: &Expr) -> Result<Value> {
    let curr_block = fd.curr_block;
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
                let vd = ValueData::new(
                    tmp_unique_name().as_str(),
                    ValueKind::Member(addr, i.clone()),
                    expr.ty.clone(),
                    curr_block,
                );
                return Ok(fd.cfg.new_value(curr_block, vd));
            }
            bail!("cant not parse")
        }

        ExprKind::Ident(i) => {
            return Ok(fd.cfg.read_variable(curr_block, i));
        }

        _ => todo!(),
    }
}
