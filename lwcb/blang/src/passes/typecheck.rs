use std::collections::HashMap;

use crate::{
    btf::BTF,
    call::Call,
    parser::{Ast, Expr, ExprKind},
};

use bpfir::types::{BinaryOp, Type, TypeKind, UnaryOp};

use anyhow::{bail, Result};

pub struct TypeCheck<'a> {
    btf: &'a BTF<'a>,

    symbols: HashMap<String, Type>,
}

pub fn type_check<'a>(btf: &'a BTF, ast: &mut Ast) -> Result<()> {
    let mut tc = TypeCheck {
        btf,
        symbols: HashMap::default(),
    };

    tc.symbols
        .insert("ctx".to_owned(), Type::ptr(Type::struct_("pt_regs".into())));

    for expr in &mut ast.exprs {
        if let Expr {
            kind: ExprKind::Trace(x, y),
            ..
        } = expr
        {
            type_check_expr_trace(&mut tc, x)?;
            type_check_expr(&mut tc, y)?;
        } else {
            bail!("tracing declaration must be first")
        }
    }

    Ok(())
}

fn type_check_expr_trace(tc: &mut TypeCheck, expr: &mut Expr) -> Result<()> {
    if let ExprKind::Type(x) = &expr.kind {
        expr.ty = x.clone();
    } else {
        panic!()
    }
    Ok(())
}

fn type_check_expr(tc: &mut TypeCheck, expr: &mut Expr) -> Result<()> {
    match &mut expr.kind {
        ExprKind::Binary(o, l, r) => type_check_expr_bianry(tc, o, l, r),
        ExprKind::Call(c, args) => type_check_expr_call(tc, c, args),
        ExprKind::Cast(from, to) => {
            type_check_expr(tc, from)?;
            type_check_expr(tc, to)?;
            expr.ty = to.ty().clone();
            return Ok(());
        }
        ExprKind::Compound(es) => {
            for e in es {
                type_check_expr(tc, e)?;
            }
            return Ok(());
        }
        ExprKind::Constant(x) => Ok(()),
        ExprKind::ExprStmt(e) => type_check_expr(tc, e),
        ExprKind::Ident(x) => {
            tc.symbols
                .get(x)
                .map_or(Err(anyhow::anyhow!("failed to find symbol:{}", x)), |ty| {
                    expr.ty = ty.clone();
                    Ok(())
                })
        }
        ExprKind::If(_, _, _) => todo!(),
        ExprKind::LitStr(_) => {
            expr.ty = Type::string();
            return Ok(());
        }
        ExprKind::Member(p, s) => {
            type_check_expr(tc, p)?;

            if let Expr {
                kind: ExprKind::Ident(i),
                ..
            } = s.as_ref()
            {
                // tc.btf.find_member(id, name)
            }

            return Ok(());
        }
        ExprKind::Return => Ok(()),
        ExprKind::Type(ty) => {
            expr.ty = ty.clone();
            return Ok(());
        }
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                type_check_expr(tc, e)?;
                if let Type {
                    kind: TypeKind::Ptr(p),
                    ..
                } = e.ty()
                {
                    expr.ty = *p.clone();
                    return Ok(());
                }
                bail!("not a pointer")
            }
            _ => todo!(),
        },
        _ => todo!("{:?}", expr),
    }
}

fn type_check_expr_bianry(
    tc: &mut TypeCheck,
    op: &BinaryOp,
    l: &mut Expr,
    r: &mut Expr,
) -> Result<()> {
    match op {
        BinaryOp::Assign => {
            type_check_expr(tc, r)?;
            if let Expr {
                kind: ExprKind::Ident(i),
                ..
            } = l
            {
                l.ty = r.ty().clone();
                tc.symbols.insert(i.clone(), l.ty.clone());
            }
        }
        _ => todo!(),
    }

    Ok(())
}

fn type_check_expr_call(tc: &mut TypeCheck, c: &Call, args: &mut Vec<Expr>) -> Result<()> {
    todo!()
}
