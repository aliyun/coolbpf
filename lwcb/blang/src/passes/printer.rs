use std::collections::HashMap;

use crate::{
    btf::BTF,
    call::Call,
    parser::{Ast, BinaryOp, Expr, ExprKind, UnaryOp},
    types::{Type, TypeKind},
};

use anyhow::{bail, Result};

pub fn printer(ast: &Ast)  {
    for expr in &ast.exprs {
        if let Expr {
            kind: ExprKind::Trace(x, y),
            ..
        } = expr
        {
            printer_expr_trace(x);
            printer_expr(y);
        }
    }

}

fn printer_expr_trace(expr: &Expr) {
    if let ExprKind::Type(ty) = &expr.kind {
        match ty.kind {
            TypeKind::Kprobe(x) => {
                print!("kprobe:{}", x);
            }
            TypeKind::Kretprobe(x) => {
                print!("kretprobe:{}", x);
            }
            _ => print!("error!")
        }
    }
}

fn printer_expr(expr: &Expr) {
    match &expr.kind {
        ExprKind::Binary(o, l, r) => printer_expr_bianry(o, l, r),
        ExprKind::Call(c, args) => todo!(),
        ExprKind::Cast(from, to) => {
            printer_expr(to);
            printer_expr(from);
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
        ExprKind::Unary(op, e) => {
            match op {
                UnaryOp::Deref => {
                    type_check_expr(tc, e)?;
                    if let Type { kind: TypeKind::Ptr(p),.. }  = e.ty() {
                        expr.ty = *p.clone();
                        return Ok(());
                    }
                    bail!("not a pointer")
                }
                _ => todo!()
            }
        }
        _ => todo!("{:?}", expr),
    }
}

fn printer_expr_bianry(
    op: &BinaryOp,
    l: &Expr,
    r: &Expr,
) -> Result<()> {
    match op {
        BinaryOp::Assign => {
            printer_expr(l);
            print!("=");
            printer_expr(r);
            println!("");
        }
        _ => todo!(),
    }

    Ok(())
}
