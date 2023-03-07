use std::collections::HashMap;

use crate::types::{Constant, Type, TypeKind};

use super::ast::*;
use anyhow::{bail, Result};

pub fn typer_inferring(Ast { exprs }: &mut Ast) {
    let mut gtbl = HashMap::new();
    for expr in exprs {
        typer_inferring_program(&mut gtbl, expr);
    }
}

pub fn typer_inferring_program(
    gtbl: &mut HashMap<String, Type>,
    Expr { kind, span, typ_ }: &mut Expr,
) -> Result<()> {
    let mut tbl = HashMap::new();
    match kind {
        ExprKind::Program(tys, e) => {
            for ty in tys {
                typer_inferring_ty(ty)?;
            }
            typer_inferring_expr(gtbl, &mut tbl, e)?;
        }
        _ => {
            panic!("Could not found program entry")
        }
    }

    Ok(())
}

pub fn typer_inferring_expr(
    gtbl: &mut HashMap<String, Type>,
    tbl: &mut HashMap<String, Type>,
    Expr { kind, span, typ_ }: &mut Expr,
) -> Result<Option<Type>> {
    match kind {
        ExprKind::Program(tys, e) => {
            for ty in tys {
                typer_inferring_ty(ty)?;
            }
            typer_inferring_expr(gtbl, tbl, e)?;
        }

        ExprKind::Compound(exprs) => {
            for expr in exprs {
                typer_inferring_expr(gtbl, tbl, expr)?;
            }
        }

        ExprKind::ExprStmt(expr) => {
            typer_inferring_expr(gtbl, tbl, expr)?;
        }

        ExprKind::If(c, t, e) => {}

        ExprKind::Ident(name) => {
            return Ok(typer_inferring_ident(gtbl, tbl, name)?);
        }

        ExprKind::LitStr(s) => {}

        ExprKind::Const(c) => {
            *typ_ = Type::from_constant(c);

            return Ok(Some((*typ_).clone()));
        }

        ExprKind::Unary(op, e) => {
            let typ = typer_inferring_expr(gtbl, tbl, e)?;
            match op {
                UnaryOp::Deref => {
                    if let Some(ty) = typ {
                        assert!(ty.is_ptr());
                        *typ_ = ty.ptr_to();
                        return Ok(Some((*typ_).clone()));
                    }
                    bail!("Deref type is not specified")
                }

                _ => {}
            }
        }

        ExprKind::Binary(op, l, r) => {
            let lt = typer_inferring_expr(gtbl, tbl, l)?;
            let rt = typer_inferring_expr(gtbl, tbl, r)?;

            // todo: check other op
            match op {
                BinaryOp::Assign => {
                    if let ExprKind::Ident(ident) = &l.kind {
                        tbl.insert(ident.to_owned(), rt.ok_or(anyhow::anyhow!("None type"))?);
                    }
                }

                // BinaryOp::Index => {
                //     if lt.is_none() {
                //         // it's a map
                //         let mut lt_map = Type::new(TypeKind::Map(
                //             Box::new(Type::default()),
                //             Box::new(Type::default()),
                //         ));

                //         lt_map.update_mapkey(rt.ok_or(anyhow::anyhow!("None type"))?)?;

                //         if let ExprKind::Ident(ident) = &l.kind {
                //             tbl.insert(ident.to_owned(), lt_map);
                //         }
                //     }
                // }
                _ => {}
            }
        }

        ExprKind::Cast(e, to) => {
            let origin_type = typer_inferring_expr(gtbl, tbl, e)?;
            let new_type = typer_inferring_ty(to)?;
            // todo: check origin_type and new_type if are compatible
            *typ_ = new_type;
            return Ok(Some((*typ_).clone()));
        }

        ExprKind::BuiltinCall(b, args) => {
            let mut args_type = vec![];
            for arg in args {
                args_type.push(typer_inferring_expr(gtbl, tbl, arg)?);
            }
            // todo: check function input parameters type
            if let Some(typ) = b.return_type() {
                *typ_ = typ;
                return Ok(Some((*typ_).clone()));
            }
            return Ok(None);
        }

        ExprKind::Member(p, s) => {
            if let Some(pty) = typer_inferring_expr(gtbl, tbl, p)? {
                // todo: assert 's' must be identifier
                if let ExprKind::Ident(name) = &s.kind {
                    let sty = pty.find_member(name);
                    *typ_ = sty;
                    return Ok(Some((*typ_).clone()));
                }
                bail!("member not a identifier")
            }

            panic!("Unkown type of structure")
        }

        _ => todo!(),
    }

    Ok(None)
}

fn typer_inferring_ty(Ty { kind, span, typ_ }: &mut Ty) -> Result<Type> {
    let ty = Type::from_tykind(kind);
    *typ_ = ty;
    Ok((*typ_).clone())
}

fn typer_inferring_ident(
    gtbl: &mut HashMap<String, Type>,
    tbl: &mut HashMap<String, Type>,
    ident: &String,
) -> Result<Option<Type>> {
    if let Some(t) = tbl.get(ident) {
        return Ok(Some(t.clone()));
    }

    if let Some(t) = gtbl.get(ident) {
        return Ok(Some(t.clone()));
    }

    Ok(None)
}
