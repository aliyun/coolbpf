use std::collections::HashMap;

use crate::{
    btf::{btf_get_func_args, btf_get_func_returnty, btf_get_point_to, btf_type_is_ptr, btf_find_struct, btf_find_struct_member},
    types::{typeid_to_irtype, Constant, Type, TypeId, TypeKind, pt_regs_type},
    utils::btf::btf_locate_path,
};

use super::{ast::*, nodeid::NodeId};
use anyhow::{bail, Result};
use btfparse::{btf::Btf, btf_load};


pub struct TypeBinding {
    // todo: use typeid as index
    types: Vec<Type>,
    proj: Vec<usize>,             // projection between nodeid and types array
    gtbl: HashMap<String, usize>, // projection between identifier and types array
    ltbl: HashMap<String, usize>,
}

impl TypeBinding {
    pub fn new() -> Self {
        let mut u64 = Type::new(TypeKind::U64);
        u64.set_param();

        TypeBinding {
            types: vec![Type::default(), u64],
            proj: vec![0; NodeId::current()],
            gtbl: HashMap::from([
                ("arg0".to_owned(), 1),
                ("arg1".to_owned(), 1),
                ("arg2".to_owned(), 1),
                ("arg3".to_owned(), 1),
                ("arg4".to_owned(), 1),
            ]),
            ltbl: HashMap::new(),
        }
    }

    pub fn mut_type(&mut self, id: &NodeId) -> &mut Type {
        self.mut_type_idx(self.proj[id.id()])
    }

    pub fn type_(&self, id: &NodeId) -> &Type {
        self.type_by_idx(self.proj[id.id()])
    }

    pub fn mut_type_idx(&mut self, idx: usize) -> &mut Type {
        &mut self.types[idx]
    }

    pub fn type_by_idx(&self, idx: usize) -> &Type {
        &self.types[idx]
    }

    pub fn try_mut_type_ident(&mut self, ident: &String) -> Option<&mut Type> {
        if let Some(x) = self.ltbl.get(ident) {
            return Some(self.mut_type_idx(*x));
        }

        if let Some(x) = self.gtbl.get(ident) {
            return Some(self.mut_type_idx(*x));
        }

        None
    }

    pub fn reset_ltbl(&mut self) {
        // remove local table
        self.ltbl.clear();
    }

    pub fn bind(&mut self, id: &NodeId, ty: Type) -> usize {
        let idx = self.add_type(ty);
        self.bind_by_idx(id, idx);
        idx
    }

    pub fn bind_by_idx(&mut self, id: &NodeId, idx: usize) {
        self.proj[id.id()] = idx;
    }

    pub fn bind_lident(&mut self, ident: String, ty: Type) -> usize {
        let idx = self.add_type(ty);
        self.bind_lident_by_idx(ident, idx);
        idx
    }

    pub fn bind_lident_by_idx(&mut self, ident: String, idx: usize) {
        log::debug!(
            "Local identifier: {}, type: {}",
            ident,
            self.type_by_idx(idx)
        );
        self.ltbl.insert(ident, idx);
    }

    pub fn bind_gident(&mut self, ident: String, ty: Type) -> usize {
        log::debug!("Global identifier: {}, type: {}", ident, ty);
        let idx = self.add_type(ty);
        self.gtbl.insert(ident, idx);
        idx
    }

    pub fn lookup_ident(&self, ident: &String) -> Option<usize> {
        self.lookup_lident(ident).or(self.lookup_gident(ident))
    }

    pub fn lookup_lident(&self, ident: &String) -> Option<usize> {
        self.ltbl.get(ident).map(|x| *x)
    }

    pub fn lookup_gident(&self, ident: &String) -> Option<usize> {
        self.gtbl.get(ident).map(|x| *x)
    }

    fn add_type(&mut self, ty: Type) -> usize {
        let idx = self.types.len();
        self.types.push(ty);
        idx
    }
}

impl From<&Ast> for TypeBinding {
    fn from(ast: &Ast) -> Self {
        typer_inferring(ast)
    }
}

fn get_param_type_by_typeid(typeid: u32) -> Type {
    if btf_type_is_ptr(typeid) {
        let id = btf_get_point_to(typeid);
        let typ = Box::new(get_param_type_by_typeid(id));
        return Type::new(TypeKind::Ptr(typ));
    } else {
        let mut typ = Type::from_typeid(typeid);
        typ.set_kmem();
        return typ;
    }
}

fn typer_inferring(ast: &Ast) -> TypeBinding {
    let mut tb = TypeBinding::new();
    for expr in &ast.exprs {
        typer_inferring_program(&mut tb, expr).unwrap();
    }

    tb
}

fn typer_inferring_program(tb: &mut TypeBinding, expr: &Expr) -> Result<()> {
    let mut set_param = false;
    tb.reset_ltbl();

    match &expr.kind {
        ExprKind::Program(tys, e) => {
            for ty in tys {
                let idx = typer_inferring_ty(tb, ty);
                log::debug!("Determing Program type: {}", tb.type_by_idx(idx));
                if set_param {
                    continue;
                }
                // bind parameter type
                match tb.type_by_idx(idx).kind {
                    TypeKind::Kprobe(id) => {
                        id.map(|x| {
                            let pt_regs = pt_regs_type();
                            let tmp = vec!["di", "si", "dx", "cx", "r8", "sp"];
                            let mut count = 0;
                            for (name, typeid) in btf_get_func_args(x) {
                                let mut typ = get_param_type_by_typeid(typeid);
                                typ.set_param();
                                typ.set_offset(pt_regs.member_offset(tmp[count]));
                                tb.bind_lident(name, typ);
                                count += 1;
                            }
                            set_param = true;
                        });
                    }
                    TypeKind::Kretprobe(id) => {
                        id.map(|x| {
                            let typeid = btf_get_func_returnty(x);
                            let mut typ = get_param_type_by_typeid(typeid);
                            typ.set_param();
                            tb.bind_lident("retval".to_owned(), typ);

                            set_param = true;
                        });
                    }
                    _ => {}
                }
            }
            typer_inferring_expr(tb, e)?;
        }
        _ => {
            panic!("Could not found program entry")
        }
    }

    Ok(())
}

pub fn typer_inferring_expr(tb: &mut TypeBinding, expr: &Expr) -> Result<usize> {
    match &expr.kind {
        ExprKind::Compound(es) => {
            for e in es {
                typer_inferring_expr(tb, e)?;
            }
        }

        ExprKind::ExprStmt(e) => {
            typer_inferring_expr(tb, e)?;
        }

        ExprKind::If(c, t, e) => {
            let cidx = typer_inferring_expr(tb, c)?;
            typer_inferring_expr(tb, t)?;
            if let Some(x) = e {
                typer_inferring_expr(tb, x)?;
            }
        }

        ExprKind::Ident(name) => {
            let idx = typer_inferring_ident(tb, name)?;
            tb.bind_by_idx(&expr.id, idx);
            return Ok(idx);
        }

        ExprKind::LitStr(s) => {
            return Ok(tb.bind(&expr.id, Type::new(TypeKind::String)));
        }

        ExprKind::Const(c) => {
            return Ok(tb.bind(&expr.id, Type::from_constant(c)));
        }

        ExprKind::Unary(op, e) => {
            let idx = typer_inferring_expr(tb, e)?;
            match op {
                UnaryOp::Deref => {
                    let ty = tb.type_by_idx(idx);
                    assert!(ty.is_ptr());
                    let ty = ty.ptr_to();
                    return Ok(tb.bind(&expr.id, ty));
                }

                _ => {}
            }
        }

        ExprKind::Binary(op, l, r) => {
            let lt = typer_inferring_expr(tb, l);
            let rt = typer_inferring_expr(tb, r)?;

            // todo: check other op
            match op {
                BinaryOp::Assign => {
                    if let ExprKind::Ident(ident) = &l.kind {
                        tb.bind_lident_by_idx(ident.to_owned(), rt);
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
            let origin_type = typer_inferring_expr(tb, e)?;
            let new_type = typer_inferring_ty(tb, to);
            // todo: check origin_type and new_type if are compatible
            tb.bind_by_idx(&expr.id, new_type);
            return Ok(new_type);
        }

        ExprKind::BuiltinCall(b, args) => {
            let mut args_type = vec![];
            for arg in args {
                args_type.push(typer_inferring_expr(tb, arg)?);
            }
            let new_type = b.return_type(
                &args_type
                    .iter()
                    .map(|x| tb.type_by_idx(*x))
                    .collect::<Vec<&Type>>(),
            );
            // todo: check function input parameters type
            return Ok(tb.bind(&expr.id, new_type));
        }

        ExprKind::Member(p, s) => {
            let idx = typer_inferring_expr(tb, p)?;
            // todo: assert 's' must be identifier
            if let ExprKind::Ident(name) = &s.kind {
                let pty = tb.type_by_idx(idx);
                let sty = pty.find_member(name);

                return Ok(tb.bind(&expr.id, sty));
            }

            panic!("Unkown type of structure")
        }

        _ => {}
    }

    Ok(0)
}

fn typer_inferring_ty(tb: &mut TypeBinding, ty: &Ty) -> usize {
    let new_ty = Type::from_tykind(&ty.kind);
    tb.bind(&ty.id, new_ty)
}

fn typer_inferring_ident(tb: &mut TypeBinding, ident: &String) -> Result<usize> {
    tb.lookup_ident(ident)
        .map_or_else(|| bail!("Failed to find {}", ident), |x| Ok(x))
}
