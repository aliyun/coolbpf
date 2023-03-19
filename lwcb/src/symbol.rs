// use std::{collections::HashMap, rc::Rc, cell::RefCell};

// use crate::{
//     btf::{btf_find_struct, try_btf_find_func},
//     newast::ast::*,
//     types::{Type, TypeKind},
// };

// use anyhow::Result;

// pub struct Symbol {
//     ty: Type,
// }

// pub struct Symbols {
//     syms: HashMap<String, Symbol>,
//     gsyms: Rc<RefCell<Symbols>>,
// }

// fn gen_ty(ty: &Ty) -> Type {
//     Type::from_ty(ty)
// }

// fn gen_expr(tbl: Symbol, expr: &Expr) -> Result<Option<Type>>{
//     match &expr.kind {
//         ExprKind::Compound(c) => {
//             for mut i in c {
//                 gen_expr(tbl, i)?;
//             }
//             return Ok(None);
//         }

//         ExprKind::ExprStmt(s) => {
//             return gen_expr(tbl, &s);
//         }

//         ExprKind::If(c, t, se) => {
//             let ct = gen_expr(tbl, c)?;
//             let tt = gen_expr(tbl, t)?;
//             if let Some(e) = se {
//                 let et = gen_expr(tbl, e)?;
//             }
//             return Ok(None);
//         }

//         ExprKind::Ident(name) => {

//         }

//         ExprKind::Str(s) => {}

//         ExprKind::Num(n) => {}

//         ExprKind::Const(c) => {}

//         ExprKind::Unary(op, e) => {}

//         ExprKind::Binary(op, l, r) => {}

//         ExprKind::Cast(e, to) => {}

//         ExprKind::BuiltinCall(b, args) => {}

//         ExprKind::Member(p, s) => {}

//         _ => todo!("Not implemented or unexpected behavior"),
//     }
// }

// impl Symbols {
//     pub fn new(gsym: &mut Symbols, func: &Type, program: &Expr) {}

//     pub fn lookup(&self, name: &str) -> Option<&Symbol> {
//         self.syms.get(name)
//     }

    
// }
