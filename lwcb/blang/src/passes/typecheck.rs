use crate::btf::BTF;
use crate::call::Call;
use crate::parser::Ast;
use crate::parser::Expr;
use crate::parser::ExprKind;
use bpfir::types::BinaryOp;
use bpfir::types::Type;
use bpfir::types::TypeKind;
use bpfir::types::UnaryOp;
use std::collections::HashMap;

struct LocalContext<'a> {
    btf: &'a BTF<'a>,

    symbols: Vec<HashMap<String, Type>>,
    maps: HashMap<String, Type>,

    cur: usize,
}

impl<'a> LocalContext<'a> {
    fn get_map(&self, sym: &String) -> Type {
        let ty = self.maps.get(sym);
        if let Some(t) = ty {
            if let TypeKind::Map(_, _, _, _) = &t.kind {
                return t.clone();
            }
        }
        Type::undef()
    }
    fn get_map_val(&mut self, sym: &String) -> Type {
        let ty = self.maps.get(sym);
        if let Some(t) = ty {
            if let TypeKind::Map(_, _, _, v) = &t.kind {
                return *v.clone();
            }
        }
        Type::undef()
    }

    fn add_map_key(&mut self, sym: &String, key: &Type) {
        let ty = self.maps.entry(sym.clone()).or_insert(Type::map(
            libbpf_rs::MapType::Hash,
            0,
            Type::undef(),
            Type::undef(),
        ));
        if let TypeKind::Map(_, _, k, _) = &mut ty.kind {
            if k.is_undef() {
                *k = Box::new(key.clone());
            }
        }
    }

    fn add_map_val(&mut self, sym: &String, val: &Type) {
        let ty = self.maps.entry(sym.clone()).or_insert(Type::map(
            libbpf_rs::MapType::Hash,
            0,
            Type::undef(),
            Type::undef(),
        ));
        if let TypeKind::Map(_, _, _, v) = &mut ty.kind {
            if v.is_undef() {
                *v = Box::new(val.clone());
            }
        }
    }

    fn find_local_symbol(&self, name: &String) -> Option<&Type> {
        self.symbols[self.cur].get(name)
    }

    fn find_symbol(&self, name: &String) -> Option<&Type> {
        if let Some(ty) = self.symbols[self.cur].get(name) {
            return Some(ty);
        }
        self.maps.get(name)
    }

    fn add_symbol(&mut self, sym: &String, ty: &Type) {
        self.symbols[self.cur].insert(sym.clone(), ty.clone());
    }

    fn new_func(&mut self) {
        self.symbols.push(Default::default());
        self.cur = self.symbols.len() - 1;
    }

    fn set_cur(&mut self, cur: usize) {
        self.cur = cur;
    }
}

pub fn type_check<'a>(btf: &'a BTF, ast: &mut Ast) {
    let mut tc = LocalContext {
        btf,
        symbols: Default::default(),
        maps: Default::default(),
        cur: 0,
    };

    for expr in &mut ast.exprs {
        tc.new_func();
        tc.add_symbol(
            &"ctx".to_owned(),
            &Type::ptr(Type::struct_("pt_regs".into())),
        );
        type_check_func(&mut tc, expr);
    }

    for (idx, expr) in ast.exprs.iter_mut().enumerate() {
        tc.set_cur(idx);
        type_check_func(&mut tc, expr);
    }
}

fn type_check_func(tc: &mut LocalContext, expr: &mut Expr) {
    if let Expr {
        kind: ExprKind::Trace(x, y),
        ..
    } = expr
    {
        type_check_expr_trace(tc, x);
        type_check_expr(tc, y);
    } else {
        panic!("tracing declaration must be first")
    }
}

fn type_check_expr_trace(tc: &mut LocalContext, expr: &mut Expr) {
    if let ExprKind::Type(x) = &expr.kind {
        expr.ty = x.clone();
    } else {
        panic!("Expect tracing program type, found {:?}", expr.kind);
    }
}

fn type_check_expr(tc: &mut LocalContext, expr: &mut Expr) {
    match &mut expr.kind {
        ExprKind::Binary(o, l, r) => expr.ty = type_check_expr_bianry(tc, o, l, r),
        ExprKind::Call(c, args) => type_check_expr_call(tc, c, args),
        ExprKind::Cast(from, to) => {
            type_check_expr(tc, from);
            type_check_expr(tc, to);
            expr.ty = to.ty().clone();
        }
        ExprKind::Compound(es) => {
            for e in es {
                type_check_expr(tc, e);
            }
        }
        ExprKind::Constant(x) => return,
        ExprKind::ExprStmt(e) => type_check_expr(tc, e),
        ExprKind::Ident(x) => {
            if let Some(ty) = tc.find_symbol(x) {
                expr.ty = ty.clone();
            }
        }
        ExprKind::If(c, t, e) => {
            c.ty = Type::bool();
            type_check_expr(tc, t);
            if let Some(x) = e.as_mut() {
                type_check_expr(tc, x);
            }
        }
        ExprKind::LitStr(_) => {
            expr.ty = Type::string();
        }
        ExprKind::Member(p, s, attr) => {
            type_check_expr(tc, p);

            if let Expr {
                kind: ExprKind::Ident(i),
                ..
            } = s.as_ref()
            {
                let mut ty = &p.ty;
                // For structure pointers, we can automatically dereference
                if let TypeKind::Ptr(t) = &ty.kind {
                    ty = t;
                }

                if let TypeKind::Struct(x) = &ty.kind {
                    let (id, ma) = tc
                        .btf
                        .find_member(tc.btf.find_by_name(x).unwrap(), i)
                        .expect("failed to resolve type");

                    log::debug!(
                        "member {i} offset: {}, bitfield_offset: {}, bitfield_size: {}",
                        ma.offset,
                        ma.bitfield_offset,
                        ma.bitfield_size
                    );
                    *attr = Some(ma);

                    expr.ty = tc.btf.to_type(id);
                    return;
                }
            }

            panic!("Something wrong with member expression");
        }
        ExprKind::Return => todo!(),
        ExprKind::Type(ty) => {
            expr.ty = ty.clone();
        }
        ExprKind::Unary(op, e) => match op {
            UnaryOp::Deref => {
                type_check_expr(tc, e);
                if let Type {
                    kind: TypeKind::Ptr(p),
                    ..
                } = e.ty()
                {
                    expr.ty = *p.clone();
                    return;
                }
                panic!("expect pointer type");
            }
            UnaryOp::Neg => {
                type_check_expr(tc, e);
                expr.ty = e.ty.clone();
            }
            _ => todo!(),
        },
        _ => todo!("{:?}", expr),
    }
}

fn type_check_expr_bianry(
    tc: &mut LocalContext,
    op: &BinaryOp,
    l: &mut Expr,
    r: &mut Expr,
) -> Type {
    type_check_expr(tc, l);
    type_check_expr(tc, r);
    assert!(!r.ty.is_undef());
    match op {
        BinaryOp::Assign => {
            match &l.kind {
                ExprKind::Ident(i) => {
                    log::debug!("{} <- {:?}", i, r.ty.kind);
                    l.ty = r.ty().clone();
                    tc.add_symbol(i, &l.ty);
                }
                ExprKind::Binary(op2, lhs, _) => match op2 {
                    BinaryOp::Index => {
                        if let ExprKind::Ident(i) = &lhs.kind {
                            tc.add_map_val(i, &r.ty);
                        }
                    }
                    _ => todo!(),
                },
                _ => todo!(),
            }
            return Type::undef();
        }
        BinaryOp::Index => {
            if let ExprKind::Ident(i) = &l.kind {
                tc.add_map_key(i, &r.ty);
                l.ty = tc.get_map(i);
                log::debug!("{} <- {:?}", i, l.ty.kind);
                return tc.get_map_val(i);
            } else {
                panic!("map is not a identifier");
            }
        }
        BinaryOp::Add => l.ty.clone(),
        BinaryOp::Sub => l.ty.clone(),
        BinaryOp::Div => l.ty.clone(),
        BinaryOp::Mult => l.ty.clone(),
        BinaryOp::Equal
        | BinaryOp::GT
        | BinaryOp::NonEqual
        | BinaryOp::GTE
        | BinaryOp::LT
        | BinaryOp::LTE => Type::bool(),

        _ => {
            todo!("not implment {op}");
        }
    }
}

fn type_check_expr_call(tc: &mut LocalContext, c: &Call, args: &mut Vec<Expr>) {
    for arg in args {
        type_check_expr(tc, arg);
    }
    match c {
        _ => {}
    }
}
