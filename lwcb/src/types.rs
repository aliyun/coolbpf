use std::fmt;
use std::ops;

use anyhow::{bail, Result};

use crate::btf::btf_find_struct;
use crate::btf::btf_find_struct_member;
use crate::btf::try_btf_find_func;
use crate::newast::ast::Ty;
use crate::newast::ast::TyKind;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum Types {
    Void,
    Char,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    String,
    Pointer,
    Struct,
    Union,
}

impl fmt::Display for Types {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Types::Void => write!(f, "void"),
            _ => unimplemented!(),
        }
    }
}

impl From<&Constant> for Types {
    fn from(c: &Constant) -> Self {
        match c {
            Constant::Char(_) => Self::Char,
            Constant::I32(_) => Self::I32,
            _ => unimplemented!(),
        }
    }
}

/// A generic identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct Identifier {
    pub name: String,
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.name)
    }
}

impl From<&str> for Identifier {
    fn from(val: &str) -> Self {
        Identifier {
            name: val.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Constant {
    Bool(bool),
    Char(char),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
}

impl Into<i32> for Constant {
    fn into(self) -> i32 {
        match self {
            Constant::I32(x) => x,
            Constant::U32(x) => x as i32,
            Constant::I16(x) => x as i32,

            _ => unimplemented!(),
        }
    }
}

impl From<i32> for Constant {
    fn from(x: i32) -> Self {
        Constant::I32(x)
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constant::I32(x) => write!(f, "{}:i32", x),
            _ => unimplemented!(),
        }
    }
}

impl Constant {
    pub fn number(radix: usize, value_str: &str) -> Self {
        /*
         * todo: default type is i32, but we need to infer type in some cases.
         * For example, 0xffffffff should be u32
         */
        Constant::I32(value_str.parse().expect("Not a number"))
    }

    pub fn type_(&self) -> Types {
        match self {
            Constant::I16(_) => Types::I16,
            Constant::I32(_) => Types::I32,
            _ => unimplemented!(),
        }
    }

    pub fn type_size(&self) -> usize {
        match self {
            Constant::Char(_) | Constant::Bool(_) | Constant::I8(_) | Constant::U8(_) => 1,
            Constant::I16(_) | Constant::U16(_) => 2,
            Constant::I32(_) | Constant::U32(_) => 4,
            Constant::I64(_) | Constant::U64(_) => 8,
        }
    }

    pub fn type_signed(&self) -> bool {
        match self {
            Constant::I8(_) | Constant::I16(_) | Constant::I32(_) | Constant::I64(_) => true,
            Constant::U8(_) | Constant::U16(_) | Constant::U32(_) | Constant::U64(_) => false,
            _ => panic!("Char or Bool could not be determined if signed"),
        }
    }

    pub fn is_bool(&self) -> bool {
        if let Constant::Bool(_) = self {
            return true;
        }
        false
    }

    pub fn is_char(&self) -> bool {
        if let Constant::Char(_) = self {
            return true;
        }
        false
    }
}

fn add<T: ops::Add + ops::Add<Output = T>>(x: T, y: T) -> T {
    x + y
}

fn mul<T: ops::Mul + ops::Mul<Output = T>>(x: T, y: T) -> T {
    x * y
}

// lhs has higher priority
fn constant_op(op: char, lhs: Constant, rhs: Constant) -> Constant {
    match lhs {
        Constant::I32(x) => {
            let y: i32 = rhs.into();
            match op {
                '+' => add(x, y).into(),
                '*' => mul(x, y).into(),
                _ => unimplemented!(),
            }
        }
        _ => unimplemented!(),
    }
}

impl ops::Sub<&Constant> for &Constant {
    type Output = Constant;
    fn sub(self, rhs: &Constant) -> Self::Output {
        todo!()
    }
}

impl ops::Add<Constant> for Constant {
    type Output = Constant;
    fn add(self, rhs: Constant) -> Self::Output {
        if self.type_() > rhs.type_() {
            constant_op('+', self, rhs)
        } else {
            constant_op('+', rhs, self)
        }
    }
}

impl ops::Div<&Constant> for &Constant {
    type Output = Constant;
    fn div(self, rhs: &Constant) -> Self::Output {
        todo!()
    }
}

impl ops::Mul<Constant> for Constant {
    type Output = Constant;
    fn mul(self, rhs: Constant) -> Self::Output {
        if self.type_() > rhs.type_() {
            constant_op('*', self, rhs)
        } else {
            constant_op('*', rhs, self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Constant;

    #[test]
    fn test_constant_add() {
        let c1 = Constant::I32(1);
        let c2 = Constant::I32(2);
        assert_eq!(c1 + c2, Constant::I32(3));
        let c3 = Constant::I16(4);
        assert_eq!(c1 + c3, Constant::I32(5));
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeKind {
    TypeID(u32), // btf type id
    Void,
    Char,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    String,
    Ptr(Box<Type>),
    Struct(Box<Type>),
    Union(Box<Type>),

    Tuple(Vec<Type>),
    Map(Box<Type>, Box<Type>), // key type and value type
    Func(Option<u32>),         // func proto typeid
    Default,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Type {
    pub kind: TypeKind,
}

impl Default for Type {
    fn default() -> Self {
        Self {
            kind: TypeKind::Default,
        }
    }
}

impl Type {
    pub fn new(kind: TypeKind) -> Self {
        Self { kind }
    }

    pub fn typid(&self) -> u32 {
        if let TypeKind::TypeID(x) = self.kind {
            return x;
        }
        panic!("is not typeid")
    }

    pub fn is_ptr(&self) -> bool {
        if let TypeKind::Ptr(_) = &self.kind {
            return true;
        }
        false
    }

    pub fn ptr_to(&self) -> Self {
        if let TypeKind::Ptr(p) = &self.kind {
            return (**p).clone();
        }
        panic!("Not a pointer")
    }

    // get type from member
    pub fn find_member(&self, name: &str) -> Self {
        // must be struct or union
        match &self.kind {
            TypeKind::Struct(x) | TypeKind::Union(x) => {
                let typeid = x.typid();
                return Type::from_typeid(btf_find_struct_member(typeid, name).unwrap().type_id);
            }
            _ => {panic!("target is not struct or union")}
        }
    }

    pub fn update_mapkey(&mut self, key: Type) -> Result<()>{
        todo!()
    }

    pub fn update_mapval(&mut self, val: Type) -> Result<()>{
        todo!()
    }

    pub fn from_typeid(typeid: u32) -> Self {
        Self::new(TypeKind::TypeID(typeid))
    }

    pub fn from_func(name: &str) -> Self {
        Self::new(TypeKind::Func(try_btf_find_func(&name)))
    }

    pub fn from_constant(c: &Constant) -> Self {
        let type_kind = match c {
            Constant::Bool(_) => TypeKind::Bool,
            Constant::Char(_) => TypeKind::Char,
            Constant::I8(_) => TypeKind::I8,
            Constant::U8(_) => TypeKind::U8,
            Constant::I16(_) => TypeKind::I16,
            Constant::U16(_) => TypeKind::U16,

            Constant::I32(_) => TypeKind::I32,
            Constant::U32(_) => TypeKind::U32,
            Constant::I64(_) => TypeKind::I64,
            Constant::U64(_) => TypeKind::U64,
        };

        Self::new(type_kind)
    }

    pub fn from_tykind(ty_kind: &TyKind) -> Self {
        let type_kind = match &ty_kind {
            TyKind::Void => TypeKind::Void,
            TyKind::Char => TypeKind::Char,
            TyKind::Bool => TypeKind::Bool,
            TyKind::I8 => TypeKind::I8,
            TyKind::U8 => TypeKind::U8,
            TyKind::I16 => TypeKind::I16,
            TyKind::U16 => TypeKind::U16,
            TyKind::I32 => TypeKind::I32,
            TyKind::U32 => TypeKind::U32,
            TyKind::I64 => TypeKind::I64,
            TyKind::U64 => TypeKind::U64,
            TyKind::String => TypeKind::String,
            TyKind::Struct(name) => {
                TypeKind::Struct(Box::new(Type::new(TypeKind::TypeID(btf_find_struct(name)))))
            }
            TyKind::Union(name) => TypeKind::Struct(Box::new(Type::new(TypeKind::TypeID(
                btf_find_struct(&name),
            )))),
            TyKind::Ptr(t) => TypeKind::Ptr(Box::new(Self::from_tykind(&t.kind))),

            TyKind::Kprobe(name) => TypeKind::Func(try_btf_find_func(&name)),
            TyKind::Kretprobe(name) => TypeKind::Func(try_btf_find_func(&name)),
        };

        Type::new(type_kind)
    }
}

// pub fn gen_type(ast: &Ast) -> Result<()> {
//     let mut tt = HashMap::new();
//     tt.insert("arg0".to_owned(), Type::new(TypeKind::U64));
//     tt.insert("arg1".to_owned(), Type::new(TypeKind::U64));
//     tt.insert("arg2".to_owned(), Type::new(TypeKind::U64));
//     tt.insert("arg3".to_owned(), Type::new(TypeKind::U64));
//     tt.insert("arg4".to_owned(), Type::new(TypeKind::U64));

//     tt.insert("ctx".to_owned(), Type::new(TypeKind::U64));
//     Ok(())
// }

// fn gen_type_expr(tt: HashMap<String, Type>, expr: &Expr) {
//     match expr.kind {
//         ExprKind::Program(tys, e) => {}

//         ExprKind::Compound(mut c) => {
//             for mut i in c {
//                 gen_type_expr(&mut i);
//             }
//         }

//         ExprKind::ExprStmt(mut s) => {
//             gen_type_expr(&mut s);
//         }

//         ExprKind::If(c, t, e) => {}

//         ExprKind::Ident(name) => {}

//         ExprKind::Str(s) => {}

//         ExprKind::Num(n) => {}

//         ExprKind::Const(c) => {}

//         ExprKind::Unary(op, e) => {}

//         ExprKind::Binary(op, l, r) => {}

//         ExprKind::Cast(e, to) => {}

//         ExprKind::BuiltinCall(b, args) => {}

//         ExprKind::Member(p, s) => {}

//         _ => todo!(),
//     }
// }

// fn gen_type_ty(ty: &mut Ty) -> Type {
//     let type_kind = match &mut ty.kind {
//         TyKind::Void => TypeKind::Void,
//         TyKind::Char => TypeKind::Char,
//         TyKind::Bool => TypeKind::Bool,
//         TyKind::I8 => TypeKind::I8,
//         TyKind::U8 => TypeKind::U8,
//         TyKind::I16 => TypeKind::I16,
//         TyKind::U16 => TypeKind::U16,
//         TyKind::I32 => TypeKind::I32,
//         TyKind::U32 => TypeKind::U32,
//         TyKind::I64 => TypeKind::I64,
//         TyKind::U64 => TypeKind::U64,
//         TyKind::String => TypeKind::String,
//         TyKind::Struct(name) => TypeKind::Struct(Box::new(Type::new(TypeKind::TypeID(
//             btf_find_struct(name),
//         )))),
//         TyKind::Union(name) => TypeKind::Struct(Box::new(Type::new(TypeKind::TypeID(
//             btf_find_struct(&name),
//         )))),
//         TyKind::Ptr(mut t) => TypeKind::Ptr(Box::new(gen_type_ty(&mut t))),

//         TyKind::Kprobe(name) => TypeKind::Func(try_btf_find_func(&name)),
//         TyKind::Kretprobe(name) => TypeKind::Func(try_btf_find_func(&name)),
//     };

//     Type::new(type_kind)
// }
