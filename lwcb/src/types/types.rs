use std::fmt;
use std::ops;

use anyhow::{bail, Result};
use btfparse::btf::Btf;
use btfparse::BtfKind;
use libfirm_rs::{Mode, Type as IrType};

use crate::ast::*;
use crate::btf::btf_find_struct;
use crate::btf::btf_find_struct_member;
use crate::btf::btf_get_func_name;
use crate::btf::btf_get_point_to;
use crate::btf::btf_get_struct_name;
use crate::btf::btf_get_struct_size;
use crate::btf::btf_skip_const;
use crate::btf::btf_skip_typedef;
use crate::btf::btf_skip_volatile;
use crate::btf::btf_type_is_ptr;
use crate::btf::btf_type_is_struct;
use crate::btf::btf_type_is_union;
use crate::btf::btf_type_kind;
use crate::btf::btf_type_mode;
use crate::btf::btf_type_resolve;
use crate::btf::btf_type_size;
use crate::btf::btf_type_to_type;
use crate::btf::dump_by_typeid;
use crate::btf::try_btf_find_func;
use crate::builtin::UBuiltin;
use crate::firm::frame::ident;
use crate::firm::frame::unique_ident;

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
        Constant::I32(i32::from_str_radix(value_str, radix as u32).expect("Not a number"))
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
pub struct TypeId(u32);

#[derive(Clone, Debug, PartialEq)]
pub enum TypeKind {
    TypeId(u32), // btf type id
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
    Struct(Vec<Type>),
    Union(Vec<Type>),

    Tuple(Vec<Type>),
    Map(Box<Type>, Box<Type>), // key type and value type
    Func(Option<u32>),         // func proto typeid
    Default,

    Kprobe(Option<u32>),
    Kretprobe(Option<u32>),

    UBuiltin(UBuiltin, Box<Type>),
}

impl TypeKind {
    pub fn size(&self) -> usize {
        match self {
            TypeKind::TypeId(x) => btf_type_size(*x) as usize,
            TypeKind::Void
            | TypeKind::String
            | TypeKind::Default
            | TypeKind::Map(_, _)
            | TypeKind::Func(_)
            | TypeKind::Kprobe(_)
            | TypeKind::Kretprobe(_) => 0,
            TypeKind::Char | TypeKind::Bool | TypeKind::I8 | TypeKind::U8 => 1,
            TypeKind::I16 | TypeKind::U16 => 2,
            TypeKind::I32 | TypeKind::U32 => 4,
            TypeKind::I64 | TypeKind::U64 | TypeKind::Ptr(_) => 8,
            TypeKind::Struct(types) | TypeKind::Tuple(types) => {
                types.iter().map(|typ| typ.size()).sum()
            }
            TypeKind::Union(types) => types.iter().map(|typ| typ.size()).max().map_or(0, |s| s),
            TypeKind::UBuiltin(_, typ) => typ.size(),
            _ => todo!(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Type {
    pub kind: TypeKind,
    pub size: u16,
    pub offset: u16,
    pub name: Option<String>,

    pub kmem: bool,
    pub param: bool,
    pub ub: Option<UBuiltin>,
    // if member
}

impl Default for Type {
    fn default() -> Self {
        Self::new(TypeKind::Default)
    }
}

impl Type {
    pub fn new(kind: TypeKind) -> Self {
        Self {
            size: kind.size() as u16,
            kind,
            name: None,
            offset: 0,
            kmem: false,
            param: false,
            ub: None,
        }
    }

    pub fn void() -> Self {
        Self::new(TypeKind::Void)
    }

    pub fn i8() -> Self {
        Self::new(TypeKind::I8)
    }

    pub fn u8() -> Self {
        Self::new(TypeKind::U8)
    }

    pub fn i16() -> Self {
        Self::new(TypeKind::I16)
    }

    pub fn u16() -> Self {
        Self::new(TypeKind::U16)
    }

    pub fn i32() -> Self {
        Self::new(TypeKind::I32)
    }

    pub fn u32() -> Self {
        Self::new(TypeKind::U32)
    }

    pub fn i64() -> Self {
        Self::new(TypeKind::I64)
    }

    pub fn u64() -> Self {
        Self::new(TypeKind::U64)
    }

    pub fn ptr(to: Type) -> Self {
        Self::new(TypeKind::Ptr(Box::new(to)))
    }

    pub fn string() -> Self {
        Self::new(TypeKind::String)
    }

    pub fn ubuiltin(ub: UBuiltin, typ: Type) -> Self {
        Self::new(TypeKind::UBuiltin(ub, Box::new(typ)))
    }

    /// any type to pointer
    pub fn to_ptr(self) -> Self {
        Self::new(TypeKind::Ptr(Box::new(self)))
    }

    pub fn is_struct(&self) -> bool {
        match self.kind {
            TypeKind::Struct(_) => true,
            TypeKind::TypeId(id) => btf_type_is_struct(id),
            _ => false,
        }
    }

    pub fn is_union(&self) -> bool {
        match self.kind {
            TypeKind::Struct(_) => true,
            TypeKind::TypeId(id) => btf_type_is_union(id),
            _ => false,
        }
    }

    /// get function name if it's function type
    pub fn try_func_name(&self) -> Option<&str> {
        match &self.kind {
            TypeKind::Kprobe(x) | TypeKind::Kretprobe(x) => x.map(|x| btf_get_func_name(x)),
            _ => None,
        }
    }

    pub fn set_kmem(&mut self) {
        self.kmem = true;
    }

    pub fn clear_kmem(&mut self) {
        self.kmem = false;
    }

    /// Does it locate at kernel memory address space
    pub fn kmem(&self) -> bool {
        self.kmem
    }

    pub fn mode(&self) -> Mode {
        match &self.kind {
            TypeKind::Bool | TypeKind::Char | TypeKind::I8 => Mode::ModeBs(),
            TypeKind::U8 => Mode::ModeBu(),
            TypeKind::U16 => Mode::ModeHu(),
            TypeKind::I16 => Mode::ModeHs(),
            TypeKind::I32 => Mode::ModeIs(),
            TypeKind::U32 => Mode::ModeIu(),
            TypeKind::U64 => Mode::ModeLu(),
            TypeKind::I64 => Mode::ModeIu(),
            TypeKind::Ptr(_) => Mode::ModeLu(),
            TypeKind::TypeId(typeid) => btf_type_mode(*typeid),
            _ => todo!("{}", self),
        }
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }

    pub fn set_size(&mut self, size: u16) {
        self.size = size
    }

    pub fn irtype(&self) -> IrType {
        match &self.kind {
            TypeKind::Bool | TypeKind::Char | TypeKind::I8 => {
                IrType::new_primitive(&Mode::ModeBs())
            }
            TypeKind::U8 => IrType::new_primitive(&Mode::ModeBu()),
            TypeKind::U16 => IrType::new_primitive(&Mode::ModeHu()),
            TypeKind::I16 => IrType::new_primitive(&Mode::ModeHs()),
            TypeKind::I32 => IrType::new_primitive(&Mode::ModeIs()),
            TypeKind::U32 => IrType::new_primitive(&Mode::ModeIu()),
            TypeKind::U64 => IrType::new_primitive(&Mode::ModeLu()),
            TypeKind::I64 => IrType::new_primitive(&Mode::ModeIu()),
            TypeKind::Ptr(p) => IrType::new_pointer(&p.irtype()),
            TypeKind::Struct(types) => {
                if let Some(x) = &self.name {
                    return IrType::new_struct(&unique_ident(x));
                } else {
                    panic!("no name")
                }
            }
            TypeKind::TypeId(typeid) => typeid_to_irtype(*typeid),
            TypeKind::UBuiltin(_, typ) => typ.irtype(),
            _ => todo!("{}", self),
        }
    }

    pub fn member_by_idx(&self, idx: usize) -> &Type {
        match &self.kind {
            TypeKind::Struct(types) => &types[idx],
            _ => todo!(),
        }
    }
    // find member by name
    pub fn member_type(&self, name: &str) -> Type {
        let mut new_type = match &self.kind {
            TypeKind::Struct(types) => {
                for typ in types {
                    if typ.is_name(name) {
                        return typ.clone();
                    }
                }
                panic!("Can't find {}", name)
            }

            TypeKind::TypeId(typeid) => {
                let member = btf_find_struct_member(*typeid, name).unwrap();
                let mut member_type = Type::from_typeid(member.type_id);
                member_type.set_offset((member.offset() / 8) as u16);
                member_type
            }

            _ => panic!("Target type is not structure"),
        };
        if self.kmem() {
            new_type.set_kmem();
        }
        new_type
    }

    pub fn member_offset(&self, name: &str) -> u16 {
        self.member_type(name).offset() as u16
    }

    pub fn offset(&self) -> usize {
        self.offset as usize
    }

    pub fn set_offset(&mut self, offset: u16) {
        self.offset = offset
    }

    pub fn is_bitfield(&self) -> bool {
        todo!()
    }

    /// Is it a parameter of tracing function?
    pub fn param(&self) -> bool {
        self.param
    }

    pub fn set_param(&mut self) {
        self.param = true;
    }

    pub fn bitfield_offset(&self) -> usize {
        todo!()
    }

    pub fn bitfield_size(&self) -> usize {
        todo!()
    }

    pub fn typeid(&self) -> u32 {
        if let TypeKind::TypeId(x) = self.kind {
            return x;
        }
        panic!("is not typeid")
    }

    pub fn set_name(&mut self, name: String) {
        self.name = Some(name)
    }

    pub fn is_name(&self, name: &str) -> bool {
        if let Some(x) = &self.name {
            return x.eq(name);
        }
        false
    }

    pub fn is_ptr(&self) -> bool {
        if let TypeKind::Ptr(_) = &self.kind {
            return true;
        }

        if let TypeKind::TypeId(id) = &self.kind {
            return btf_type_is_ptr(*id);
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
            TypeKind::TypeId(typeid) => {
                if let Some(member) = btf_find_struct_member(*typeid, name) {
                    let mut new_type = Type::from_typeid(member.type_id);
                    new_type.set_offset((member.offset / 8) as u16);
                    return new_type;
                }
            }
            _ => {}
        }
        todo!()
    }

    pub fn update_mapkey(&mut self, key: Type) -> Result<()> {
        todo!()
    }

    pub fn update_mapval(&mut self, val: Type) -> Result<()> {
        todo!()
    }

    pub fn __from_typeid(typeid: u32) -> Self {
        Self::new(TypeKind::TypeId(btf_type_resolve(typeid)))
    }

    pub fn from_typeid(typeid: u32) -> Self {
        btf_type_to_type(btf_type_resolve(typeid))
    }

    // Get type by structure's name
    pub fn from_struct_name(name: &str) -> Self {
        let typeid = btf_find_struct(name);
        let mut typ = Self::from_typeid(typeid);
        typ.set_name(name.to_owned());
        typ
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

    pub fn set_ubuiltin(&mut self, ub: UBuiltin) {
        self.ub = Some(ub)
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
            // TyKind::Struct(name) => {
            //     TypeKind::Struct(Box::new(Type::new(TypeKind::TypeId(btf_find_struct(name)))))
            // }
            // TyKind::Union(name) => TypeKind::Struct(Box::new(Type::new(TypeKind::TypeId(
            //     btf_find_struct(&name),
            // )))),
            TyKind::Ptr(t) => TypeKind::Ptr(Box::new(Self::from_tykind(&t.kind))),

            TyKind::Kprobe(name) => TypeKind::Kprobe(try_btf_find_func(&name)),
            TyKind::Kretprobe(name) => TypeKind::Kretprobe(try_btf_find_func(&name)),
            _ => todo!(),
        };

        Type::new(type_kind)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            TypeKind::TypeId(x) => write!(f, "Typeid")?,
            TypeKind::Void => write!(f, "Void")?,
            TypeKind::String => write!(f, "String")?,
            TypeKind::Default => write!(f, "Invalid")?,
            TypeKind::Map(_, _) => write!(f, "Map")?,
            TypeKind::Kprobe(_) => write!(f, "Kprobe")?,
            TypeKind::Kretprobe(_) => write!(f, "Kretprobe")?,
            TypeKind::Char => write!(f, "Char")?,
            TypeKind::Bool => write!(f, "Bool")?,
            TypeKind::I8 => write!(f, "I8")?,
            TypeKind::U8 => write!(f, "U8")?,
            TypeKind::I16 => write!(f, "I16")?,
            TypeKind::U16 => write!(f, "U16")?,
            TypeKind::I32 => write!(f, "I32")?,
            TypeKind::U32 => write!(f, "U32")?,
            TypeKind::I64 => write!(f, "I64")?,
            TypeKind::U64 => write!(f, "U64")?,
            TypeKind::Ptr(_) => write!(f, "Pointer")?,
            TypeKind::Struct(_) => write!(f, "Struct")?,
            TypeKind::Union(_) => write!(f, "Union")?,
            TypeKind::Tuple(_) => write!(f, "Map")?,
            TypeKind::UBuiltin(_, _) => write!(f, "Ubuiltin")?,
            _ => todo!(),
        }

        write!(
            f,
            " name={} size={} offset={} param={} kmem={}",
            self.name.as_ref().map_or("none", |x| x.as_str()),
            self.size(),
            self.offset(),
            self.param(),
            self.kmem(),
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DataAction {}

pub fn typeid_to_irtype(typeid: u32) -> IrType {
    loop {
        match btf_type_kind(typeid) {
            BtfKind::Ptr => {
                let tmp = btf_get_point_to(typeid);
                let point_to = typeid_to_irtype(tmp);
                let pointer = IrType::new_pointer(&point_to);
                return pointer;
            }
            BtfKind::Struct => {
                let mut ty = IrType::new_struct(&ident(&btf_get_struct_name(typeid)));
                // set alignment
                // set size
                ty.set_align(8);
                ty.set_size(btf_get_struct_size(typeid));
                return ty;
            }
            BtfKind::Int => {
                let mode = btf_type_mode(typeid);
                let mut ty = IrType::new_primitive(&mode);
                return ty;
            }

            BtfKind::Typedef => {
                return typeid_to_irtype(btf_skip_typedef(typeid));
            }

            BtfKind::Volatile => {
                return typeid_to_irtype(btf_skip_volatile(typeid));
            }

            BtfKind::Const => {
                return typeid_to_irtype(btf_skip_const(typeid));
            }

            BtfKind::Enum => {
                // todo: fix this
                return IrType::new_primitive(&Mode::ModeIs());
            }
            _ => {
                panic!("{:?} not yet implemented", dump_by_typeid(typeid));
            }
        }
    }
}
