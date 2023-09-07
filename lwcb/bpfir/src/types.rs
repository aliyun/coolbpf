use std::fmt::Display;

use logos::Span;
use paste::paste;
macro_rules! impl_specified_type {
    ($($func: ident, $ty: ident), *) => {
        paste! {
            $(
                pub fn $func() -> Self {
                    Self::new(TypeKind::$ty)
                }

                pub fn [<is_ $func>](&self) -> bool {
                    self.is_kind(TypeKind::$ty)
                }
            )*
        }
    };
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeKind {
    Undef,
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
    Struct(String),
    Union(String),

    Kprobe(String),
    Kretprobe(String),
}

impl TypeKind {
    pub fn func_sec_name(&self) -> String {
        match self {
            TypeKind::Kprobe(n) => format!("kprobe/{n}"),
            TypeKind::Kretprobe(n) => format!("kretprobe/{n}"),
            _ => panic!("Not a function type"),
        }
    }

    pub fn func_name(&self) -> String {
        match self {
            TypeKind::Kprobe(n) => format!("kprobe_{n}"),
            TypeKind::Kretprobe(n) => format!("kretprobe_{n}"),
            _ => panic!("Not a function type"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Type {
    pub kind: TypeKind,
    pub span: Span,
}

impl Type {
    pub fn new(kind: TypeKind) -> Self {
        Type {
            kind,
            span: Span::default(),
        }
    }

    pub fn is_kind(&self, kind: TypeKind) -> bool {
        self.kind == kind
    }

    impl_specified_type!(
        undef, Undef, void, Void, bool, Bool, char, Char, i8, I8, u8, U8, i16, I16, u16, U16, i32,
        I32, u32, U32, i64, I64, u64, U64, string, String
    );

    pub fn ptr(pointee: Type) -> Self {
        Self::new(TypeKind::Ptr(Box::new(pointee)))
    }

    pub fn struct_(name: String) -> Self {
        Type::new(TypeKind::Struct(name))
    }

    pub fn union(name: String) -> Self {
        Type::new(TypeKind::Union(name))
    }

    pub fn kprobe(name: String) -> Self {
        Type::new(TypeKind::Kprobe(name))
    }

    pub fn kretprobe(name: String) -> Self {
        Type::new(TypeKind::Kretprobe(name))
    }
}

impl ToString for Type {
    fn to_string(&self) -> String {
        let str = match &self.kind {
            TypeKind::Undef => "undef".to_owned(),
            TypeKind::Void => "void".to_owned(),
            TypeKind::Char => "char".to_owned(),
            TypeKind::Bool => "bool".to_owned(),
            TypeKind::I8 => "i8".to_owned(),
            TypeKind::U8 => "u8".to_owned(),
            TypeKind::I16 => "i16".to_owned(),
            TypeKind::U16 => "u16".to_owned(),
            TypeKind::I32 => "i32".to_owned(),
            TypeKind::U32 => "u32".to_owned(),
            TypeKind::I64 => "i64".to_owned(),
            TypeKind::U64 => "u64".to_owned(),
            TypeKind::String => "string".to_owned(),
            TypeKind::Ptr(x) => x.to_string() + "*",
            TypeKind::Struct(name) => format!("struct {}", name),
            TypeKind::Union(name) => format!("union {}", name),

            TypeKind::Kprobe(name) => format!("kprobe {}", name),
            TypeKind::Kretprobe(name) => format!("kprobe {}", name),
        };
        str.to_owned()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum UnaryOp {
    Deref, // *
    Not,   // '!'
    Neg,   // -
}

#[derive(Clone, Debug, PartialEq)]
pub enum BinaryOp {
    /// `lhs[rhs]`
    Index,
    /// ||
    Or,
    ///
    Xor,
    And,
    BitOr,
    BitXor,
    BitAnd,
    Equal,
    NonEqual,
    LT,
    GT,
    LTE,
    GTE,
    LShift,
    RShift,
    Add,
    Sub,
    Mult,
    Div,
    Mod,
    Assign,
}
