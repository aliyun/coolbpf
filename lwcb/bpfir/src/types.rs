use logos::Span;
use parse_display::Display;
use parse_display::FromStr;
use paste::paste;
use std::fmt;

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
    Map(libbpf_rs::MapType, u32, Box<Type>, Box<Type>), // entries, key, value

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

    pub fn loadable(&self) -> bool {
        match self {
            Self::Char
            | Self::Bool
            | Self::I8
            | Self::U8
            | Self::I16
            | Self::U16
            | Self::I32
            | Self::U32
            | Self::I64
            | Self::U64
            | Self::Ptr(_) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Type {
    pub kind: TypeKind,
    // pub span: Span,
    pub typeid: u32,
}

impl Type {
    pub fn new(kind: TypeKind) -> Self {
        Type {
            kind,
            // span: Span::default(),
            typeid: 0,
        }
    }

    pub fn is_kind(&self, kind: TypeKind) -> bool {
        self.kind == kind
    }

    pub fn is_ptr(&self) -> bool {
        if let TypeKind::Ptr(..) = self.kind {
            true
        } else {
            false
        }
    }

    pub fn points_to(&self) -> &Type {
        if let TypeKind::Ptr(x) = &self.kind {
            return x.as_ref();
        }
        panic!("Not a pointer")
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

    pub fn map(ty: libbpf_rs::MapType, entries: u32, key: Type, val: Type) -> Self {
        Type::new(TypeKind::Map(ty, entries, Box::new(key), Box::new(val)))
    }

    pub fn size(&self) -> i32 {
        match self.kind {
            TypeKind::Bool | TypeKind::Char | TypeKind::I8 | TypeKind::U8 => 1,
            TypeKind::I16 | TypeKind::U16 => 2,
            TypeKind::I32 | TypeKind::U32 => 4,
            TypeKind::I64 | TypeKind::U64 | TypeKind::Ptr(_) => 8,
            _ => todo!("{:?}", self),
        }
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
            TypeKind::Map(ty, n, k, v) => {
                format!("{ty} map {n} key:{}, val:{}", k.to_string(), v.to_string())
            }

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

macro_rules! match_expand {
    ($($ty: expr, $char: expr) *) => {
        $(
            Self::$ty => $char,
        )*
    };
}

#[derive(Clone, Debug, PartialEq, Display, FromStr)]
pub enum BinaryOp {
    #[display("[]")]
    Index,
    #[display("||")]
    Or,
    #[display("^|")]
    Xor,
    #[display("&&")]
    And,
    #[display("==")]
    Equal,
    #[display("!=")]
    NonEqual,
    #[display("<")]
    LT,
    #[display(">")]
    GT,
    #[display("<=")]
    LTE,
    #[display(">=")]
    GTE,
    #[display("<<")]
    LShift,
    #[display(">>")]
    RShift,
    #[display("+")]
    Add,
    #[display("-")]
    Sub,
    #[display("*")]
    Mult,
    #[display("/")]
    Div,
    #[display("%")]
    Mod,
    #[display("=")]
    Assign,
    #[display("|")]
    BitOr,
    #[display("&")]
    BitAnd,
    #[display("^")]
    BitXor,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Relation {
    NotEqual = libbpf_sys::BPF_JNE,
    Equal = libbpf_sys::BPF_JEQ,
    Less = libbpf_sys::BPF_JLT,
    LessEqual = libbpf_sys::BPF_JLE,
    SignedLess = libbpf_sys::BPF_JSLT,
    SignedLessEqual = libbpf_sys::BPF_JSLE,
    Greater = libbpf_sys::BPF_JGT,
    GreateEqual = libbpf_sys::BPF_JGE,
    SignedGreater = libbpf_sys::BPF_JSGT,
    SignedGreateEqual = libbpf_sys::BPF_JSGE,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relation::NotEqual => write!(f, "!="),
            Relation::Equal => write!(f, "=="),
            Relation::Less => write!(f, "<"),
            Relation::LessEqual => write!(f, "<="),
            Relation::SignedLess => write!(f, "<(signed)"),
            Relation::SignedLessEqual => write!(f, "<=(signed)"),
            Relation::Greater => write!(f, ">"),
            Relation::GreateEqual => write!(f, ">="),
            Relation::SignedGreater => write!(f, ">(signed)"),
            Relation::SignedGreateEqual => write!(f, ">=(signed)"),
        }
    }
}
