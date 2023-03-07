use crate::{
    builtin_function::BuiltinFunction,
    types::{Constant, Type},
};
use logos::Span;

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    Compound(Vec<Expr>), // compound statement
    ExprStmt(Box<Expr>),
    If(Box<Expr>, Box<Expr>, Option<Box<Expr>>), // condition, then, else
    Return,

    Ident(String), // identifier
    LitStr(String),   // string literal
    Num(i64),      // number
    Const(Constant),
    Unary(UnaryOp, Box<Expr>),              // unary expression
    Binary(BinaryOp, Box<Expr>, Box<Expr>), // binary expression
    Cast(Box<Expr>, Ty),
    BuiltinCall(BuiltinFunction, Vec<Expr>), // builtin call exression: callee, arguments
    Member(Box<Expr>, Box<Expr>),            //member access
    Program(Vec<Ty>, Box<Expr>), // bpf program, tracing point definition and program body
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
    pub typ_: Type,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self {
            kind,
            span,
            typ_: Type::default(),
        }
    }

    pub fn new_binary(op: BinaryOp, l: Expr, r: Expr, span: Span) -> Self {
        Self::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), span)
    }

    pub fn new_unary(op: UnaryOp, e: Expr, span: Span) -> Self {
        Self::new(ExprKind::Unary(op, Box::new(e)), span)
    }

    pub fn new_builtincall(builtin: BuiltinFunction, args: Vec<Expr>, span: Span) -> Self {
        Self::new(ExprKind::BuiltinCall(builtin, args), span)
    }

    pub fn new_num(num: i64, span: Span) -> Self {
        Self::new(ExprKind::Num(num), span)
    }

    pub fn new_const(c: Constant, span: Span) -> Self {
        Self::new(ExprKind::Const(c), span)
    }

    pub fn new_ident(ident: String, span: Span) -> Self {
        Self::new(ExprKind::Ident(ident), span)
    }

    pub fn new_litstr(str: String, span: Span) -> Self {
        Self::new(ExprKind::LitStr(str), span)
    }

    pub fn new_member(expr1: Expr, expr2: Expr, span: Span) -> Self {
        Self::new(ExprKind::Member(Box::new(expr1), Box::new(expr2)), span)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TyKind {
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
    Struct(String),
    Union(String),
    Ptr(Box<Ty>),

    Kprobe(String),
    Kretprobe(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ty {
    pub kind: TyKind,
    pub span: Span,
    pub typ_: Type,
}

impl Ty {
    pub fn new(kind: TyKind, span: Span) -> Self {
        Ty { kind, span, typ_: Type::default() }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ast {
    pub exprs: Vec<Expr>,
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
    Or,
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
