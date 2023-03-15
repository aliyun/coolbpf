use logos::{Lexer, Logos};

use crate::builtin_function::BuiltinFunction;
use crate::types::*;

#[derive(Logos, Debug, Clone, PartialEq)]
pub enum Token {
    //bpf program type
    #[token("kprobe")]
    Kprobe,
    #[token("kretprobe")]
    Kretprobe,
    #[token("tracepoint")]
    Tracepoint,
    #[token("begin")]
    Begin,
    #[token("end")]
    End,

    // type name
    #[token("bool")]
    Bool,
    #[token("char")]
    Char,
    #[token("i8")]
    I8,
    #[token("u8")]
    U8,
    #[token("i16")]
    I16,
    #[token("u16")]
    U16,
    #[token("i32")]
    I32,
    #[token("u32")]
    U32,
    #[token("i64")]
    I64,
    #[token("u64")]
    U64,
    #[token("union")]
    Union,
    #[token("struct")]
    Struct,

    // if statment
    #[token("if")]
    If,
    #[token("else")]
    Else,

    // operator
    #[token("<<")]
    LShift,
    #[token(">>")]
    RShift,
    #[token("!=")]
    NotEqual,
    #[token("+=")]
    PlusEqual,

    #[token("-=")]
    MinusEqual,

    #[token("*=")]
    StarEqual,

    #[token("/=")]
    SlashEqual,

    #[token("%=")]
    PercentEqual,

    #[token("^=")]
    CaretEqual,

    #[token("^")]
    Caret,

    #[token(":")]
    Colon,

    #[token(",")]
    Comma,

    #[token("...")]
    Ellipse,

    #[token("->")]
    Deref,
    #[token(".")]
    Dot,

    #[token("==")]
    TwoEqual,

    #[token("=")]
    Equal,

    #[token(">=")]
    GreaterThanEqual,

    #[token(">")]
    GreaterThan,

    #[token("[")]
    LeftBracket,

    #[token("{")]
    LeftBrace,

    #[token("(")]
    LeftParen,

    #[token("<=")]
    LessThanEqual,

    #[token("<")]
    LessThan,

    #[token("-")]
    Minus,

    #[token("%")]
    Percent,

    #[token("+")]
    Plus,

    #[token("?")]
    QuestionMark,

    #[token("}")]
    RightBrace,

    #[token("]")]
    RightBracket,

    #[token(")")]
    RightParen,

    #[token(";")]
    Semicolon,

    #[token("/")]
    Slash,

    #[token("*")]
    Star,

    #[token("return")]
    Return,

    #[regex(r"[_\p{L}][_\p{L}\p{N}]*", |x| Identifier::from(x.slice()))]
    Identifier(Identifier),

    #[regex("\"[^\"]*\"", |x| x.slice().parse())]
    StringLiteral(String),

    // constant
    // #[token("true")]
    // #[token("false")]
    // #[regex(r"'.'")]
    #[regex(r"0[xX][0-9a-fA-F]+", |x| Constant::number(16, x.slice()))]
    #[regex(r"[0-9]+", |x| Constant::number(10, x.slice()))]
    Constant(Constant),

    #[regex(r"[ \t]*(\r?\n)?", logos::skip)]
    Whitespace,
    #[error]
    Unknown,

    #[regex(r"//[^\r\n]*(\r\n|\n)?", logos::skip)]
    Comment,

    EOF,
}

impl Token {
    pub fn is_type_name(&self) -> bool {
        match self {
            Token::Bool
            | Token::Char
            | Token::I8
            | Token::U8
            | Token::I16
            | Token::U16
            | Token::I32
            | Token::U32
            | Token::I64
            | Token::U64
            | Token::Union
            | Token::Struct => true,
            _ => false,
        }
    }
}
