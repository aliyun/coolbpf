use crate::constant::Constant;
use anyhow::bail;
use anyhow::Result;
use logos::Logos;
use std::collections::VecDeque;

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
    #[regex(r"[_\p{L}][_\p{L}\p{N}]*", |x| x.slice().parse())]
    Identifier(String),
    #[regex("\"[^\"]*\"", |x| x.slice().parse())]
    StringLiteral(String),
    #[regex(r"0[bB][01]+", |x| Constant::from_str_radix(x.slice(), 2))]
    #[regex(r"0[oO][0-7]+", |x| Constant::from_str_radix(x.slice(), 8))]
    #[regex(r"0[xX][0-9a-fA-F]+", |x| Constant::from_str_radix(x.slice(), 16))]
    #[regex(r"[0-9]+", |x| Constant::from_str_radix(x.slice(), 10))]
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

#[derive(Clone, Debug)]
pub struct Tokens<'text> {
    lexer: logos::Lexer<'text, Token>,
    peeks: VecDeque<(Token, logos::Span)>,
    span: logos::Span,
    source: &'text str,
}

impl<'text> From<&'text str> for Tokens<'text> {
    fn from(source: &'text str) -> Self {
        Tokens::new(source)
    }
}

impl<'text> Tokens<'text> {
    pub fn new(text: &'text str) -> Self {
        Self {
            lexer: Token::lexer(text),
            peeks: VecDeque::new(),
            span: logos::Span::default(),
            source: text,
        }
    }

    pub fn span(&self) -> logos::Span {
        self.span.clone()
    }

    pub fn is_eof(&mut self) -> bool {
        !self.have_token()
    }

    pub fn have_token(&mut self) -> bool {
        if self.peeks.is_empty() {
            if let Some(x) = self.lexer.next() {
                self.peeks.push_back((x, self.lexer.span()));
                return true;
            } else {
                return false;
            }
        }
        false
    }

    pub fn read(&mut self) -> Token {
        self.token().unwrap()
    }

    pub fn peek(&mut self) -> Token {
        self.peek_offset(0)
    }

    pub fn peek_offset(&mut self, offset: usize) -> Token {
        let mut tokens = vec![];
        for i in 0..(offset + 1) {
            tokens.push((self.token().unwrap(), self.span()));
        }
        loop {
            if let Some(token) = tokens.pop() {
                self.peeks.push_front(token);
            } else {
                break;
            }
        }
        self.peeks[offset].0.clone()
    }

    pub fn try_eat(&mut self, token: Token) -> bool {
        if self.peek() == token {
            self.token().unwrap();
            return true;
        }
        false
    }

    // get a token
    fn token(&mut self) -> Result<Token> {
        if let Some(token) = self.peeks.pop_front() {
            self.span = token.1;
            return Ok(token.0);
        }
        if let Some(token) = self.lexer.next() {
            self.span = self.lexer.span();
            return Ok(token);
        }
        bail!("No left token")
    }

    pub fn eat(&mut self, token: Token) -> Result<()> {
        if self.token()? == token {
            return Ok(());
        }
        bail!("Expect {:?}", token)
    }

    pub fn eat_identifier(&mut self) -> Result<String> {
        match &self.token()? {
            Token::Identifier(i) => {
                return Ok(i.clone());
            }
            _ => {
                bail!("Not identifier")
            }
        }
    }

    pub fn eat_constant(&mut self) -> Result<Constant> {
        match &self.token()? {
            Token::Constant(c) => {
                return Ok(c.clone());
            }
            _ => {
                bail!("Not constant")
            }
        }
    }

    pub fn eat_string_literal(&mut self) -> Result<()> {
        match self.token()? {
            Token::StringLiteral(_) => {
                return Ok(());
            }
            _ => {
                bail!("Not a string literal token")
            }
        }
    }

    pub fn span_string(&self, span: logos::Span) -> &str {
        &self.source[span]
    }

    pub fn span_str(&self, span: logos::Span) -> &str {
        &self.source[span]
    }

    pub fn left_str(&self) -> &str {
        &self.source[self.span.start..]
    }
}
