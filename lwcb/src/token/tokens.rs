use std::collections::VecDeque;

use anyhow::{bail, Result};
use logos::{Lexer, Logos, Span};

use crate::token::Token;
use crate::types::Identifier;

#[derive(Debug, Clone)]
pub struct Tokens {
    source: String,
    tokens: Vec<Token>,
    slice: Vec<String>,
    span: Vec<Span>,
    start: usize,
    end: usize,
}

impl From<&str> for Tokens {
    fn from(source: &str) -> Self {
        let source_clone = source.clone().to_owned();
        let mut lex = Token::lexer(source);

        let mut tokens = Vec::new();
        let mut slice = Vec::new();
        let mut span = Vec::new();

        loop {
            if let Some(token) = lex.next() {
                tokens.push(token);
                slice.push(lex.slice().to_owned());
                span.push(lex.span());
                continue;
            }
            break;
        }
        tokens.push(Token::EOF);
        Tokens {
            source: source_clone,
            tokens,
            slice,
            span,
            start: 0,
            end: 0,
        }
    }
}

impl Tokens {
    pub fn is_eof(&self) -> bool {
        self.tokens[self.start] == Token::EOF
    }

    pub fn read(&mut self) -> Token {
        let t = self.peek();
        self.start += 1;
        t
    }

    pub fn peek(&self) -> Token {
        self.tokens[self.start].clone()
    }

    pub fn peek_offset(&self, offset: usize) -> Token {
        self.tokens[self.start + offset].clone()
    }

    pub fn try_eat(&mut self, token: Token) -> bool {
        if self.tokens[self.start] == token {
            self.start += 1;
            return true;
        }
        false
    }

    pub fn eat(&mut self, token: Token) -> Result<()> {
        if self.tokens[self.start] == token {
            self.start += 1;
            return Ok(());
        }
        bail!("Expect {:?}, found: {:?}", token, self.tokens[self.start])
    }

    pub fn eat_identifier(&mut self) -> Result<Identifier> {
        match &self.tokens[self.start] {
            Token::Identifier(i) => {
                self.start += 1;
                return Ok(i.clone());
            }
            _ => {
                bail!("Found {:?} expect identifer", self.tokens[self.start])
            }
        }
    }

    pub fn eat_string_literal(&mut self) -> Result<()> {
        match self.tokens[self.start] {
            Token::StringLiteral(_) => {
                self.start += 1;
                return Ok(());
            }
            _ => {
                bail!("Not a string literal token")
            }
        }
    }

    pub fn error_msg(&self) -> &str {
        // let span = &self.span[self.start];
        &self.source[..1]
    }

    // pub fn expect(&mut self, token: Token) -> Reuslt<>
}

#[derive(Debug, Clone)]
pub struct TokenStream<'text> {
    lexer: Lexer<'text, Token>,
    peeks: VecDeque<(Token, Span)>,
    span: Span,
}

impl<'text> TokenStream<'text> {
    pub fn new(text: &'text str) -> Self {
        Self {
            lexer: Token::lexer(text),
            peeks: VecDeque::new(),
            span: Span::default(),
        }
    }

    pub fn span(&self) -> Span {
        self.span.clone()
    }

    pub fn is_eof(&mut self) -> bool {
        self.peek() == Token::EOF
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
            tokens.push( (self.token().unwrap(), self.span()) );
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
            self.token();
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

    pub fn eat_identifier(&mut self) -> Result<Identifier> {
        match &self.token()? {
            Token::Identifier(i) => {
                return Ok(i.clone());
            }
            _ => {
                bail!("Not identifier")
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
}

#[test]
fn test_tokens() {
    let mut tokens = Tokens::from("printf(\"test %s\", \"test\")");
    println!("{:?}", tokens);

    tokens.eat_identifier().unwrap();
    tokens.eat(Token::LeftParen).unwrap();
    tokens.eat_string_literal().unwrap();
    tokens.eat(Token::Comma).unwrap();
    tokens.eat_string_literal().unwrap();
    tokens.eat(Token::RightParen).unwrap();
}
