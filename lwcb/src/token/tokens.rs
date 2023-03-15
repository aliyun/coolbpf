use anyhow::{bail, Result};
use logos::{Logos, Span};

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
