mod ast;
mod attr;
mod parser;
mod print;
mod visit;

pub use {self::ast::*, self::parser::*, self::visit::*};

use crate::token::Tokens;

#[derive(Clone, Debug, PartialEq)]
pub struct Ast {
    translation_unit: TranslationUnit,
}

impl From<&mut Tokens> for Ast {
    fn from(tokens: &mut Tokens) -> Self {
        Ast {
            translation_unit: translation_unit(tokens)
                .expect(&format!("failed to parse tokens: {}", tokens.error_msg())),
        }
    }
}

impl From<&str> for Ast {
    fn from(source: &str) -> Self {
        let mut tokens = Tokens::from(source);
        Ast::from(&mut tokens)
    }
}

impl From<&String> for Ast {
    fn from(source: &String) -> Self {
        Ast::from(source.as_str())
    }
}
