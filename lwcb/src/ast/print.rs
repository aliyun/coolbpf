use crate::ast::*;
use crate::ast::{Ast, Visit};
use crate::types::{Constant, Identifier, Types};
use std::{fmt, io::BufWriter};

pub struct Printer {
    ident: usize,
}

impl Printer {
    pub fn new() -> Self {
        Printer { ident: 0 }
    }

    pub fn next_level(&mut self) -> Self {
        println!();
        Printer {
            ident: self.ident + 1,
        }
    }
}

impl Visit for Printer {
    fn visit_expression(&mut self, expression: &Expression) {
        visit_expression(&mut self.next_level(), expression)
    }

    fn visit_constant(&mut self, constant: &Constant) {
        print!("Constant {}", constant);
        visit_constant(&mut self.next_level(), constant)
    }

    fn visit_identifier(&mut self, identifier: &Identifier) {
        print!("Identifier {}", identifier);
        visit_identifier(&mut self.next_level(), identifier)
    }
}

fn test() {
    unsafe {
        // libc::dup
    }
}
