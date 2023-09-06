mod call;
mod constant;
mod lexer;
mod parser;

mod btf;
mod passes;

use anyhow::Result;
use btf::BTF;
use lexer::Tokens;
use parser::Ast;
use passes::{typecheck::type_check, unfold};

use crate::passes::bpfir::gen_bpfir;
mod blang;

pub struct Compiler {
    code: String,
    ast: Ast,
}

impl Compiler {
    pub fn code(&self) -> &String {
        &self.code
    }

    pub fn ast(&self) -> &Ast {
        &self.ast
    }
}

pub struct CompilerBuilder {
    code: String,
    btf_path: Option<String>,
    // options
}

impl CompilerBuilder {
    pub fn new(code: String) -> Self {
        CompilerBuilder {
            code,
            btf_path: None,
        }
    }

    pub fn build(self) -> Compiler {
        let mut ast = Ast::from(self.code.as_str());
        let btf = BTF::from_path("/root/easybpf/vmlinux-4.19.91-010.ali4000.alios7.x86_64");
        unfold::unfold(&btf, &mut ast);
        type_check(&btf, &mut ast).expect("Type check error");
        let m = gen_bpfir(&ast).expect("Failed to generate bpf ir");
        // println!("{}", m.dump());

        Compiler {
            code: self.code,
            ast,
        }
    }
}
