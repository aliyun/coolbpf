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
pub use blang::BLang;
pub use blang::BLangBuilder;

