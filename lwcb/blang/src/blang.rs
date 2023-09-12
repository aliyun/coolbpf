use crate::btf::BTF;
use crate::parser::Ast;
use crate::passes::bpfir::gen_bpfir;
use crate::passes::typecheck::type_check;
use crate::passes::unfold;
use bpfir::mir::*;

pub struct BLang {
    code: String,
    ast: Ast,
    // ir module
    irm: Module,

    object: Vec<u8>,
}

impl BLang {
    pub fn code(&self) -> &String {
        &self.code
    }

    pub fn ast(&self) -> &Ast {
        &self.ast
    }

    pub fn object(&self) -> &Vec<u8> {
        &self.object
    }
}

pub struct BLangBuilder {
    code: String,
    btf_path: Option<String>,
    // options
}

impl BLangBuilder {
    pub fn new(code: String) -> Self {
        BLangBuilder {
            code,
            btf_path: None,
        }
    }

    pub fn btf(mut self, path: &str) -> Self {
        self.btf_path = Some(path.to_owned());
        self
    }

    pub fn build(self) -> BLang {
        let btf = BTF::from_path(self.btf_path.expect("Please specify btf path"));

        let mut ast = Ast::from(self.code.as_str());
        unfold::unfold(&btf, &mut ast);
        type_check(&btf, &mut ast).expect("Type check error");
        let mut m = gen_bpfir(&ast).expect("Failed to generate bpf ir");
        let object = m.compile().emit();

        BLang {
            code: self.code,
            ast,
            irm: m,
            object,
        }
    }
}
