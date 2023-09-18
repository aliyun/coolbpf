use std::io::Write;

use crate::btf::BTF;
use crate::parser::Ast;
use crate::passes::bpfir::gen_bpfir;
use crate::passes::typecheck::type_check;
use crate::passes::unfold;
use crate::print::Print;

pub struct BLang {
    code: String,
    object: Vec<u8>,
    pub prints: Vec<Print>,
}

impl BLang {
    pub fn code(&self) -> &String {
        &self.code
    }

    pub fn object(&self) -> &Vec<u8> {
        &self.object
    }
}

pub struct BLangBuilder {
    code: String,
    btf_path: Option<String>,
    dump_ir: bool,
    pub(crate) prints: Vec<Print>,
}

impl BLangBuilder {
    pub fn new(code: String) -> Self {
        BLangBuilder {
            code,
            btf_path: None,
            dump_ir: false,
            prints: vec![],
        }
    }

    pub fn btf(mut self, path: &str) -> Self {
        self.btf_path = Some(path.to_owned());
        self
    }

    pub fn dump_ir(mut self, dump: bool) -> Self {
        self.dump_ir = dump;
        self
    }

    pub fn build(mut self) -> BLang {
        let mut compile = true;

        let btf = BTF::from_path(self.btf_path.as_ref().expect("Please specify btf path"));

        let mut ast = Ast::from(self.code.as_str());
        unfold::unfold(&btf, &mut ast);
        type_check(&btf, &mut ast);
        let m = gen_bpfir(&mut self, &ast).expect("Failed to generate bpf ir");
        let mut object = vec![];

        if self.dump_ir {
            compile = false;
        }

        if compile {
            object = m.compile().emit();
        }

        BLang {
            code: self.code,
            object,
            prints: self.prints,
        }
    }

    pub fn build_with_output(mut self, out: &mut impl Write) -> BLang {
        let mut compile = true;

        let btf = BTF::from_path(self.btf_path.as_ref().expect("Please specify btf path"));

        let mut ast = Ast::from(self.code.as_str());
        unfold::unfold(&btf, &mut ast);
        type_check(&btf, &mut ast);
        let m = gen_bpfir(&mut self, &ast).expect("Failed to generate bpf ir");
        let mut object = vec![];

        if self.dump_ir {
            compile = false;
            write!(out, "{}", m).unwrap();
        }

        if compile {
            object = m.compile().emit();
        }

        BLang {
            code: self.code,
            object,
            prints: self.prints,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output() {
        let mut out = vec![];
        let _ = BLangBuilder::new("kprobe:tcp_sendmsg {}".to_owned())
            .btf("../tests/bin/vmlinux")
            .dump_ir(true)
            .build_with_output(&mut out);

        assert!(out.len() > 0);
    }
}
