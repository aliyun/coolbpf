use crate::be::be_codegen;
use crate::object::BPFObject;
use cranelift_codegen::ir::Function;
use cranelift_codegen::isa::riscv64::isa_builder;
use cranelift_codegen::settings::builder;
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::settings::Flags;
use cranelift_codegen::Context;
use std::fmt;
use target_lexicon::Architecture;
use target_lexicon::Riscv64Architecture;
use target_lexicon::Triple;

#[derive(Debug)]
pub struct Func {
    clif_func: Function,
    ty: crate::Type,
}

impl Func {
    pub fn new(cf: Function, ty: crate::Type) -> Self {
        Func { ty, clif_func: cf }
    }

    /// Compile this function and write the generated instructions to `BPFObject`
    pub(crate) fn compile(self, object: &mut BPFObject) {
        let mut ctx = Context::for_function(self.clif_func);

        let mut triple = Triple::unknown();
        triple.architecture = Architecture::Riscv64(Riscv64Architecture::Riscv64);
        let mut b = builder();
        b.set("opt_level", "speed_and_size")
            .expect("failed to set optimization level");
        let flag = Flags::new(b);
        let isa = isa_builder(triple).finish(flag).unwrap();
        ctx.optimize(isa.as_ref()).unwrap();

        log::debug!("optimized function:\n{}", ctx.func.display());

        be_codegen(&ctx, object, self.ty);
    }
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.ty.to_string(), self.clif_func)
    }
}
