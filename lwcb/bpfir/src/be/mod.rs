use self::clif::do_clif;
use self::codegen::codegen;
use self::codegen::codegen_object;
use self::isel::ISelFunctionBuilder;
use self::regalloc::RAFunctionBuilder;
use crate::mir::FunctionData;
use crate::BPFObject;
use cranelift_codegen::ir::Function;
use cranelift_codegen::isa::riscv64::isa_builder;
use cranelift_codegen::isa::IsaBuilder;
use cranelift_codegen::settings::builder;
use cranelift_codegen::settings::Builder;
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::settings::Flags;
use cranelift_codegen::Context;
use target_lexicon::Architecture;
use target_lexicon::Riscv64Architecture;
use target_lexicon::Triple;
use target_lexicon::Vendor;
pub mod clif;
pub mod codegen;
pub mod isel;
pub mod object;
pub mod regalloc;
mod spec;

pub(crate) fn compile_function(object: &mut BPFObject, fd: &FunctionData) {
    let mut ctx = Context::for_function(do_clif(fd));

    let mut triple = Triple::unknown();
    triple.architecture = Architecture::Riscv64(Riscv64Architecture::Riscv64);
    let mut b = builder();
    b.set("opt_level", "speed_and_size")
        .expect("failed to set optimization level");
    let flag = Flags::new(b);
    let isa = isa_builder(triple).finish(flag).unwrap();
    ctx.optimize(isa.as_ref()).unwrap();

    log::debug!("optimized function:\n{}", ctx.func.display());

    let ifunc = ISelFunctionBuilder::new().build(&ctx);
    log::debug!("isel function:\n{ifunc}");
    let rfunc = RAFunctionBuilder::new().build(ifunc);
    log::debug!("regalloc function:\n{rfunc}");

    codegen_object(
        object,
        fd.ty.kind.func_sec_name().as_str(),
        fd.ty.kind.func_name().as_str(),
        rfunc.insts(),
    );
}
