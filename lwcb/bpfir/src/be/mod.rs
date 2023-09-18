mod codegen;
mod isel;
mod regalloc;
mod spec;
use cranelift_codegen::Context;

pub(crate) fn be_codegen(ctx: &Context, object: &mut crate::object::BPFObject, ty: crate::Type) {
    let ifunc = isel::ISelFunctionBuilder::new().build(&ctx);
    log::debug!("isel function:\n{ifunc}");
    let rfunc = regalloc::RAFunctionBuilder::new().build(ifunc);
    log::debug!("regalloc function:\n{rfunc}");

    codegen::codegen_object(
        object,
        ty.kind.func_sec_name().as_str(),
        ty.kind.func_name().as_str(),
        rfunc.insts(),
    );
}
