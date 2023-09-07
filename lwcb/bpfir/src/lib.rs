mod be;

mod bblock;
mod cfg;
mod func;
mod module;
pub mod types;
mod value;

pub use bblock::BBlock;
use be::object::BPFObject;
pub use func::Func;
pub use func::FuncData;
pub use module::Module;
pub use types::Type;
pub use types::TypeKind;
pub use value::Value;
pub use value::ValueData;
pub use value::ValueKind;

use crate::be::codegen;
use crate::be::isel;
use crate::be::regalloc;
use std::sync::atomic::{AtomicUsize, Ordering};
static GLOBAL_TMP_NAME_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_NAME_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn tmp_unique_name() -> String {
    format!(
        "TMP_{}",
        GLOBAL_TMP_NAME_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

pub fn unique_name(name: &str) -> String {
    format!(
        "{name}_{}",
        GLOBAL_TMP_NAME_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

pub fn do_optimize(m: &mut Module) {
    todo!()
}

pub fn do_codegen(m: &Module) -> Vec<u8> {
    let mut object = BPFObject::new();
    for (_, fd) in m.funcs.iter() {
        do_codegen_func(&mut object, fd);
    }
    object.emit()
}

fn do_codegen_func(object: &mut BPFObject, fd: &FuncData){
    let isel = isel::ISelFunction::from_funcdata(fd);
    let mut ra = regalloc::RAFunction::from_isel_function(&isel);
    let output = regalloc::do_regalloc(&mut ra);
    let insts = regalloc::regalloc_emit(&ra, &output);
    codegen::codegen_object(
        object,
        fd.ty.kind.func_sec_name().as_str(),
        fd.ty.kind.func_name().as_str(),
        &insts,
    )
}
