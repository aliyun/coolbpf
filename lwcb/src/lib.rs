mod ast;
mod bpf;
mod btf;
mod builtin_function;
mod cmacro;
mod firm;
mod gperf;
mod gstack;
mod kallsyms;
mod lwcb;
mod token;
mod types;
mod utils;

pub static mut IS_IN_PYTHON: bool = false;

pub use self::lwcb::LwCB;

pub fn enable_python() {
    unsafe { IS_IN_PYTHON = true };
}

pub fn is_python() -> bool {
    unsafe { IS_IN_PYTHON }
}
