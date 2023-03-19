mod ast;
mod btf;
mod token;
mod types;
mod bpf;
mod cmacro;
mod firm;
mod gperf;
mod gstack;
mod kallsyms;
mod lwcb;
mod utils;
mod symbol;
mod perf_event;
mod context;
mod builtin;
mod event;

pub static mut IS_IN_PYTHON: bool = false;

pub use self::lwcb::LwCB;

pub fn enable_python() {
    unsafe { IS_IN_PYTHON = true };
}

pub fn is_python() -> bool {
    unsafe { IS_IN_PYTHON }
}
