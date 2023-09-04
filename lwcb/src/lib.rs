mod ast;
mod bpf;
mod btf;
mod builtin;
mod cmacro;
mod context;
mod event;
mod firm;
mod gperf;
mod gstack;
mod kallsyms;
mod lwcb;
mod perf_event;
mod symbol;
mod token;
mod tracepoint;
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
