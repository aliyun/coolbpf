use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::SeqCst);
    if v {
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
        }
    } else {
        unsafe {
            std::env::set_var("RUST_LOG", "warn");
        }
    }
    env_logger::init();
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::SeqCst)
}
