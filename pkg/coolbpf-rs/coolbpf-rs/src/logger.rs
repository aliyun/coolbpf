use libbpf_rs::set_print;
use log::{log_enabled, Level};

pub fn set_libbpf_print() {
    if log_enabled!(Level::Trace) || log_enabled!(Level::Debug) {
        set_print(Some((libbpf_rs::PrintLevel::Debug, |_, s| print!("{s}"))));
    } else if log_enabled!(Level::Info) {
        set_print(Some((libbpf_rs::PrintLevel::Info, |_, s| print!("{s}"))));
    } else if log_enabled!(Level::Warn) {
        set_print(Some((libbpf_rs::PrintLevel::Warn, |_, s| print!("{s}"))));
    }
}

pub fn init_from_env() {
    env_logger::init_from_env(env_logger::Env::new().filter("COOLBPF_LOG"));
    set_libbpf_print();
}
