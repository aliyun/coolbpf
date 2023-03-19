// global perf map

use crate::bpf::map::{Map, PerfMap};
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref GLOBAL_PERF_MAP: Mutex<PerfMap> = {
        let perf = PerfMap::new();
        Mutex::new(perf)
    };
}

pub fn perf_open_buffer() {
    GLOBAL_PERF_MAP.lock().unwrap().open_buffer();
}

pub fn perf_read_events() -> Vec<Vec<String>>{
    GLOBAL_PERF_MAP.lock().unwrap().read_events()
}

pub fn perf_poll() {
    GLOBAL_PERF_MAP.lock().unwrap().open_buffer();
    GLOBAL_PERF_MAP.lock().unwrap().poll();
}
