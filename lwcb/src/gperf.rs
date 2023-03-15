// global perf map

use crate::bpf::map::{Map, PerfEvent, PerfMap};
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref GLOBAL_PERF_MAP: Mutex<PerfMap> = {
        let perf = PerfMap::new();
        Mutex::new(perf)
    };
}

pub fn perf_get_event_id() -> usize {
    GLOBAL_PERF_MAP.lock().unwrap().event_id()
}

pub fn perf_add_event(event: PerfEvent) {
    GLOBAL_PERF_MAP.lock().unwrap().add_perf_event(event)
}

/// return perf map fd
pub fn perf_mapfd() -> i64 {
    GLOBAL_PERF_MAP.lock().unwrap().fd()
}

pub fn perf_open_buffer() {
    GLOBAL_PERF_MAP.lock().unwrap().open_buffer();
}

pub fn perf_read_events() -> Vec<Vec<String>> {
    GLOBAL_PERF_MAP.lock().unwrap().read_events()
}

pub fn perf_poll() {
    GLOBAL_PERF_MAP.lock().unwrap().open_buffer();
    GLOBAL_PERF_MAP.lock().unwrap().poll();
}
