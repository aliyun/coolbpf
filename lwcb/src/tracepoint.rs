use once_cell::sync::Lazy;
use std::fs;
use std::path::PathBuf;

use crate::utils::tracepoint::{tracepoint_path, TracepointEvent};

pub static GLOBAL_TRACEPOINT: Lazy<Tracepoint> = Lazy::new(|| tracepoint_load());

#[derive(Debug, Clone)]
pub struct Tracepoint {
    pub tracepoints: Vec<TracepointEvent>,
}

impl Tracepoint {
    pub fn new() -> Self {
        Tracepoint {
            tracepoints: vec![],
        }
    }

    pub fn get_all_tracepoints(&self) -> &Vec<TracepointEvent> {
        &self.tracepoints
    }
}

pub fn tracepoint_load() -> Tracepoint {
    let mut tracepoint = Tracepoint::new();
    let category_path = PathBuf::from("/sys/kernel/debug/tracing/events");
    for category in fs::read_dir(category_path).unwrap() {
        if let Ok(category) = category {
            if let Ok(category_name) = category.file_name().into_string() {
                if category.path().is_dir() {
                    for name in fs::read_dir(category.path()).unwrap() {
                        if let Ok(name) = name {
                            if let Ok(name_name) = name.file_name().into_string() {
                                let path = tracepoint_path(&category_name, &name_name);
                                if path.exists() && name_name != "enable" && name_name != "filter" {
                                    tracepoint
                                        .tracepoints
                                        .push(TracepointEvent::new(&category_name, &name_name));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracepoint
}

mod tests {
    use super::*;

    #[test]
    fn test_tracepoint_load() {
        env_logger::init();
        GLOBAL_TRACEPOINT.get_all_tracepoints();
    }
}
