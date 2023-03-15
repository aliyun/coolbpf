use super::program::Program;
use anyhow::{bail, Result};
use libbpf_sys::*;
use std::{ffi::CString, fs::read_to_string};

use perf_event_open_sys::bindings::perf_event_attr;
use perf_event_open_sys::bindings::PERF_FLAG_FD_CLOEXEC;
use perf_event_open_sys::ioctls;
use perf_event_open_sys::perf_event_open;

fn determine_tracepoint_id(category: &str, name: &str) -> Result<i32> {
    let path = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);
    let mut content = read_to_string(path)?;

    for (i, c) in content.chars().enumerate() {
        if c < '0' || c > '9' {
            content.truncate(i);
            break;
        }
    }
    Ok(content.parse::<i32>()?)
}

pub struct TracepointProgram {
    insns: Vec<u64>,
    insns_cnt: usize,
    fd: i64,
    pfd: i64,
}

impl TracepointProgram {
    pub fn new() -> Self {
        TracepointProgram {
            insns: vec![],
            insns_cnt: 0,
            fd: 0,
            pfd: 0,
        }
    }

    pub fn attach(&mut self, category: &str, name: &str) -> Result<()> {
        let mut attr = perf_event_attr::default();
        attr.size = std::mem::size_of::<perf_event_attr>() as u32;
        attr.type_ = self.program_type();
        attr.config = determine_tracepoint_id(category, name)? as u64;

        let pfd = unsafe { perf_event_open(&mut attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC as u64) };
        if pfd < 0 {
            bail!(
                "tracepoint {}/{} perf_event_open failed: {}",
                category,
                name,
                errno::errno()
            )
        }

        if unsafe { ioctls::SET_BPF(pfd, self.fd as u32) } < 0 {
            bail!("Failed to set bpf program to perf event")
        }

        if unsafe { ioctls::ENABLE(pfd, 0) } < 0 {
            bail!("Failed to enable bpf program in perf event")
        }

        return Ok(());
    }
}

impl Program for TracepointProgram {
    fn program_type(&self) -> bpf_prog_type {
        BPF_PROG_TYPE_TRACEPOINT
    }

    fn set_program_fd(&mut self, fd: i64) {
        self.fd = fd;
    }

    fn set_insns(&mut self, insns: Vec<u64>) {
        self.insns = insns;
    }

    fn insns_cnt(&self) -> usize {
        self.insns.len()
    }

    fn insns_ptr(&self) -> *const bpf_insn {
        self.insns.as_ptr() as *const bpf_insn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_tracepoint_id() {
        assert!(determine_tracepoint_id("net", "netif_rx").unwrap() > 0);
    }

    #[test]
    fn test_tracepoint_attach() {
        // todo
    }
}
