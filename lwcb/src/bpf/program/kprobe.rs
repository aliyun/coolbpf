use super::program::Program;
use anyhow::{bail, Result};
use libbpf_sys::*;
use std::{ffi::CString, fs::read_to_string};

use perf_event_open_sys::bindings::perf_event_attr;
use perf_event_open_sys::bindings::PERF_FLAG_FD_CLOEXEC;
use perf_event_open_sys::ioctls;
use perf_event_open_sys::perf_event_open;

fn determine_kprobe_perf_type() -> Result<i32> {
    let mut content = read_to_string("/sys/bus/event_source/devices/kprobe/type")?;

    for (i, c) in content.chars().enumerate() {
        if c < '0' || c > '9' {
            content.truncate(i);
            break;
        }
    }
    Ok(content.parse::<i32>()?)
}

fn determine_kprobe_retprobe_bit() -> Result<i32> {
    let mut content = read_to_string("/sys/bus/event_source/devices/kprobe/format/retprobe")?;
    let skip_len = "config:".len();
    Ok(content[skip_len..skip_len + 1].parse::<i32>()?)
}

pub struct KprobeProgram {
    insns: Vec<u64>,
    kretprobe: bool,
    offset: u64,

    name: Option<CString>,
    fd: i64,
    pfd: i64,
}

impl KprobeProgram {
    pub fn new() -> Self {
        KprobeProgram {
            insns: vec![],
            kretprobe: false,
            offset: 0,
            name: None,
            fd: 0,
            pfd: 0,
        }
    }

    pub fn set_kretprobe(&mut self, kretprobe: bool) {
        self.kretprobe = kretprobe
    }

    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = Some(CString::new(name).unwrap());
    }

    pub fn attach(&mut self, name: &str, offset: u64) -> Result<()> {
        log::debug!("Attaching kprobe program: {}", name);

        let cname = CString::new(name).unwrap();
        let mut attr = perf_event_attr::default();
        attr.size = std::mem::size_of::<perf_event_attr>() as u32;
        attr.type_ = determine_kprobe_perf_type()? as u32;
        attr.__bindgen_anon_3.config1 = cname.as_ptr() as u64;
        attr.__bindgen_anon_4.config2 = offset;

        if self.kretprobe {
            attr.config = 1 << determine_kprobe_retprobe_bit()?;
        }

        let pfd = unsafe { perf_event_open(&mut attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC as u64) };
        if pfd < 0 {
            bail!("Failed to open perf event: {}", pfd)
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

impl Program for KprobeProgram {
    fn program_type(&self) -> bpf_prog_type {
        BPF_PROG_TYPE_KPROBE
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
