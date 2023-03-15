use anyhow::{bail, Result};
use libbpf_sys::*;
use std::ffi::CString;

#[derive(Debug, Clone, Copy)]
pub enum ProgramType {
    Kprobe,
    Kretprobe,
    Tracepoint,
}

pub trait Program {
    fn set_insns(&mut self, insns: Vec<u64>);
    fn insns_cnt(&self) -> usize;
    fn insns_ptr(&self) -> *const bpf_insn;
    fn program_type(&self) -> bpf_prog_type;

    fn set_program_fd(&mut self, fd: i64);

    fn load(&mut self) -> Result<()> {
        let fd = bpf_program_load(self.program_type(), self.insns_ptr(), self.insns_cnt());
        if fd < 0 {
            bail!("Failed to load eBPF program: fd = {}", fd)
        }
        self.set_program_fd(fd);
        return Ok(());
    }
}

macro_rules! impl_program_common {
    ($name: ident) => {
        impl Program for $name {
            fn insns(&self) -> *const bpf_insn {
                self.insns
            }

            fn set_insns(&mut self, insns: Vec<u64>) {
                self.insns = insns;
            }

            fn set_insns_cnt(&mut self, cnt: usize) {
                self.insns_cnt = cnt;
            }
        }
    };
}

pub(crate) use impl_program_common;

use crate::utils::kernel_version::kernel_version;

pub fn bpf_program_load(prog_type: bpf_prog_type, insns: *const bpf_insn, insns_cnt: usize) -> i64 {
    let license = CString::new("GPL").unwrap();
    let log_buf_size = 65536;

    let mut attr = bpf_attr::default();
    attr.__bindgen_anon_3.prog_type = prog_type;
    attr.__bindgen_anon_3.insns = insns as u64;
    attr.__bindgen_anon_3.insn_cnt = insns_cnt as u32;
    attr.__bindgen_anon_3.license = license.as_ptr() as u64;
    attr.__bindgen_anon_3.kern_version = kernel_version().unwrap();

    let mut fd =
        unsafe { libc::syscall(321, BPF_PROG_LOAD, &attr, std::mem::size_of::<bpf_attr>()) };

    if fd < 0 {
        let mut log_buf = vec![0; log_buf_size];
        attr.__bindgen_anon_3.log_buf = log_buf.as_mut_ptr() as u64;
        attr.__bindgen_anon_3.log_size = log_buf_size as u32;
        attr.__bindgen_anon_3.log_level = 1;
        fd = unsafe { libc::syscall(321, BPF_PROG_LOAD, &attr, std::mem::size_of::<bpf_attr>()) };

        let len = log_buf
            .iter()
            .position(|&c| c == 0)
            .expect("Log buffer overflow");
        log_buf.truncate(len);
        if fd < 0 {
            let s = String::from_utf8(log_buf).unwrap();
            panic!("failed to load program: {}, error: {}", s, errno::errno());
        }
    }
    return fd;
}
