use super::{
    map::{bpf_create_map, Map},
    perfbuffer::PerfBuffer,
};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, NativeEndian};
use libbpf_sys::bpf_map_update_elem;
use mio::unix::SourceFd;
use std::ffi::CString;

pub struct HashMap {
    fd: i64,
    key_size: usize,
    value_size: usize,
    max_entries: usize,
}

impl HashMap {
    pub fn new(key_size: usize, value_size: usize, max_entries: usize) -> Self {
        let mut hm = HashMap {
            fd: -1,
            key_size,
            value_size,
            max_entries,
        };
        if hm.create().is_err() {
            panic!(
                "Failed to create perf map, err: {}, {}",
                hm.fd,
                errno::errno()
            )
        }
        hm
    }
}

impl Map for HashMap {
    fn create(&mut self) -> Result<()> {
        let fd = bpf_create_map(
            libbpf_sys::BPF_MAP_TYPE_HASH,
            self.key_size() as u32,
            self.value_size() as u32,
            self.max_entries() as u32,
        );

        self.fd = fd;
        if fd < 0 {
            bail!("Failed to create perf map: {}", errno::errno())
        }

        Ok(())
    }

    fn fd(&self) -> i64 {
        self.fd
    }

    fn key_size(&self) -> usize {
        self.key_size
    }
    fn value_size(&self) -> usize {
        self.value_size
    }
    fn max_entries(&self) -> usize {
        self.max_entries
    }

    fn set_key_size(&mut self, key_size: usize) {
        self.key_size = key_size
    }

    fn set_value_size(&mut self, value_size: usize) {
        self.value_size = value_size
    }

    fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bump_memlock_rlimit;
    #[test]
    fn test_perf_map_create() {
        bump_memlock_rlimit().unwrap();
        let hm = HashMap::new(4, 4, 16);
        assert!(hm.fd() > 0);
    }
}
