use crate::utils::to_u8_slice;

use super::{
    map::{bpf_create_map, bpf_map_lookup},
    Map,
};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, NativeEndian};

pub struct StackMap {
    depth: u8,

    fd: i64,
    entries: u32,
}

impl StackMap {
    pub fn new() -> Self {
        StackMap {
            depth: 20,
            fd: -1,
            entries: 1024,
        }
    }

    /// max depth is 127, default is 20
    pub fn set_depth(&mut self, depth: u8) {
        self.depth = depth;
    }

    pub fn set_entries(&mut self, entries: u32) {
        self.entries = entries;
    }

    pub fn lookup(&self, key: i64) -> Result<Option<Vec<u64>>> {
        let vec = to_u8_slice(&key);
        if let Some(res) = bpf_map_lookup(self.fd as i32, vec, self.depth as usize * 8)? {
            let mut ret = vec![];
            for i in 0..self.depth {
                let offset = i as usize * 8;
                ret.push(NativeEndian::read_u64(&res[offset..offset + 8]));
            }
            return Ok(Some(ret));
        }
        Ok(None)
    }
}

impl Map for StackMap {
    fn create(&mut self) -> Result<()> {
        self.fd = bpf_create_map(
            libbpf_sys::BPF_MAP_TYPE_STACK_TRACE,
            4,
            (self.depth as u32) * 8,
            self.entries,
        );
        if self.fd < 0 {
            bail!("Failed to create stackmap, errno: {}", errno::errno())
        }
        Ok(())
    }

    fn fd(&self) -> i64 {
        self.fd
    }

    fn key_size(&self) -> usize {
        4
    }
    fn value_size(&self) -> usize {
        4
    }

    fn max_entries(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::bump_memlock_rlimit;

    use super::*;
    #[test]
    fn test_stack_map_create() {
        bump_memlock_rlimit().unwrap();
        assert!(StackMap::new().create().is_ok());
    }
}
