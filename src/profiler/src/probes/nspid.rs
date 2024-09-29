use std::io::Read;

use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
pub struct NsPidMap {
    map: MapHandle,
}

impl NsPidMap {
    pub fn new(map: MapHandle) -> Self {
        NsPidMap { map }
    }

    pub fn is_empty(&self) -> bool {
        self.map.keys().next().is_none()
    }

    pub fn delete(&self, nspid: u32) -> Result<()> {
        self.map.delete(&nspid.to_ne_bytes())?;
        Ok(())
    }

    pub fn lookup(&self, nspid: u32) -> Result<Option<u32>> {
        Ok(self
            .map
            .lookup(&nspid.to_ne_bytes(), MapFlags::ANY)?
            .map(|x| u32::from_ne_bytes(vec2array(x))))
    }
}

fn vec2array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}
