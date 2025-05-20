use super::types::bpf;
use super::types::impl_default;
use crate::symbollizer::file_id::FileId64;
use anyhow::bail;
use anyhow::Result;
use libbpf_rs::libbpf_sys::bpf_map_create_opts;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

pub struct StackDeltaPageInfo {
    raw: bpf::StackDeltaPageInfo,
}

impl StackDeltaPageInfo {
    pub fn new(first_delta: u32, deltas: u16, map_id: u16) -> Self {
        StackDeltaPageInfo {
            raw: bpf::StackDeltaPageInfo {
                firstDelta: first_delta,
                numDeltas: deltas,
                mapID: map_id,
            },
        }
    }
}

pub struct StackDeltaPageKey {
    raw: bpf::StackDeltaPageKey,
}

impl StackDeltaPageKey {
    pub fn new(file_id: FileId64, page: u64) -> Self {
        StackDeltaPageKey {
            raw: bpf::StackDeltaPageKey {
                fileID: *file_id,
                page,
            },
        }
    }
}

pub struct StackDelta {
    raw: bpf::StackDelta,
}

impl StackDelta {
    pub fn new(addr_low: u16, unwind_info: u16) -> Self {
        StackDelta {
            raw: bpf::StackDelta {
                addrLow: addr_low,
                unwindInfo: unwind_info,
            },
        }
    }
}

impl_default!(StackDelta);

impl_default!(StackDeltaPageKey);
impl_default!(StackDeltaPageInfo);

pub struct StackDeltaPageMap {
    map: MapHandle,
    batch: bool,
}

impl StackDeltaPageMap {
    pub fn new(map: MapHandle) -> Self {
        StackDeltaPageMap { map, batch: false }
    }

    pub fn is_empty(&self) -> bool {
        self.map.keys().next().is_none()
    }

    pub fn update(
        &self,
        file_id: FileId64,
        deltas: &Vec<u16>,
        map_id: u16,
        first_page: u64,
    ) -> Result<()> {
        let mut first_delta = 0;

        for (i, &delta) in deltas.iter().enumerate() {
            let key = StackDeltaPageKey::new(file_id, first_page + (i << 16) as u64);
            let val = StackDeltaPageInfo::new(first_delta, delta, map_id);
            self.map
                .update(key.slice(), val.slice(), MapFlags::NO_EXIST)?;
            first_delta += delta as u32;
        }
        Ok(())
    }

    pub fn delete(&self, file_id: FileId64, page: u64, numpage: u32) -> Result<()> {
        for i in 0..numpage {
            let pageaddr = page + (i << 16) as u64;
            let key = StackDeltaPageKey::new(file_id, pageaddr);
            self.map.delete(key.slice())?;
        }
        Ok(())
    }
}

pub struct StackDeltaMap {
    maps: Vec<MapHandle>,
    batch: bool,
}

impl StackDeltaMap {
    pub fn new(maps: Vec<MapHandle>, batch: bool) -> Self {
        StackDeltaMap { maps, batch }
    }

    /// check if no inner map
    pub fn is_empty(&self) -> bool {
        for map in &self.maps {
            if map.keys().next().is_some() {
                return false;
            }
        }
        true
    }

    #[inline]
    fn outer_map(&self, map_id: u32) -> &MapHandle {
        &self.maps[(map_id - bpf::STACK_DELTA_BUCKET_SMALLEST) as usize]
    }
    pub fn update(&self, file_id: FileId64, deltas: Vec<StackDelta>) -> Result<u32> {
        let map_id = get_map_id(deltas.len() as u32)?;

        let inner = self.create_inner_map(map_id)?;
        let outer = self.outer_map(map_id);

        if self.batch {
            update_batch_inner_map(&inner, deltas)?;
        } else {
            update_inner_map(&inner, deltas)?;
        }
        update_outer_map(outer, file_id, &inner)?;

        Ok(map_id)
    }

    pub fn delete(&self, file_id: FileId64, map_id: u32) -> Result<()> {
        let outer = self.outer_map(map_id);
        delete_outer_map(outer, file_id)?;
        Ok(())
    }

    fn create_inner_map(&self, map_id: u32) -> Result<MapHandle> {
        let key_size = 4;
        let value_size = 4;
        let max_entries = 1 << map_id;
        let mut opts = bpf_map_create_opts::default();
        opts.sz = std::mem::size_of::<bpf_map_create_opts>() as u64;
        let mh = MapHandle::create(
            MapType::Array,
            Some("inner_map"),
            key_size,
            value_size,
            max_entries,
            &opts,
        )?;
        Ok(mh)
    }
}

fn update_outer_map(outer: &MapHandle, file_id: FileId64, inner: &MapHandle) -> Result<()> {
    let fd = inner.as_fd().as_raw_fd();
    debug_assert!(fd > 0);
    outer.update(
        &file_id.to_ne_bytes(),
        &fd.to_ne_bytes(),
        MapFlags::NO_EXIST,
    )?;
    Ok(())
}

fn delete_outer_map(outer: &MapHandle, file_id: FileId64) -> Result<()> {
    outer.delete(&file_id.to_ne_bytes())?;
    Ok(())
}

fn update_inner_map(inner: &MapHandle, deltas: Vec<StackDelta>) -> Result<()> {
    for (idx, delta) in deltas.iter().enumerate() {
        let idx = idx as u32;
        inner.update(&idx.to_ne_bytes(), delta.slice(), MapFlags::ANY)?;
    }
    Ok(())
}

fn update_batch_inner_map(inner: &MapHandle, deltas: Vec<StackDelta>) -> Result<()> {
    let mut batch_key = Vec::with_capacity(deltas.len() * 4);
    let mut batch_val: Vec<u8> = Vec::with_capacity(deltas.len() * deltas[0].raw_size());

    for (idx, delta) in deltas.iter().enumerate() {
        let idx = idx as u32;
        batch_key.extend(idx.to_ne_bytes());
        batch_val.extend(delta.slice());
    }
    inner.update_batch(
        &batch_key,
        &batch_val,
        deltas.len() as u32,
        MapFlags::ANY,
        MapFlags::ANY,
    )?;
    Ok(())
}

pub fn create_inner_map(map_id: u32) -> Result<MapHandle> {
    let key_size = 4;
    let value_size = 4;
    let max_entries = 1 << map_id;
    let mut opts = bpf_map_create_opts::default();
    opts.sz = std::mem::size_of::<bpf_map_create_opts>() as u64;
    let mh = MapHandle::create(
        MapType::Array,
        Some("inner"),
        key_size,
        value_size,
        max_entries,
        &opts,
    )?;
    Ok(mh)
}

fn get_map_id(num_deltas: u32) -> Result<u32> {
    let significant_bits = 32 - num_deltas.leading_zeros();
    if significant_bits <= bpf::STACK_DELTA_BUCKET_SMALLEST {
        Ok(bpf::STACK_DELTA_BUCKET_SMALLEST)
    } else if significant_bits > bpf::STACK_DELTA_BUCKET_LARGEST {
        bail!("no map available for {} stack deltas", num_deltas)
    } else {
        Ok(significant_bits)
    }
}
