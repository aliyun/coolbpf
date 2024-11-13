use std::ops::Range;

use super::types::bpf;
use super::types::impl_default;
use crate::symbollizer::file_id::FileId64;
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;

struct OffsetRange {
    raw: bpf::OffsetRange,
}

impl_default!(OffsetRange);

impl OffsetRange {
    pub fn new(prog: u16, start: u64, end: u64) -> Self {
        let mut or = OffsetRange::default();
        or.raw.program_index = prog;
        or.raw.upper_offset = end;
        or.raw.lower_offset = start;
        or
    }
}

pub struct InterpreterOffsetMap {
    map: MapHandle,
}

impl InterpreterOffsetMap {
    pub fn new(map: MapHandle) -> Self {
        InterpreterOffsetMap { map }
    }

    pub fn update(&self, prog: u16, id: FileId64, offset: &Range<u64>) -> Result<()> {
        let key = id.0;
        let or = OffsetRange::new(prog, offset.start, offset.end);

        self.map
            .update(&key.to_ne_bytes(), or.slice(), MapFlags::ANY)?;
        Ok(())
    }
}
