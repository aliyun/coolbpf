use crate::btf::BtfReader;
use std::fmt;

// https://docs.kernel.org/bpf/btf.html#btf-kind-ptr
#[derive(Debug, Clone)]
pub struct Ptr {
    pub type_id: u32,
}

impl Ptr {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(8);
        Ptr {
            type_id: reader.read_u32(),
        }
    }
}

impl fmt::Display for Ptr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pointer: {}", self.type_id)
    }
}
