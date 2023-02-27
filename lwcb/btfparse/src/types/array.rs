use crate::btf::BtfReader;
use std::fmt;

// https://docs.kernel.org/bpf/btf.html#btf-kind-array
#[derive(Debug, Clone, Copy)]
pub struct Array {
    pub elem_type_id: u32,
    pub indx_type_id: u32,
    pub nelems: u32,
}

impl Array {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(12);

        Array {
            elem_type_id: reader.read_u32(),
            indx_type_id: reader.read_u32(),
            nelems: reader.read_u32(),
        }
    }
}

impl fmt::Display for Array {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Array")
    }
}
