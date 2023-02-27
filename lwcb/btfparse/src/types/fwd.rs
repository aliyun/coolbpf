use super::info_kind_flag;
use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-fwd
#[derive(Debug, Clone)]
pub struct Fwd {
    pub name: String,
    // struct or union
    pub is_struct: bool,
}

impl Fwd {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        let info = reader.read_u32();
        let is_struct = info_kind_flag!(info) == 0;
        reader.skip(4);

        Fwd { name, is_struct }
    }
}
