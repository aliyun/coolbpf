use super::info_kind_flag;
use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-float
#[derive(Debug, Clone)]
pub struct Float {
    pub name: String,
    pub size: u32,
}

impl Float {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);

        Float {
            name,
            size: reader.read_u32(),
        }
    }
}
