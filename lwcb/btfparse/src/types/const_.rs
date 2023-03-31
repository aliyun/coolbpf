use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-const
#[derive(Debug, Clone)]
pub struct Const {
    pub type_id: u32,
}

impl Const {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(8);
        Const {
            type_id: reader.read_u32(),
        }
    }
}
