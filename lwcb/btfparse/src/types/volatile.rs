use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-volatile
#[derive(Debug, Clone)]
pub struct Volatile {
    pub type_id: u32,
}

impl Volatile {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(8);
        Volatile {
            type_id: reader.read_u32(),
        }
    }
}
