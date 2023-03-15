use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-restrict
#[derive(Debug, Clone)]
pub struct Restrict {
    pub type_id: u32,
}

impl Restrict {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(8);
        Restrict {
            type_id: reader.read_u32(),
        }
    }
}
