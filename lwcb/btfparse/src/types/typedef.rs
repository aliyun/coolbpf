use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-typedef
#[derive(Debug, Clone)]
pub struct Typedef {
    pub name: String,
    pub type_id: u32,
}

impl Typedef {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);
        let type_id = reader.read_u32();

        Typedef { name, type_id }
    }
}
