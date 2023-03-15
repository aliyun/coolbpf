use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-type-tag
#[derive(Debug, Clone)]
pub struct TypeTag {
    pub name: String,
    pub type_id: u32,
}

impl TypeTag {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);
        TypeTag {
            name,
            type_id: reader.read_u32(),
        }
    }
}
