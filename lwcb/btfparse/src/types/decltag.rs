use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-decl-tag
#[derive(Debug, Clone)]
pub struct DeclTag {
    pub name: String,
    pub type_id: u32,
    pub component_idx: u32,
}

impl DeclTag {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);
        DeclTag {
            name,
            type_id: reader.read_u32(),
            component_idx: reader.read_u32(),
        }
    }
}
