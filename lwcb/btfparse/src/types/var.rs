use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-var
#[derive(Debug, Clone)]
pub struct Var {
    pub name: String,
    pub type_id: u32,
    // pub linkage
}

impl Var {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);
        let type_id = reader.read_u32();
        reader.skip(4); // skip btf_var
        Var { name, type_id }
    }
}
