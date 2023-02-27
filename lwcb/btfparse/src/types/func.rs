use crate::btf::BtfReader;

// https://docs.kernel.org/bpf/btf.html#btf-kind-func
#[derive(Debug, Clone)]
pub struct Func {
    pub name: String,
    // pub linkage:
    pub type_id: u32,
}

impl Func {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        reader.skip(4);
        let type_id = reader.read_u32();
        Func { name, type_id }
    }
}
