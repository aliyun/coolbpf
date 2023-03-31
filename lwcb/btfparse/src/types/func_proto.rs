use super::info_vlen;
use crate::btf::BtfReader;

#[derive(Debug, Clone)]
pub struct FuncParam {
    pub name: String,
    pub type_id: u32,
}

impl FuncParam {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        FuncParam {
            name: reader.read_name(),
            type_id: reader.read_u32(),
        }
    }
}

// https://docs.kernel.org/bpf/btf.html#btf-kind-func-proto
#[derive(Debug, Clone)]
pub struct FuncProto {
    pub params: Vec<FuncParam>,
    pub return_type_id: u32,
}

impl FuncProto {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(4);
        let info = reader.read_u32();
        let mut params = Vec::new();
        let return_type_id = reader.read_u32();

        for _ in 0..info_vlen!(info) {
            params.push(FuncParam::from_reader(reader));
        }

        FuncProto {
            params,
            return_type_id,
        }
    }
}
