use crate::btf::BtfReader;

use super::{info_kind_flag, info_vlen};

// https://docs.kernel.org/bpf/btf.html#btf-kind-enum64
#[derive(Debug, Clone)]
pub enum Enum64Item {
    Signed(i64),
    Unsigned(u64),
}

#[derive(Debug, Clone)]
pub struct Enum64 {
    size: u32,
    enums: Vec<(String, Enum64Item)>,
}

impl Enum64 {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        reader.skip(4);
        let info = reader.read_u32();
        let size = reader.read_u32();
        let mut enums = Vec::new();
        let signed = info_kind_flag!(info) == 1;

        for _ in 0..info_vlen!(info) {
            let name = reader.read_name();
            let low = reader.read_u32();
            let hig = reader.read_u32();
            let item;
            if signed {
                // unsigned
                item = Enum64Item::Signed((hig as i64) << 32 + low);
            } else {
                item = Enum64Item::Unsigned((hig as u64) << 32 + low)
            }

            enums.push((name, item));
        }

        Enum64 { size, enums }
    }
}
