use super::{info_kind_flag, info_vlen};
use crate::btf::BtfReader;
use std::fmt;

#[derive(Debug, Clone)]
pub enum EnumItem {
    Signed(i32),
    Unsigned(u32),
}

// https://docs.kernel.org/bpf/btf.html#btf-kind-enum
#[derive(Debug, Clone)]
pub struct Enum {
    pub name: String,
    // 1/2/4/8
    pub size: u32,
    pub enums: Vec<(String, EnumItem)>,
}

impl Enum {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        let info = reader.read_u32();
        let size = reader.read_u32();

        let signed = info_kind_flag!(info) == 1;
        let vlen = info_vlen!(info);
        let mut enums = Vec::new();

        for i in 0..vlen {
            let item_name = reader.read_name();
            let item;
            if signed {
                item = EnumItem::Signed(reader.read_u32() as i32);
            } else {
                item = EnumItem::Unsigned(reader.read_u32());
            }
            enums.push((item_name, item));
        }

        Enum { name, size, enums }
    }
}
