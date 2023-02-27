use crate::btf::BtfReader;

pub(crate) mod array;
pub(crate) mod const_;
pub(crate) mod datasec;
pub(crate) mod decltag;
pub(crate) mod enum64;
pub(crate) mod enum_;
pub(crate) mod float;
pub(crate) mod func;
pub(crate) mod func_proto;
pub(crate) mod fwd;
pub(crate) mod int;
pub(crate) mod ptr;
pub(crate) mod restrict;
pub(crate) mod struct_;
pub(crate) mod typedef;
pub(crate) mod typetag;
pub(crate) mod union;
pub(crate) mod var;
pub(crate) mod volatile;

#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name: String,
    pub type_id: u32,
    pub offset: u32,
}

impl BtfMember {
    fn from_reader(reader: &mut BtfReader) -> Self {
        BtfMember {
            name: reader.read_name(),
            type_id: reader.read_u32(),
            offset: reader.read_u32(),
        }
    }

    // offset in bits
    pub fn offset(&self) -> u32 {
        self.offset
    }

    // offset in bits
    // bitfield offset and bitfield size
    pub fn offset_bitfield(&self) -> (u32, u32) {
        ((self.offset & 0xffffff), self.offset >> 24)
    }
}

macro_rules! info_kind_flag {
    ($info: ident) => {
        ($info >> 31)
    };
}

macro_rules! info_vlen {
    ($info: ident) => {
        ($info & 0xffff)
    };
}

pub(crate) use {info_kind_flag, info_vlen};
