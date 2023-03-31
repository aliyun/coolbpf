use std::fmt;

use crate::btf::BtfReader;

#[derive(Debug, Clone)]
pub enum IntEncoding {
    Default,
    Signed,
    Char,
    Bool,
}

impl From<u32> for IntEncoding {
    fn from(val: u32) -> Self {
        match (val >> 24) & 0xf {
            0 => IntEncoding::Default,
            1 => IntEncoding::Signed,
            2 => IntEncoding::Char,
            4 => IntEncoding::Bool,
            _ => panic!("failed to parse IntEncoding, val: 0x{:X}", val),
        }
    }
}

impl fmt::Display for IntEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntEncoding::Default => write!(f, "Default"),
            IntEncoding::Signed => write!(f, "Signed"),
            IntEncoding::Char => write!(f, "Char"),
            IntEncoding::Bool => write!(f, "Bool"),
        }
    }
}

// https://docs.kernel.org/bpf/btf.html#btf-kind-int
#[derive(Debug, Clone)]
pub struct Int {
    pub name: String,
    /// size in bytes
    pub size: u32,
    pub encoding: IntEncoding,
    /// the start offset and bits for bitfield
    pub offset: u8,
    pub bits: u8,
}

impl Int {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        let _info = reader.read_u32();
        let size = reader.read_u32();
        let attr = reader.read_u32();

        Int {
            name,
            size,
            encoding: IntEncoding::from(attr),
            offset: ((attr & 0x00ff0000) >> 16) as u8,
            bits: (attr & 0x000000ff) as u8,
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn is_signed(&self) -> bool {
        if let IntEncoding::Signed = self.encoding {
            return true;
        }
        false
    }

    pub fn is_bitfield(&self) -> bool {
        self.offset != 0
    }

    pub fn is_bool(&self) -> bool {
        if let IntEncoding::Bool = self.encoding {
            return true;
        }
        false
    }

    pub fn is_char(&self) -> bool {
        if let IntEncoding::Char = self.encoding {
            return true;
        }
        false
    }

    pub fn is_u8(&self) -> bool {
        !self.is_bitfield() && self.size == 1 && !self.is_signed()
    }

    pub fn is_i8(&self) -> bool {
        !self.is_bitfield() && self.size == 1 && self.is_signed()
    }

    pub fn is_u16(&self) -> bool {
        !self.is_bitfield() && self.size == 2 && !self.is_signed()
    }

    pub fn is_i16(&self) -> bool {
        !self.is_bitfield() && self.size == 2 && self.is_signed()
    }

    pub fn is_u32(&self) -> bool {
        !self.is_bitfield() && self.size == 4 && !self.is_signed()
    }

    pub fn is_i32(&self) -> bool {
        !self.is_bitfield() && self.size == 4 && self.is_signed()
    }

    pub fn is_u64(&self) -> bool {
        !self.is_bitfield() && self.size == 8 && !self.is_signed()
    }

    pub fn is_i64(&self) -> bool {
        !self.is_bitfield() && self.size == 8 && self.is_signed()
    }
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} size: {}, encoding: {}, bitfield:({}, {})",
            self.name, self.size, self.encoding, self.offset, self.bits
        )
    }
}
