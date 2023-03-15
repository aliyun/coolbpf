use anyhow::{bail, Result};
use byteorder::ByteOrder;
use byteorder::{BigEndian, LittleEndian};
use std::cmp::Ordering;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;

use super::{
    Array, Const, DataSec, DeclTag, Enum, Enum64, Float, Func, FuncProto, Fwd, Int, Ptr, Restrict,
    Struct, TypeTag, Typedef, Union, Var, Volatile,
};

#[derive(Debug, Clone, Copy)]
pub enum BtfKind {
    Void,
    Int,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Func,
    FuncProto,
    Var,
    DataSec,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
}

impl From<&BtfType> for BtfKind {
    fn from(ty: &BtfType) -> Self {
        match ty {
            BtfType::Void => BtfKind::Void,
            BtfType::Int(_) => BtfKind::Int,
            BtfType::Ptr(_) => BtfKind::Ptr,
            BtfType::Array(_) => BtfKind::Array,
            BtfType::Struct(_) => BtfKind::Struct,
            BtfType::Union(_) => BtfKind::Union,
            BtfType::Enum(_) => BtfKind::Enum,
            BtfType::Fwd(_) => BtfKind::Fwd,
            BtfType::Typedef(_) => BtfKind::Typedef,
            BtfType::Volatile(_) => BtfKind::Volatile,
            BtfType::Const(_) => BtfKind::Const,
            BtfType::Restrict(_) => BtfKind::Restrict,
            BtfType::Func(_) => BtfKind::Func,
            BtfType::FuncProto(_) => BtfKind::FuncProto,
            BtfType::Var(_) => BtfKind::Var,
            BtfType::DataSec(_) => BtfKind::DataSec,
            BtfType::Float(_) => BtfKind::Float,
            BtfType::DeclTag(_) => BtfKind::DeclTag,
            BtfType::TypeTag(_) => BtfKind::TypeTag,
            BtfType::Enum64(_) => BtfKind::Enum64,
        }
    }
}

// https://docs.kernel.org/bpf/btf.html#type-encoding
#[derive(Debug, Clone)]
pub enum BtfType {
    Void,
    Int(Int),
    Ptr(Ptr),
    Array(Array),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Fwd(Fwd),
    Typedef(Typedef),
    Volatile(Volatile),
    Const(Const),
    Restrict(Restrict),
    Func(Func),
    FuncProto(FuncProto),
    Var(Var),
    DataSec(DataSec),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(TypeTag),
    Enum64(Enum64),
}

impl BtfType {
    pub fn is_pointer(&self) -> bool {
        match self {
            BtfType::Ptr(_) => true,
            _ => false,
        }
    }
}

// https://docs.kernel.org/bpf/btf.html#btf-type-and-string-encoding
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct BtfHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

impl BtfHeader {
    pub fn from_reader(reader: &mut BtfReader) -> BtfHeader {
        BtfHeader {
            magic: reader.read_u16(),
            version: reader.read_u8(),
            flags: reader.read_u8(),
            hdr_len: reader.read_u32(),
            type_off: reader.read_u32(),
            type_len: reader.read_u32(),
            str_off: reader.read_u32(),
            str_len: reader.read_u32(),
        }
    }
}

pub struct Btf {
    pub types: Vec<BtfType>,
}

impl Btf {
    pub fn from_file<P>(path: P) -> Result<Btf>
    where
        P: AsRef<Path>,
    {
        let mut reader = BtfReader::from_file(path)?;
        let mut types = Vec::new();
        types.push(BtfType::Void);
        loop {
            if reader.is_empty() {
                break;
            }
            let kind = (reader.peek_u32(4) >> 24) & 0xf;
            let ty = match kind {
                1 => BtfType::Int(Int::from_reader(&mut reader)),
                2 => BtfType::Ptr(Ptr::from_reader(&mut reader)),
                3 => BtfType::Array(Array::from_reader(&mut reader)),
                4 => BtfType::Struct(Struct::from_reader(&mut reader)),
                5 => BtfType::Union(Union::from_reader(&mut reader)),
                6 => BtfType::Enum(Enum::from_reader(&mut reader)),
                7 => BtfType::Fwd(Fwd::from_reader(&mut reader)),
                8 => BtfType::Typedef(Typedef::from_reader(&mut reader)),
                9 => BtfType::Volatile(Volatile::from_reader(&mut reader)),
                10 => BtfType::Const(Const::from_reader(&mut reader)),
                11 => BtfType::Restrict(Restrict::from_reader(&mut reader)),
                12 => BtfType::Func(Func::from_reader(&mut reader)),
                13 => BtfType::FuncProto(FuncProto::from_reader(&mut reader)),
                14 => BtfType::Var(Var::from_reader(&mut reader)),
                15 => BtfType::DataSec(DataSec::from_reader(&mut reader)),
                16 => BtfType::Float(Float::from_reader(&mut reader)),
                17 => BtfType::DeclTag(DeclTag::from_reader(&mut reader)),
                18 => BtfType::TypeTag(TypeTag::from_reader(&mut reader)),
                19 => BtfType::Enum64(Enum64::from_reader(&mut reader)),
                _ => bail!(
                    "Wrong btf type: {}, types len: {}, {:#x?}",
                    kind,
                    types.len(),
                    reader
                ),
            };
            // log::debug!("{:?}", ty);
            types.push(ty);
        }

        log::debug!("Btf: {} btf types", types.len());
        Ok(Btf { types })
    }

    pub fn types(&self) -> &Vec<BtfType> {
        &self.types
    }

    pub fn find_func(&self, name: &str) -> Option<u32> {
        for (id, ty) in self.types().iter().enumerate() {
            if let BtfType::Func(f) = ty {
                if f.name.as_str().cmp(name) == Ordering::Equal {
                    return Some(id as u32);
                }
            }
        }
        None
    }
}

pub struct BtfReader {
    little_endian: bool,
    data: Vec<u8>,
    cursor: usize,
    hdr: BtfHeader,
}

impl fmt::Debug for BtfReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtfReader")
            .field("little_endian", &self.little_endian)
            .field("cursor", &self.cursor)
            .field("hdr", &self.hdr)
            .finish()
    }
}

impl BtfReader {
    pub fn from_file<P>(path: P) -> Result<BtfReader>
    where
        P: AsRef<Path>,
    {
        let mut data = Vec::new();
        let mut file = File::open(path)?;
        file.read_to_end(&mut data)?;

        let magic = LittleEndian::read_u16(&data);
        let mut little_endian = true;
        match magic {
            0xEB9F => {}
            0x9FEB => little_endian = false,
            _ => bail!("Wrong magic number in btf header: {}", magic),
        }

        let mut reader = BtfReader {
            little_endian,
            data,
            cursor: 0,
            hdr: BtfHeader::default(),
        };

        let hdr = BtfHeader::from_reader(&mut reader);
        log::debug!("Little endian: {}, BtfHeader: {:#X?}", little_endian, hdr);
        reader.cursor = hdr.type_off as usize + hdr.hdr_len as usize;
        reader.hdr = hdr;

        Ok(reader)
    }

    pub fn peek_u8(&mut self, offset: usize) -> u8 {
        self.data[self.cursor + offset]
    }

    pub fn peek_u16(&mut self, offset: usize) -> u16 {
        if self.little_endian {
            LittleEndian::read_u16(&self.data[self.cursor + offset..])
        } else {
            BigEndian::read_u16(&self.data[self.cursor + offset..])
        }
    }

    pub fn peek_u32(&mut self, offset: usize) -> u32 {
        if self.little_endian {
            LittleEndian::read_u32(&self.data[self.cursor + offset..])
        } else {
            BigEndian::read_u32(&self.data[self.cursor + offset..])
        }
    }

    pub fn read_u8(&mut self) -> u8 {
        let ret = self.peek_u8(0);
        self.cursor += 1;
        ret
    }

    pub fn read_u16(&mut self) -> u16 {
        let ret = self.peek_u16(0);
        self.cursor += 2;
        ret
    }

    pub fn read_u32(&mut self) -> u32 {
        let ret = self.peek_u32(0);
        self.cursor += 4;
        ret
    }

    pub fn skip(&mut self, offset: usize) {
        self.cursor += offset;
    }

    pub fn name(&self, name_off: u32) -> String {
        let off = (self.hdr.hdr_len + self.hdr.str_off + name_off) as usize;
        let off_end = off + self.data[off..].iter().position(|&c| c == b'\0').unwrap();
        unsafe { std::str::from_utf8_unchecked(&self.data[off..off_end]).to_string() }
    }

    pub fn read_name(&mut self) -> String {
        let name_off = self.read_u32();
        self.name(name_off)
    }

    pub fn is_empty(&self) -> bool {
        if self.cursor >= (self.hdr.hdr_len + self.hdr.type_off + self.hdr.type_len) as usize {
            true
        } else {
            false
        }
    }
}

#[test]
fn test_btf_find_func() {
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
    let id = btf.find_func("tcp_sendmsg").unwrap();
    assert!(id > 0);
}

#[test]
fn test_btf_get_func_proto() {
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
    let id = btf.find_func("tcp_sendmsg").unwrap();

    if let BtfType::Func(f) = &btf.types()[id as usize] {
        let fpid = f.type_id - 1;
        if let BtfType::FuncProto(fp) = &btf.types()[fpid as usize] {
            return;
        }
    }
    panic!()
}
