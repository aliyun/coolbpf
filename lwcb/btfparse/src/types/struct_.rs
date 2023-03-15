use super::{info_kind_flag, info_vlen, BtfMember};
use crate::btf::BtfReader;
use std::{cmp::Ordering, fmt};

// https://docs.kernel.org/bpf/btf.html#btf-kind-struct
#[derive(Debug, Clone)]
pub struct Struct {
    pub name: String,
    pub members: Vec<BtfMember>,
    pub size: u32,
    pub has_bitfield: bool,
}

impl Struct {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        let info = reader.read_u32();
        let size = reader.read_u32();

        let mut members = Vec::new();

        // the bit 31 of struct_type->info, previously reserved, now is used to indicate whether bitfield_size is
        // encoded in btf_member or not.
        let has_bitfield = info_kind_flag!(info) == 1;

        for _ in 0..info_vlen!(info) {
            members.push(BtfMember::from_reader(reader));
        }

        Struct {
            name,
            members,
            size,
            has_bitfield,
        }
    }

    pub fn find_member(&self, name: &str) -> Option<BtfMember> {
        for mem in &self.members {
            if let Ordering::Equal = mem.name.as_str().cmp(name) {
                return Some(mem.clone());
            }
        }
        None
    }

    pub fn has_bitfield(&self) -> bool {
        self.has_bitfield
    }
}

impl fmt::Display for Struct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Struct")
    }
}
