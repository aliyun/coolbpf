use std::{cmp::Ordering, fmt};

use crate::btf::BtfReader;

use super::BtfMember;

// https://docs.kernel.org/bpf/btf.html#btf-kind-struct
#[derive(Debug, Clone)]
pub struct Union {
    pub name: String,
    pub members: Vec<BtfMember>,
    pub size: u32,
}

impl Union {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        // reader.read_name();
        let name = reader.read_name();
        let vlen = reader.read_u32() & 0xff;
        let size = reader.read_u32();

        let mut members = Vec::new();

        for i in 0..vlen {
            members.push(BtfMember::from_reader(reader));
        }

        Union {
            name,
            members,
            size,
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
}

impl fmt::Display for Union {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Union")
    }
}
