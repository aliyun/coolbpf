use bpfir::Type;
use libbpf_rs::btf::types::*;
use libbpf_rs::btf::BtfKind;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::Btf;
use std::cmp::Ordering;
use std::ops::Deref;
use std::path::Path;

use crate::parser;

pub struct BTF<'a> {
    btf: Btf<'a>,
}

impl<'a> BTF<'a> {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        BTF {
            btf: Btf::from_path(path).unwrap(),
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<u32> {
        if let Some(bt) = self.type_by_name::<BtfType>(name) {
            return Some(bt.type_id().into());
        }
        None
    }

    pub fn find_member(&self, id: u32, name: &str) -> Option<(u32, parser::MemberAttr)> {
        if let Some(st) = self.type_by_id::<Struct>(id.into()) {
            for mem in st.iter() {
                if let Some(x) = mem.name {
                    if let Some(y) = x.to_str().ok() {
                        if y.cmp(name) == Ordering::Equal {
                            let ma = match mem.attr {
                                MemberAttr::Normal { offset } => parser::MemberAttr {
                                    offset: offset / 8,
                                    bitfield_offset: 0,
                                    bitfield_size: 0,
                                },
                                MemberAttr::BitField { size, offset } => parser::MemberAttr {
                                    offset: offset / 8,
                                    bitfield_offset: (offset % 8) as u16,
                                    bitfield_size: size as u16,
                                },
                            };
                            return Some((mem.ty.into(), ma));
                        }
                    }
                }
            }
        }
        return None;
    }

    pub fn func_args(&self, name: &str) -> Vec<(String, u32)> {
        let mut res = vec![];
        if let Some(func) = self.type_by_name::<Func>(name) {
            if let Some(func_proto) = func.next_type().map(|x| FuncProto::try_from(x).unwrap()) {
                for fp in func_proto.iter() {
                    res.push((fp.name.unwrap().to_str().unwrap().to_owned(), fp.ty.into()));
                }
            }
        }
        res
    }

    pub fn func_ret(&self, name: &str) -> Option<u32> {
        if let Some(func) = self.type_by_name::<Func>(name) {
            if let Some(bt) = func.next_type() {
                return Some(bt.next_type().unwrap().type_id().into());
            }
        }
        None
    }

    pub fn type_string(&self, id: u32) -> String {
        let mut ty = self.type_by_id::<BtfType>(id.into()).unwrap();
        ty = ty.skip_mods_and_typedefs();
        match ty.kind() {
            BtfKind::Int => {
                let mut res = String::default();
                let i = Int::try_from(ty).unwrap();
                match i.encoding {
                    IntEncoding::Bool => {
                        res.push_str("bool");
                    }
                    IntEncoding::Char => {
                        res.push_str("char");
                    }
                    IntEncoding::Signed => {
                        res.push('i');
                        res.push_str(&i.bits.to_string());
                    }
                    _ => {
                        res.push('u');
                        res.push_str(&i.bits.to_string());
                    }
                }

                return res;
            }

            BtfKind::Ptr => {
                let mut res = self.type_string(ty.next_type().unwrap().type_id().into());
                res.push('*');
                return res;
            }

            BtfKind::Struct => {
                let mut res = "struct ".to_owned();
                res.push_str(ty.name().unwrap().to_str().unwrap());
                return res;
            }

            _ => {
                println!("kind: {:?}", ty.kind());
                todo!()
            }
        }
    }

    pub fn to_type(&self, id: u32) -> Type {
        let mut bt = self.btf.type_by_id::<BtfType>(TypeId::from(id)).unwrap();
        bt = bt.skip_mods_and_typedefs();
        match bt.kind() {
            BtfKind::Struct => Type::struct_(to_string(&bt)),
            BtfKind::Int => {
                let i = Int::try_from(bt).unwrap();
                let bits = i.bits;
                match i.encoding {
                    IntEncoding::Bool => Type::bool(),
                    IntEncoding::Char => Type::char(),
                    IntEncoding::Signed => match bits {
                        8 => Type::i8(),
                        16 => Type::i16(),
                        32 => Type::i32(),
                        64 => Type::i64(),
                        _ => unimplemented!(),
                    },
                    IntEncoding::None => match bits {
                        8 => Type::u8(),
                        16 => Type::u16(),
                        32 => Type::u32(),
                        64 => Type::u64(),
                        _ => unimplemented!(),
                    },
                }
            }
            _ => todo!("{:?}", bt.kind()),
        }
    }
}

#[inline]
fn to_string(bt: &BtfType) -> String {
    bt.name().unwrap().to_str().unwrap().to_owned()
}

impl<'a> Deref for BTF<'a> {
    type Target = Btf<'a>;
    fn deref(&self) -> &Self::Target {
        &self.btf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btf_get_func_args() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        assert_ne!(btf.func_args("tcp_sendmsg").len(), 0);
    }

    #[test]
    fn test_btf_get_func_ret() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        assert_eq!(btf.type_string(btf.func_ret("tcp_sendmsg").unwrap()), "i32");
    }

    #[test]
    fn test_btf_type_string() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        let args = btf.func_args("tcp_data_queue");
        assert_ne!(args.len(), 0);

        assert_eq!(btf.type_string(args[0].1), "struct sock*");
    }

    #[test]
    fn find_by_name() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        let args = btf.find_by_name("sock");
        assert!(args.is_some());
    }

    #[test]
    fn find_member() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        let id = btf.find_by_name("sock");
        assert!(btf.find_member(id.unwrap(), "__sk_common").is_some());
    }

    #[test]
    fn find_member_bitfield() {
        let btf = BTF::from_path("../tests/bin/vmlinux");
        let id = btf.find_by_name("tcphdr").unwrap();
        let (_, ma) = btf.find_member(id, "res1").unwrap();

        assert_eq!(ma.offset, 12);
        assert_eq!(ma.bitfield_offset, 0);
        assert_eq!(ma.bitfield_size, 4);
    }
}
