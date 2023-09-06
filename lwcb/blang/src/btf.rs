use libbpf_rs::btf::{types::*, BtfKind, BtfType};
use libbpf_rs::Btf;
use std::cmp::Ordering;
use std::{ops::Deref, path::Path};

pub struct BTF<'a> {
    btf: Btf<'a>,
}

impl<'a> BTF<'a> {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        BTF {
            btf: Btf::from_path(path).unwrap(),
        }
    }

    pub fn find_member(&self, id: u32, name: &String) -> Option<u32> {
        self.type_by_id::<Struct>(id.into()).map(|x| {
            for mem in x.iter() {
                mem.name.map(|x| {
                    x.to_str().ok().map(|x| {
                        if x.cmp(&name) == Ordering::Equal {
                            return Some::<u32>(mem.ty.into());
                        } else {
                            return None;
                        }
                    })
                });
            }
        });
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
        let btf = BTF::from_path("/root/easybpf/vmlinux-4.19.91-010.ali4000.alios7.x86_64");
        assert_ne!(btf.func_args("tcp_sendmsg").len(), 0);
    }

    #[test]
    fn test_btf_get_func_ret() {
        let btf = BTF::from_path("/root/easybpf/vmlinux-4.19.91-010.ali4000.alios7.x86_64");
        assert_eq!(btf.type_string(btf.func_ret("tcp_sendmsg").unwrap()), "i32");
    }

    #[test]
    fn test_btf_type_string() {
        let btf = BTF::from_path("/root/easybpf/vmlinux-4.19.91-010.ali4000.alios7.x86_64");
        let args = btf.func_args("tcp_sendmsg");
        assert_ne!(args.len(), 0);

        assert_eq!(btf.type_string(args[0].1), "struct sock*");
    }
}
