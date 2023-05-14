use std::collections::HashMap;

use crate::{
    btf::{Btf, BtfType},
    FuncProto,
};

pub struct FuncMap {
    funcs: HashMap<String, usize>,
}

impl FuncMap {
    pub fn from_btf(btf: & Btf) -> Self {
        let mut funcs = HashMap::default();
        for (i, t) in btf.types().iter().enumerate() {
            match t {
                BtfType::Func(f) => {
                    assert!(
                        !funcs.contains_key(&f.name),
                        "function name duplicated: {}",
                        f.name
                    );
                    funcs.insert(f.name.clone(), i);
                }
                _ => {}
            }
        }

        FuncMap { funcs }
    }

    pub fn find_func(&self, name: &str) -> Option<u32> {
        if let Some(&id) = self.funcs.get(name) {
            return Some(id as u32)
        }
        None
    }
}

#[test]
fn test_func_map() {
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
    let fm = FuncMap::from_btf(&btf);
}
