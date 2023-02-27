use std::collections::HashMap;

use crate::{
    btf::{Btf, BtfType},
    FuncProto,
};

pub struct FuncMap<'a> {
    btf: &'a Btf,
    funcs: HashMap<String, usize>,
}

impl<'a> FuncMap<'a> {
    pub fn from_btf(btf: &'a Btf) -> Self {
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

        FuncMap { btf, funcs }
    }
}

#[test]
fn test_func_map() {
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
    let fm = FuncMap::from_btf(&btf);
}
