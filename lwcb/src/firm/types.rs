use cached::proc_macro::cached;
use libbpf_sys::btf_type;
use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::{
    btf::btf_find_struct,
    types::{Type, TypeKind},
    utils::align::roundup,
};
use libfirm_rs::{Mode, Type as IrType, TypeKind as IrTypeKind};

// generate structure by types array
pub fn gen_struct_type(types: &Vec<Type>) -> Type {
    let mut st = vec![];
    let mut offset = 0;
    for typ in types {
        let mut new_type = typ.clone();
        offset = roundup(offset as usize, typ.size() as usize) as i32;
        new_type.set_offset(offset as u16);
        offset += typ.size() as i32;

        st.push(new_type);
    }

    let mut struct_type = Type::new(TypeKind::Struct(st));
    struct_type.set_size(offset as u16);
    struct_type
}

/// get Type of `struct pt_regs`
#[cached(size = 1)]
pub fn pt_regs_type() -> Type {
    Type::new(TypeKind::TypeId(btf_find_struct("pt_regs")))
}
